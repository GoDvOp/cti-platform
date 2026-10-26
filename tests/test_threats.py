import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.config import ROOT
from app.storage import CTIStore
from app.models import Publication
from app.collectors import ingest
from app.threats import seed_threats, shared_products
from app.graph import statements, sync_graph
from app.enrichment import reindex, expand_knowledge
from app.reporting import export_report
from app.knowledge import THREAT_KINDS


class ThreatGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root/'db.sqlite3')
        seed_threats(self.store, ROOT)

    def tearDown(self):
        self.tmp.cleanup()

    def claim(self, kind, subject=None):
        return next(a for a in self.store.assertions() if a['kind'] == kind and
                    (subject is None or a['subject'] == subject))

    def candidate(self, claim):
        return {k: claim[k] for k in ('kind','subject','object','publication_id','excerpt','attributes')}

    def graph_rows(self, marker):
        return [row for q in statements(self.store) if marker in q['statement']
                for row in q.get('parameters', {}).get('rows', [])]

    def test_repeat_import_preserves_refutation_and_catalog_edits(self):
        a = self.claim('attributed_to','equifax-2017')
        self.store.review_assertion(a['id'],'refuted','analyst','Тест ручного решения')
        e = next(e for e in self.store.entities() if e['id'] == 'pla54')
        e['note'] = 'Заметка аналитика'
        self.store.load_entities([e])
        result = seed_threats(self.store,ROOT)
        self.assertEqual(result['counts'],{'unchanged':11})
        self.assertEqual(result['existing_reviews_preserved'],31)
        self.assertEqual(self.claim('attributed_to','equifax-2017')['status'],'refuted')
        self.assertEqual(next(e for e in self.store.entities() if e['id']=='pla54')['note'],'Заметка аналитика')

    def test_attribution_retains_legal_basis_and_source(self):
        rows=self.graph_rows('r:ATTRIBUTED_TO ')
        row=next(r for r in rows if r['subject']=='real:equifax-2017')
        self.assertEqual(row['properties']['basis'],'legal_allegation')
        self.assertEqual(row['properties']['attribution_scope'],'allegation_in_indictment')
        self.assertIn('justice.gov',row['properties']['evidence_url'])
        self.assertIn('источника',row['properties']['interpretation'])

    def test_no_fabricated_cve_or_actor_for_individual_fta_incidents(self):
        claims=self.store.assertions()
        for incident in ('singtel-2021','qualys-2020','british-library-2023','novabev-2025'):
            self.assertFalse(any(a['subject']==incident and a['kind']=='incident_exploited' for a in claims))
        for incident in ('singtel-2021','qualys-2020','novabev-2025'):
            self.assertFalse(any(a['subject']==incident and a['kind']=='attributed_to' for a in claims))
        self.assertEqual(self.claim('incident_exploited','equifax-2017')['object'],'CVE-2017-5638')

    def test_malware_is_separate_from_actor_and_overlaps_do_not_merge(self):
        entities=self.store.entities()
        self.assertEqual(len([e for e in entities if e['entity_type']=='ThreatActor']),7)
        self.assertEqual(len([e for e in entities if e['entity_type']=='Malware']),2)
        rows=self.graph_rows('r:REPORTED_OVERLAP ')
        self.assertEqual(len(rows),2)
        self.assertFalse(any('SAME_AS' in q['statement'] or 'COOPERATES_WITH' in q['statement'] for q in statements(self.store)))

    def test_cooccurrence_only_produces_mentions(self):
        pub=Publication('test','https://example.org/mention','Обзор','Rhysida, Equifax и CVE-2017-5638 упомянуты в обзоре.')
        before=len(self.store.assertions())
        ingest(self.store,[pub])
        self.assertEqual(len(self.store.assertions()),before)
        e=json.loads(next(p for p in self.store.publications() if p['id']==pub.id)['extraction'])
        self.assertIn({'id':'rhysida','entity_type':'ThreatActor'},e['entity_mentions'])
        self.assertFalse(any(a['publication_id']==pub.id for a in self.store.assertions()))

    def test_shared_software_context_has_both_proofs_and_historical_status(self):
        rows=shared_products(self.store)
        row=next(r for r in rows if {r['left'],r['right']}=={'qualys','singtel'})
        self.assertEqual(row['properties']['product_id'],'accellion-fta')
        self.assertEqual(len(row['properties']['assertion_ids']),2)
        self.assertEqual(len(row['properties']['evidence_urls']),2)
        self.assertEqual(row['properties']['age_statuses'],['historical'])
        self.assertIn('одновременность',row['properties']['interpretation'])

    def test_refutation_removes_semantic_edge_but_preserves_assertion(self):
        a=self.claim('attributed_to','equifax-2017')
        self.store.review_assertion(a['id'],'refuted','analyst','Проверка отзыва')
        self.assertFalse(any(r['subject']=='real:equifax-2017' for r in self.graph_rows('r:ATTRIBUTED_TO ')))
        self.assertTrue(any(r['id']=='real:'+a['id'] and r['properties']['status']=='refuted'
                            for r in self.graph_rows('MERGE (a:Assertion')))

    def test_changed_source_invalidates_incident_claims(self):
        a=self.claim('incident_exploited','equifax-2017')
        content=json.loads(a['publication']['data']);content['text']+=' Изменение.'
        ingest(self.store,[Publication(**content)])
        self.assertFalse(any(r['subject']=='real:equifax-2017' for r in self.graph_rows('r:EXPLOITED ')))
        with self.assertRaises(ValueError):
            self.store.review_assertion(a['id'],'confirmed','analyst','Старый текст')

    def test_claim_import_cannot_confirm_and_requires_basis(self):
        row=self.candidate(self.claim('attributed_to'))
        row['status']='confirmed'
        with self.assertRaises(ValueError): self.store.add_assertion(row)
        row.pop('status');row['attributes']={}
        with self.assertRaises(ValueError): self.store.add_assertion(row)

    def test_attacker_claim_cannot_be_imported_as_attribution(self):
        row=self.candidate(self.claim('attributed_to'))
        row['attributes']={'basis':'attacker_claim','confidence':'low'}
        with self.assertRaises(ValueError): self.store.add_assertion(row)
        row['kind']='claimed_by'
        identifier=self.store.add_assertion(row)
        self.assertEqual(next(a for a in self.store.assertions() if a['id']==identifier)['status'],'needs_review')
        self.assertTrue(self.graph_rows('r:REPORTED_CLAIMED_BY '))
        self.assertFalse(self.graph_rows('r:CLAIMED_BY '))

    def test_endpoint_types_and_self_links_are_rejected(self):
        row=self.candidate(self.claim('attributed_to'))
        row['object']='equifax-2017'
        with self.assertRaises(ValueError): self.store.add_assertion(row)
        row=self.candidate(self.claim('actor_overlap'))
        row['object']=row['subject']
        with self.assertRaises(ValueError): self.store.add_assertion(row)

    def test_cve_must_occur_in_actual_excerpt(self):
        row=self.candidate(self.claim('incident_exploited','equifax-2017'))
        row['excerpt']='Инцидент Equifax 2017 затронул Equifax.'
        with self.assertRaises(ValueError): self.store.add_assertion(row)

    def test_real_demo_entity_scope_cannot_mix_or_change(self):
        entity={'id':'demoactor','name':'Rhysida','entity_type':'ThreatActor','is_demo':True}
        self.store.load_entities([entity])
        row=self.candidate(self.claim('attributed_to','british-library-2023'));row['object']='demoactor'
        with self.assertRaises(ValueError): self.store.add_assertion(row)
        entity['is_demo']=False
        with self.assertRaises(ValueError): self.store.load_entities([entity])
        self.assertEqual(len(self.store.entities(True)),1)

    def test_shared_context_removed_after_use_refutation(self):
        a=self.claim('uses_product','singtel')
        self.store.review_assertion(a['id'],'refuted','analyst','Отзыв')
        self.assertEqual(shared_products(self.store),[])

    def test_report_exposes_entities_and_attribution_limits(self):
        export_report(self.store,self.root/'report')
        data=json.loads((self.root/'report/report.json').read_text())
        self.assertEqual(len(data['knowledge_entities']),16)
        self.assertTrue(data['shared_product_context'])
        page=(self.root/'report/report.html').read_text()
        self.assertIn('legal_allegation',page)
        self.assertIn('Кампания не приписывает автоматически',page)

    def test_old_and_new_graph_share_product_sector_and_company_nodes(self):
        expand_knowledge(self.store,ROOT)
        reindex(self.store)
        qs=statements(self.store)
        ids=[r['id'] for q in qs if 'MERGE (c:Company' in q['statement'] for r in q.get('parameters',{}).get('rows',[])]
        self.assertEqual(len(ids),len(set(ids)))
        self.assertIn('novabev',ids)
        self.assertTrue(self.graph_rows('r:AFFECTED_ORGANIZATION '))
        self.assertTrue(self.graph_rows('r:SHARES_PRODUCT_CONTEXT '))
        self.assertTrue(self.graph_rows('r:IN_SECTOR'))

    @patch.dict('os.environ',{'NEO4J_PASSWORD':'test-password'})
    def test_sync_detects_missing_incidents_after_server_import(self):
        response={'database':'neo4j','nodes':[{'labels':['Product'],'count':3}],'relationships':[]}
        with patch('app.graph.execute_requests',return_value={}),patch('app.graph.graph_status',return_value=response):
            with self.assertRaisesRegex(ValueError,'Incident'):
                sync_graph(self.store)
