import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.config import ROOT
from app.storage import CTIStore
from app.threats import seed_threats
from app.company_graph import attack_contexts, statements
from app.attack import import_bundle, review_mapping
from app.models import Publication
from app.collectors import ingest


class CompanyGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=CTIStore(self.root/'db.sqlite3')
        seed_threats(self.store,ROOT,'company_attack_library.json')

    def tearDown(self):self.tmp.cleanup()

    def mappings(self):
        return [dict(local_id='fin7',stix_id='intrusion-set--test',attack_id='G0046',effective_status='confirmed'),
                dict(local_id='carbanak-malware',stix_id='malware--test',attack_id='S0030',effective_status='confirmed')]

    def contexts(self):
        with patch('app.attack.mapping_rows',return_value=self.mappings()):return attack_contexts(self.store)

    def test_company_campaign_actor_and_malware_paths_have_proof(self):
        rows=self.contexts()
        self.assertEqual(len(rows),6)
        self.assertEqual({r['company_id'] for r in rows},{'chipotle','chilis','arbys'})
        self.assertEqual({r['attack_id'] for r in rows},{'G0046','S0030'})
        self.assertTrue(all(r['assertion_ids'] and r['source_urls'] for r in rows))
        self.assertTrue(all('справочные' in r['interpretation'] for r in rows))

    def test_no_mapping_means_no_attack_context(self):
        self.assertEqual(attack_contexts(self.store),[])

    def test_refuted_attribution_stops_actor_path_but_keeps_direct_malware_evidence(self):
        claim=next(a for a in self.store.assertions() if a['kind']=='attributed_to')
        self.store.review_assertion(claim['id'],'refuted','Analyst','Оспорена атрибуция')
        rows=self.contexts()
        self.assertEqual(len(rows),3)
        self.assertEqual({r['local_entity_id'] for r in rows},{'carbanak-malware'})

    def test_refuted_company_link_removes_only_its_context(self):
        claim=next(a for a in self.store.assertions() if a['kind']=='incident_affects' and a['object']=='chipotle')
        self.store.review_assertion(claim['id'],'refuted','Analyst','Отозвана связь')
        self.assertEqual({r['company_id'] for r in self.contexts()},{'chilis','arbys'})

    def test_changed_publication_invalidates_all_seed_context(self):
        claim=self.store.assertions()[0];data=json.loads(claim['publication']['data']);data['text']+=' Изменение.'
        ingest(self.store,[Publication(**data)])
        self.assertEqual(self.contexts(),[])

    def test_reimport_preserves_analyst_refutation(self):
        claim=next(a for a in self.store.assertions() if a['kind']=='incident_malware')
        self.store.review_assertion(claim['id'],'refuted','Analyst','Отозвано')
        result=seed_threats(self.store,ROOT,'company_attack_library.json')
        self.assertEqual(result['counts'],{'unchanged':1})
        self.assertEqual(result['existing_reviews_preserved'],6)
        self.assertEqual(next(a for a in self.store.assertions() if a['id']==claim['id'])['status'],'refuted')

    def test_campaign_does_not_invent_cve_product_version_or_observed_technique(self):
        self.assertFalse(any(a['kind'] in ('uses_product','affects_product','incident_exploited','incident_product')
                             for a in self.store.assertions()))
        campaign=next(e for e in self.store.entities() if e['entity_type']=='Incident')
        self.assertEqual(campaign['incident_type'],'campaign')
        self.assertEqual(campaign['date_precision'],'year_range')
        self.assertNotIn('start_day',campaign)

    def test_overlap_is_not_used_to_attribute_a_company_incident(self):
        # Only actor_overlap would connect FIN11 to this source; no incident attribution is present.
        seed_threats(self.store,ROOT)
        rows=self.contexts()
        self.assertEqual({r['incident_id'] for r in rows},{'fin7-retail-2018'})

    def test_view_tags_existing_nodes_and_does_not_create_claim_shortcuts(self):
        queries=statements(self.store)
        text=' '.join(q['statement'] for q in queries)
        self.assertIn('REMOVE n:CompanyGraph',text)
        self.assertIn('SET n:CompanyGraph',text)
        self.assertNotIn('MERGE',text)
        self.assertEqual(statements(self.store,True),[])

    def test_view_does_not_expand_a_mapped_actor_into_catalogue_techniques(self):
        raw=json.loads((ROOT/'tests/fixtures/attack_demo.json').read_text())
        import_bundle(self.store,json.dumps(raw).encode())
        self.store.load_entities([{'id':'testgroup','name':'Test Group','entity_type':'ThreatActor'}])
        review_mapping(self.store,'testgroup','G9991','confirmed','Analyst','Fictional match')
        rows=[r for q in statements(self.store) for r in q.get('parameters',{}).get('rows',[])]
        self.assertEqual({r['id'] for r in rows},{'real:fin7','real:carbanak-malware'})
        self.assertFalse(any('real:attack:' in r['id'] for r in rows))

    def test_actor_arsenal_and_overlap_do_not_include_unattributed_groups(self):
        seed_threats(self.store,ROOT)
        from app.company_graph import incident_entities
        selected={e['id'] for e in incident_entities(self.store)}
        self.assertIn('fin7',selected)
        self.assertIn('carbanak-malware',selected)
        self.assertIn('rhysida',selected)
        self.assertNotIn('fin11',selected)
        self.assertNotIn('ta505',selected)
        self.assertNotIn('clop-ransomware',selected)
        self.assertNotIn('dewmode',selected)

    def test_refuted_incident_link_removes_actor_from_default_view(self):
        from app.company_graph import incident_entities
        claim=next(a for a in self.store.assertions() if a['kind']=='attributed_to')
        self.store.review_assertion(claim['id'],'refuted','Analyst','Withdrawn incident attribution')
        self.assertEqual({e['id'] for e in incident_entities(self.store)},{'carbanak-malware'})

    def test_mapping_metadata_is_kept_without_duplicate_profile(self):
        mappings=self.mappings()
        for m in mappings:m['evidence_url']='https://attack.mitre.org/'+m['attack_id']
        with patch('app.attack.mapping_rows',return_value=mappings):
            rows=[r for q in statements(self.store) for r in q.get('parameters',{}).get('rows',[])]
        group=next(r for r in rows if r['id']=='real:fin7')
        self.assertEqual(group['attack_ids'],['G0046'])
        self.assertTrue(group['attack_urls'])
