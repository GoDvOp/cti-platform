"""Small fictional STIX data verifies importer semantics without network access."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.storage import CTIStore
from app.attack import (parse_bundle, import_bundle, catalogue, candidates, review_mapping,
                        mapping_rows, projection, statements, status, search, update, restore_cached)
from app.threats import seed_threats
from app.config import ROOT
from app.graph import statements as graph_statements
from app.reporting import export_report

STAMP='2026-01-01T00:00:00Z'

def sid(kind,number):return kind+'--00000000-0000-4000-8000-'+str(number).zfill(12)


def fixture(version='1.0'):
    def node(kind,n,name,external,**extra):
        return dict(type=kind,id=sid(kind,n),name=name,created=STAMP,modified=STAMP,
                    x_mitre_domains=['enterprise-attack'],external_references=[{
                    'source_name':'mitre-attack','external_id':external,'url':'https://attack.mitre.org/'}],**extra)
    objects=[node('intrusion-set',1,'Test Group','G9991',aliases=['Shared Alias']),
             node('intrusion-set',2,'Other Group','G9992',aliases=['Shared Alias']),
             node('malware',3,'Test Malware','S9991'),node('tool',4,'Test Tool','S9992'),
             node('attack-pattern',5,'Test Technique','T9991',kill_chain_phases=[{'kill_chain_name':'mitre-attack','phase_name':'execution'}]),
             node('attack-pattern',6,'Test Subtechnique','T9991.001',x_mitre_is_subtechnique=True),
             node('x-mitre-tactic',7,'Execution','TA9991',x_mitre_shortname='execution'),
             node('attack-pattern',8,'Revoked Technique','T9992',revoked=True),
             node('attack-pattern',9,'Deprecated Technique','T9993',x_mitre_deprecated=True),
             node('campaign',10,'Fictional campaign','C9991')]
    def link(n,src,tgt,kind='uses'):
        return dict(type='relationship',id=sid('relationship',n),source_ref=src,target_ref=tgt,
                    relationship_type=kind,description='Fictional evidence',created=STAMP,modified=STAMP,
                    external_references=[{'source_name':'test source','url':'https://example.org/research'}])
    group=sid('intrusion-set',1); malware=sid('malware',3); tool=sid('tool',4); tech=sid('attack-pattern',5)
    objects += [link(20,group,malware),link(21,group,tool),link(22,group,sid('attack-pattern',6)),
                link(23,malware,tech),link(24,tool,tech),link(25,sid('attack-pattern',6),tech,'subtechnique-of'),
                link(26,group,sid('attack-pattern',8)),link(27,group,sid('attack-pattern',9)),
                link(28,sid('campaign',10),group,'attributed-to')]
    collection=dict(type='x-mitre-collection',id=sid('x-mitre-collection',99),name='Enterprise ATT&CK',
                    x_mitre_version=version,created=STAMP,modified=STAMP,
                    x_mitre_contents=[{'object_ref':o['id'],'object_modified':o['modified']} for o in objects])
    return dict(type='bundle',id=sid('bundle',100),objects=[collection,*objects])


def payload(data):return json.dumps(data).encode()


class AttackTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=CTIStore(self.root/'db.sqlite3')
        self.store.load_entities([{'id':'testgroup','entity_type':'ThreatActor','name':'Test Group','aliases':['Shared Alias']},
                                 {'id':'testmalware','entity_type':'Malware','name':'Test Malware'}])
        self.data=fixture();import_bundle(self.store,payload(self.data))

    def tearDown(self):self.tmp.cleanup()

    def confirm(self):return review_mapping(self.store,'testgroup','G9991','confirmed','Analyst','Checked identity in source')

    def test_import_version_counts_and_repeat_is_idempotent(self):
        result=import_bundle(self.store,payload(self.data))
        self.assertEqual(result['status'],'unchanged')
        self.assertEqual(result['version'],'1.0')
        self.assertEqual(result['active_counts']['attack-pattern'],2)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM attack_snapshots').fetchone()[0],1)

    def test_invalid_bundle_does_not_replace_active_snapshot(self):
        before=catalogue(self.store)[0]['sha256']
        bad=copy.deepcopy(self.data);bad['objects'].pop()
        with self.assertRaises(ValueError):import_bundle(self.store,payload(bad))
        self.assertEqual(catalogue(self.store)[0]['sha256'],before)

    def test_no_collection_or_duplicate_stix_id_is_rejected(self):
        bad=copy.deepcopy(self.data);bad['objects'].pop(0)
        with self.assertRaises(ValueError):parse_bundle(payload(bad))
        bad=copy.deepcopy(self.data);bad['objects'].append(bad['objects'][1])
        with self.assertRaises(ValueError):parse_bundle(payload(bad))

    def test_import_has_no_automatic_identity_mapping(self):
        self.assertEqual(mapping_rows(self.store),[])
        self.assertEqual(status(self.store)['projected_counts'],{})
        matches=candidates(self.store)
        group_matches=[m for m in matches if m['local_id']=='testgroup']
        self.assertEqual(len(group_matches),2)
        self.assertTrue(all(m['status']=='needs_review' for m in group_matches))

    def test_group_cannot_be_mapped_to_same_named_malware(self):
        with self.assertRaises(ValueError):review_mapping(self.store,'testgroup','S9991','confirmed','Analyst','Wrong type')

    def test_confirmed_mapping_keeps_source_and_review_history(self):
        m=self.confirm()
        self.assertTrue(m['evidence_url'].startswith('https://attack.mitre.org/'))
        self.assertEqual(mapping_rows(self.store)[0]['effective_status'],'confirmed')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM attack_mapping_reviews').fetchone()[0],1)

    def test_projection_contains_software_techniques_parents_tactics_and_campaigns(self):
        self.confirm();_,objects,relationships,_=projection(self.store)
        for kind,num in [('malware',3),('tool',4),('attack-pattern',5),('attack-pattern',6),('x-mitre-tactic',7),('campaign',10)]:
            self.assertIn(sid(kind,num),objects)
        self.assertNotIn(sid('intrusion-set',2),objects)
        self.assertNotIn(sid('attack-pattern',8),objects)
        self.assertNotIn(sid('attack-pattern',9),objects)
        self.assertTrue(relationships)

    def test_mapping_is_not_entity_merge_or_observed_incident(self):
        self.confirm();qs=statements(self.store)
        text=' '.join(q['statement'] for q in qs)
        self.assertIn('ATTACK_MAPPING',text)
        self.assertIn('ATTACK_USES_TECHNIQUE',text)
        self.assertNotIn('AFFECTED_ORGANIZATION',text)
        self.assertNotIn('EXPLOITED',text)
        self.assertTrue(any('IN_TACTIC' in q['statement'] and q.get('parameters',{}).get('rows') for q in qs))
        self.assertTrue(any('SUBTECHNIQUE_OF' in q['statement'] for q in qs))

    def test_revoked_and_missing_relationship_targets_are_not_projected(self):
        self.confirm();_,_,relationships,_=projection(self.store)
        self.assertFalse(any(o['target_ref'] in (sid('attack-pattern',8),sid('attack-pattern',9)) for o in relationships))

    def test_identity_change_requires_new_mapping_review(self):
        self.confirm();data=fixture('2.0');data['objects'][1]['name']='Changed identity'
        import_bundle(self.store,payload(data))
        self.assertEqual(mapping_rows(self.store)[0]['effective_status'],'needs_review')
        self.assertFalse(projection(self.store)[1])

    def test_description_change_retains_identity_review(self):
        self.confirm();data=fixture('2.0');data['objects'][1]['description']='Updated description'
        import_bundle(self.store,payload(data))
        self.assertEqual(mapping_rows(self.store)[0]['effective_status'],'confirmed')
        self.assertTrue(projection(self.store)[1])

    def test_revoked_mapping_becomes_inactive_and_review_is_not_erased(self):
        self.confirm();data=fixture('2.0');data['objects'][1]['revoked']=True
        import_bundle(self.store,payload(data))
        m=mapping_rows(self.store)[0]
        self.assertEqual(m['status'],'confirmed');self.assertEqual(m['effective_status'],'inactive')
        self.assertFalse(projection(self.store)[1])

    def test_refutation_removes_mapping_edge_and_preserves_audit(self):
        self.confirm();review_mapping(self.store,'testgroup','G9991','refuted','Analyst','Rejected after checking')
        self.assertFalse(projection(self.store)[1])
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM attack_mapping_reviews').fetchone()[0],2)

    def test_demo_graph_does_not_include_real_attack_catalogue(self):
        self.confirm();self.assertEqual(statements(self.store,True),[])
        self.assertFalse(any('ATTACK_MAPPING' in q['statement'] for q in graph_statements(self.store,True)))

    def test_search_includes_ids_aliases_and_type_filter(self):
        self.assertEqual(search(self.store,'T9991.001')[0]['name'],'Test Subtechnique')
        self.assertEqual(len(search(self.store,'Shared Alias','ThreatActor')),2)
        self.assertEqual(search(self.store,'Revoked Technique'),[])
        with self.assertRaises(ValueError):search(self.store,'x',limit=0)

    def test_update_chooses_numeric_latest_and_downloads_pinned_url(self):
        index={'collections':[{'name':'Enterprise ATT&CK','versions':[
            {'version':'2.9','url':'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/old.json'},
            {'version':'2.10','url':'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/latest.json'}]}]}
        raw=payload(fixture('2.10'))
        with patch('app.attack.fetch_official',side_effect=[payload(index),raw]) as fetch:
            result=update(self.store,self.root/'cache')
        self.assertEqual(result['version'],'2.10')
        self.assertIn('latest.json',fetch.call_args.args[0])
        self.assertEqual(Path(result['cache_file']).read_bytes(),raw)

    def test_failed_network_or_version_mismatch_preserves_snapshot(self):
        before=catalogue(self.store)[0]['sha256']
        with patch('app.attack.fetch_official',side_effect=ValueError('network')):
            with self.assertRaises(ValueError):update(self.store,self.root/'cache')
        with self.assertRaises(ValueError):import_bundle(self.store,payload(fixture('2.0')),expected_version='3.0')
        self.assertEqual(catalogue(self.store)[0]['sha256'],before)

    def test_graph_relationships_keep_stix_evidence_and_reference_role(self):
        self.confirm()
        rows=[r for q in statements(self.store) if 'ATTACK_USES_TECHNIQUE' in q['statement'] for r in q['parameters']['rows']]
        self.assertTrue(rows)
        self.assertEqual(rows[0]['properties']['status'],'reported_by_attack')
        self.assertIn('example.org',rows[0]['properties']['external_references_json'])
        self.assertEqual(rows[0]['properties']['dataset_version'],'1.0')

    def test_report_has_reference_counts_and_reviewed_mappings(self):
        self.confirm();export_report(self.store,self.root/'report')
        data=json.loads((self.root/'report/report.json').read_text())
        self.assertEqual(data['attack']['dataset']['version'],'1.0')
        self.assertEqual(data['attack']['confirmed_mappings'],1)
        self.assertIn('MITRE ATT&amp;CK',(self.root/'report/report.html').read_text())

    def test_cached_restore_checks_hash_and_preserves_refutation(self):
        self.confirm();m=mapping_rows(self.store)[0]
        folder=self.root/'shipped';(folder/'cache').mkdir(parents=True)
        raw=payload(self.data);checksum=hashlib.sha256(raw).hexdigest()
        (folder/'cache'/(checksum+'.json')).write_bytes(raw)
        (folder/'import_manifest.json').write_text(json.dumps({'sha256':checksum,'source_url':'https://example.org','version':'1.0'}))
        (folder/'reviewed_mappings.json').write_text(json.dumps([m]))
        review_mapping(self.store,'testgroup','G9991','refuted','Analyst','Do not restore over my decision')
        self.assertEqual(restore_cached(self.store,folder)['restored_mappings'],0)
        self.assertEqual(mapping_rows(self.store)[0]['status'],'refuted')
        (folder/'cache'/(checksum+'.json')).write_bytes(b'changed')
        with self.assertRaises(ValueError):restore_cached(self.store,folder)

    def test_invalid_tactic_field_and_url_are_rejected_before_mutation(self):
        bad=copy.deepcopy(self.data);bad['objects'][5]['kill_chain_phases']=None
        with self.assertRaises(ValueError):parse_bundle(payload(bad))
        bad=copy.deepcopy(self.data);bad['objects'][1]['external_references'][0]['url']='javascript:alert(1)'
        with self.assertRaises(ValueError):parse_bundle(payload(bad))
