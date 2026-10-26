from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from app.collectors import ingest
from app.models import Publication
from app.storage import CTIStore
from app.research_context import build, statements, export
from app.graph_scoring import calculate_graph
from app.graph_audit import prepare

NOW='2026-10-24T12:00:00+00:00'
class ResearchContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=CTIStore(self.root/'db.sqlite3')
        self.store.load_companies([{'id':'alpha','name':'Example Co','sector':'Example','aliases':[]}])
        self.store.load_products([{'id':'product','name':'Example Product','aliases':[]}])
        self.clock=patch('app.storage.utcnow',return_value=NOW);self.clock.start()
    def tearDown(self):self.clock.stop();self.tmp.cleanup()
    def pub(self,title,text,**kwargs):
        p=Publication('test',kwargs.pop('url','https://source.example/'+str(len(self.store.publications()))),title,text,
                      published_at=kwargs.pop('published_at',NOW),collected_at=NOW,**kwargs)
        ingest(self.store,[p]);return p
    def use(self,observed='2026-10-01',version=None,network=None):
        p=self.pub('Fictional deployment','Example Co использует Example Product.' + (' Версия '+version if version else ''))
        attrs={'observed_day':observed} if observed else {}
        if version:attrs['version']=version
        if network:attrs.update(network_exposure=network,network_exposure_note='Fictional closed-network evidence.')
        uid=self.store.add_assertion({'kind':'uses_product','subject':'alpha','object':'product',
          'publication_id':p.id,'excerpt':p.text,'attributes':attrs})
        self.store.review_assertion(uid,'confirmed','Test analyst','Fictional evidence',confidence='medium',basis='research_report')
        return uid
    def notice(self,**kwargs):
        return self.pub('Fictional vendor patch','Example Product has a security patch.',metadata={
          'security_notice':{'product_id':'product','affected_ranges':[{'lte':'2.0.0'}],
          'fixed_versions':['2.0.1'],'extraction_status':'parsed_vendor_statement'}},**kwargs)
    def test_unknown_version_produces_conditional_hypothesis_not_probability(self):
        self.use();self.notice()
        result=build(self.store,NOW);r=result['hypotheses'][0]
        self.assertEqual(r['status'],'conditional_monitoring_candidate');self.assertFalse(r['is_probability'])
        self.assertIn('installed_version_unknown',r['missing']);self.assertIn('network_exposure_unknown',r['missing'])
        self.assertEqual(r['horizon_days'],30)
    def test_closed_network_is_a_counterargument_to_external_attack_hypothesis(self):
        self.use(network='closed_network');self.notice()
        r=build(self.store,NOW)['hypotheses'][0]
        self.assertEqual(r['status'],'internal_patch_review');self.assertTrue(r['counterevidence'])
    def test_known_fixed_version_is_excluded_from_hypothesis_edges(self):
        self.use(version='2.0.1');self.notice()
        r=build(self.store,NOW)
        self.assertEqual(r['hypotheses'][0]['status'],'version_outside_reported_range')
        self.assertFalse(any(e['relation']=='MONITORING_HYPOTHESIS' for e in r['edges']))
    def test_old_use_and_old_notice_do_not_create_current_candidates(self):
        self.use(observed='2020-01-01');self.notice()
        self.assertEqual(build(self.store,NOW)['hypotheses'][0]['status'],'insufficient_current_evidence')
        self.assertFalse(any(e['relation']=='MONITORING_HYPOTHESIS' for e in build(self.store,NOW)['edges']))
    def test_unknown_notice_date_is_not_replaced_with_collection_time(self):
        self.use();self.notice(published_at=None)
        r=build(self.store,NOW)['hypotheses'][0]
        self.assertIsNone(r['notice_age_days']);self.assertEqual(r['status'],'insufficient_current_evidence')
    def test_future_notice_is_excluded(self):
        self.use();self.notice(published_at='2026-10-25T12:00:00Z')
        self.assertEqual(build(self.store,NOW)['hypotheses'],[])
    def test_refuted_use_cannot_create_candidate(self):
        uid=self.use();self.notice();self.store.review_assertion(uid,'refuted','Analyst','Fictional retraction')
        self.assertEqual(build(self.store,NOW)['hypotheses'],[])
    def test_bug_bounty_neither_creates_software_use_nor_increases_interest(self):
        before=calculate_graph(self.store,as_of=NOW)
        p=self.pub('Example Co Bug Bounty','Public program; no attacks reported.',metadata={'signal_scope':'research_program',
          'bug_bounty_program':{'name':'Example Co','company_name':'Example Co','platform':'Test Bounty','url':'https://source.example/programs/example/'}})
        self.assertEqual(calculate_graph(self.store,as_of=NOW),before)
        r=build(self.store,NOW)
        self.assertEqual(len(r['programs']),1);self.assertEqual(r['hypotheses'],[])
        self.assertTrue(any(e['relation']=='HAS_PUBLIC_BUG_BOUNTY' for e in r['edges']))
    def test_program_mentions_of_unrelated_company_do_not_create_participation(self):
        self.pub('Other Co','Example Co uses some software.',metadata={'signal_scope':'research_program',
          'bug_bounty_program':{'name':'Other Co','platform':'Test Bounty','url':'https://source.example/programs/other/'}})
        self.assertFalse(any(e['relation']=='HAS_PUBLIC_BUG_BOUNTY' for e in build(self.store,NOW)['edges']))
    def test_projection_and_audit_include_qualified_context_in_general_view(self):
        self.use(network='closed_network');self.notice()
        expected=prepare(self.store,NOW)
        self.assertTrue(expected['context'])
        self.assertTrue(all(p['weight_role']=='research_context_only' for p in expected['context'].values()))
        hypotheses=[r for r in expected['views'].values() if r['relation']=='MONITORING_HYPOTHESIS']
        self.assertTrue(hypotheses)
        self.assertTrue(all(r['existing'] and r['match_property']=='id' for r in hypotheses))
        self.assertTrue(all(r['properties']['status']=='internal_patch_review' for r in hypotheses))
        from app.graph_audit import audit
        from tests.test_graph_audit import projected_fixture
        self.assertEqual(audit(expected,projected_fixture(expected))['status'],'passed')
        export(build(self.store,NOW),self.root/'report')
        self.assertIn('закрытом контуре',(self.root/'report/monitoring.html').read_text())

    def test_exact_fixed_branch_is_excluded_even_below_a_broad_older_limit(self):
        self.use(version='1.5.1')
        pub=self.pub('Fictional multi-branch fix','Example Product is fixed in two branches.',metadata={
          'security_notice':{'product_id':'product','affected_ranges':[{'lte':'2.0.0'}],
                            'fixed_versions':['2.0.1','1.5.1']}})
        self.assertEqual(build(self.store,NOW)['hypotheses'][0]['status'],'version_outside_reported_range')

    def test_recorded_queue_matches_its_frozen_evidence_after_source_changes(self):
        from app.research_context import record
        from app.review_snapshot import restore_snapshot, read_snapshot
        self.use();self.notice()
        result=record(self.store,self.root/'report',self.root/'history')
        folder=Path(result['recorded_snapshot'])
        metadata=read_snapshot(folder/'snapshot.json.gz')
        self.pub('Later data','This publication must not enter the recorded state.')
        restore_snapshot(folder/'snapshot.json.gz',self.root/'restored.sqlite3')
        restored=CTIStore(self.root/'restored.sqlite3')
        self.assertEqual(build(restored,metadata['frozen_at']),json.loads((folder/'queue.json').read_text()))

    def test_download_time_does_not_erase_a_newer_explicit_scope_update(self):
        self.use(version='1.5.1')
        url='https://source.example/same-notice'
        for source,scope in [('manual',{'scope_updated_day':'2026-10-23','fixed_versions':['2.0.1','1.5.1']}),
                             ('automated',{'fixed_versions':['2.0.1']})]:
            p=Publication(source,url,'Fictional patch','Example Product security notice.',
                          published_at='2026-10-22T12:00:00Z',collected_at=NOW,
                          metadata={'security_notice':{'product_id':'product','affected_ranges':[{'lte':'2.0.0'}],**scope}})
            ingest(self.store,[p])
        rows=build(self.store,NOW)['hypotheses']
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['status'],'version_outside_reported_range')

    def test_matching_exploitation_report_adds_context_without_promoting_closed_network(self):
        self.use(network='closed_network');self.notice()
        self.pub('Fictional release','Example Product fixes CVE-2026-123456.',metadata={
            'software_update':{'product_id':'product','fixed_versions':['2.0.1'],'reference_cves':['CVE-2026-123456']}})
        self.pub('Исследователи зафиксировали попытки эксплуатации CVE-2026-123456',
                 'Fictional telemetry report; no named victim.')
        result=build(self.store,NOW)
        row=result['hypotheses'][0]
        self.assertEqual(row['status'],'internal_patch_review')
        self.assertEqual(row['related_exploitation_reports'][0]['cves'],['CVE-2026-123456'])
        self.assertTrue(any(e['relation']=='SECURITY_UPDATE_FOR' for e in result['edges']))
        self.assertFalse(any(e['relation']=='ATTRIBUTED_ATTACK_ON' for e in result['edges']))

    def test_combined_view_connects_shared_cve_with_sources_without_duplicate_attacks(self):
        from app.company_overview import overview_rows
        from app.graph_audit import audit
        from tests.test_graph_audit import projected_fixture
        from app.graph_view import export as export_view
        self.use(network='closed_network');self.notice()
        release=self.pub('Fictional release','Example Product fixes CVE-2026-123456.',metadata={
            'software_update':{'product_id':'product','reference_cves':['CVE-2026-123456']}})
        report=self.pub('Зафиксированы попытки эксплуатации CVE-2026-123456',
                        'Fictional telemetry report; no named victim.')
        rows=overview_rows(self.store,NOW)
        cves=[r for r in rows if r['relation']=='MENTIONS_CVE']
        self.assertEqual({r['subject'] for r in cves},{release.id,report.id})
        self.assertTrue(all(r['existing'] and r['match_property'] is None for r in cves))
        self.assertEqual({r['object'] for r in cves},{'real:CVE-2026-123456'})
        self.assertFalse(any(r['relation']=='ATTRIBUTED_ATTACK_ON' for r in rows))
        expected=prepare(self.store,NOW)
        live=projected_fixture(expected)
        self.assertEqual(audit(expected,live)['status'],'passed')
        source_edge=next(e for e in live['relationships'] if e['relation']=='PUBLISHED_BY')
        source_edge['object']='wrong-source'
        self.assertEqual(audit(expected,live)['status'],'failed')
        output=self.root/'viewer'
        export_view(self.store,output,as_of=NOW)
        data=json.loads((output/'graph_view.json').read_text())
        self.assertEqual({n['id'] for n in data['nodes']},{r[k] for r in rows for k in ('subject','object')})
        self.assertEqual(len(data['edges']),len(rows))
        usage=next(e for e in data['edges'] if e['type']=='USES_PRODUCT')
        self.assertIsInstance(usage['properties']['weight'],float)
        self.assertEqual(usage['properties']['network_exposure'],'closed_network')
        self.assertTrue(usage['properties']['evidence_url'].startswith('https://'))

    def test_viewer_escapes_untrusted_program_names_and_preserves_unknown_indices(self):
        from app.graph_view import export as export_view
        self.pub('Fictional program','Public program.',metadata={'bug_bounty_program':{
            'name':'</script><script>alert(1)</script>', 'company_name':'Example Co',
            'platform':'Fictional bounty','url':'https://source.example/programs/alpha/'}})
        output=self.root/'viewer'
        export_view(self.store,output,as_of=NOW)
        data=json.loads((output/'graph_view.json').read_text())
        company=next(n for n in data['nodes'] if n['type']=='Company')
        self.assertIsNone(company['properties']['interest_index'])
        page=(output/'graph_view.html').read_text()
        self.assertNotIn('</script><script>alert(1)</script>',page)
        self.assertIn('\\u003c/script\\u003e',page)
        self.assertIn('60000',page)
        self.assertEqual(data['as_of'],NOW)

    def test_unrelated_cve_in_report_does_not_create_an_exploitation_context(self):
        self.use();self.notice()
        self.pub('Fictional release','Example Product fixes CVE-2026-123456.',metadata={
            'software_update':{'product_id':'product','reference_cves':['CVE-2026-123456']}})
        self.pub('Зафиксированы попытки эксплуатации CVE-2026-999999','Fictional unrelated report.')
        self.assertEqual(build(self.store,NOW)['hypotheses'][0]['related_exploitation_reports'],[])
