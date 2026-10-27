import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.config import ROOT
from app.storage import CTIStore
from app.models import Publication
from app.collectors import ingest, parse_source, collect_source
from app.enrichment import expand_knowledge, reindex
from app.knowledge import exposure_rows
from app.graph import statements
from app.scoring import calculate

FIX = Path(__file__).parent / 'fixtures'
VENDOR = {'id':'vendor_test','kind':'vendor_advisories',
          'url':'https://vendor.example/advisories','allowed_hosts':['vendor.example']}


class VendorParserTests(unittest.TestCase):
    def test_row_identity_and_product_variants_are_preserved(self):
        pubs, warnings = parse_source((FIX/'vendor_advisories_demo.html').read_bytes(), VENDOR, is_demo=True)
        self.assertEqual(len(pubs), 3)
        self.assertEqual(warnings, [])
        self.assertEqual(pubs[0].metadata['vendor_record']['product_id'], 'trueconf-server')
        self.assertEqual(pubs[2].metadata['vendor_record']['product_id'], 'trueconf-client')
        self.assertTrue(all(p.is_demo for p in pubs))

    def test_exact_version_is_parsed_but_conditional_range_is_not_guessed(self):
        pubs, _ = parse_source((FIX/'vendor_advisories_demo.html').read_bytes(), VENDOR)
        attrs = pubs[0].metadata['vendor_record']['attributes']
        self.assertEqual(attrs['affected_versions'], ['1.2.3'])
        attrs = pubs[1].metadata['vendor_record']['attributes']
        self.assertNotIn('affected_ranges', attrs)
        self.assertIn('Linux only', attrs['affected_version_text'])

    def test_missing_table_is_failure(self):
        with self.assertRaises(ValueError):
            parse_source(b'<html><h1>captcha</h1></html>', VENDOR)

    def test_stable_ids_for_same_url_different_rows(self):
        pubs, _ = parse_source((FIX/'vendor_advisories_demo.html').read_bytes(), VENDOR)
        self.assertEqual(len({p.url for p in pubs}), 1)
        self.assertEqual(len({p.id for p in pubs}), 3)

    def test_case_footer_does_not_invent_server_deployment(self):
        source = dict(VENDOR, kind='vendor_case')
        pubs, _ = parse_source((FIX/'vendor_case_demo.html').read_bytes(), source)
        self.assertIn('TrueConf Enterprise', pubs[0].text)
        self.assertNotIn('TrueConf Server', pubs[0].text)
        self.assertNotIn('TrueConf Client', pubs[0].text)
        self.assertEqual(pubs[0].metadata['publication_day'], '2026-10-21')
        self.assertIsNone(pubs[0].published_at)


class ExpansionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CTIStore(Path(self.tmp.name)/'db.sqlite3')

    def tearDown(self):
        self.tmp.cleanup()

    def test_reviewed_library_imports_on_empty_database(self):
        result = expand_knowledge(self.store, ROOT)
        self.assertEqual(result['library_publications'], 21)
        self.assertEqual(result['library_claims'], 25)
        self.assertEqual(len(self.store.assertions()), 25)
        configured = json.loads((ROOT/'config/companies.json').read_text())
        self.assertEqual({c['id'] for c in self.store.companies()}, {c['id'] for c in configured} | {'rosatom-engineering'})
        self.assertEqual(result['companies'], len(self.store.companies()))
        self.assertTrue(all(a['reviewer']=='project_source_review' for a in self.store.assertions()))

    def test_reimport_does_not_duplicate_or_erase_refutation(self):
        expand_knowledge(self.store, ROOT)
        assertion = self.store.assertions()[0]
        self.store.review_assertion(assertion['id'],'refuted','analyst','Проверка требует пересмотра')
        result = expand_knowledge(self.store, ROOT)
        self.assertEqual(result['counts'], {'unchanged':21})
        self.assertEqual(result['existing_reviews_preserved'],25)
        row = next(a for a in self.store.assertions() if a['id']==assertion['id'])
        self.assertEqual(row['status'],'refuted')

    def test_enterprise_does_not_inherit_server_vulnerabilities(self):
        expand_knowledge(self.store, ROOT)
        exposures = exposure_rows(self.store)
        self.assertFalse(any(r['company_id'] in ('sibur','oteko','metalloinvest') for r in exposures))
        self.assertTrue(any(r['company_id']=='roszarubezhneft' and r['status']=='version_unknown' for r in exposures))

    def test_vendor_is_context_not_ranked_target(self):
        expand_knowledge(self.store, ROOT)
        self.assertNotIn('1c-vendor', [r['company_id'] for r in calculate(self.store)])
        self.assertIn('1c-vendor', [c['id'] for c in self.store.companies()])

    def test_bdu_survives_reindex_and_graph_export(self):
        expand_knowledge(self.store, ROOT)
        reindex(self.store)
        bdu = [a for a in self.store.assertions() if a['subject'].startswith('BDU:')]
        self.assertEqual(len(bdu),3)
        queries = statements(self.store)
        row = next(q for q in queries if 'v.bdu_id=row.bdu_id' in q['statement'])
        self.assertEqual(len(row['parameters']['rows']),3)
        self.assertTrue(any('s:Vulnerability' in q['statement'] and 'r:AFFECTS ' in q['statement'] for q in queries))

    def test_bdu_candidate_is_not_auto_confirmed_by_table(self):
        self.store.load_products([{'id':'trueconf-server','name':'TrueConf Server','aliases':[], 'is_demo':True},
                                  {'id':'trueconf-client','name':'TrueConf Client','aliases':[], 'is_demo':True}])
        pubs, _ = parse_source((FIX/'vendor_advisories_demo.html').read_bytes(), VENDOR, is_demo=True)
        ingest(self.store,pubs)
        assertions = self.store.assertions(True)
        self.assertTrue(any(a['subject']=='BDU:2099-40002' for a in assertions))
        self.assertTrue(all(a['status']=='needs_review' for a in assertions))

    def test_same_host_sources_reuse_robots_and_throttle(self):
        rss = b'<rss><channel><item><title>x</title><link>https://vendor.example/p</link></item></channel></rss>'
        source1 = dict(VENDOR,kind='rss',id='one')
        source2 = dict(VENDOR,kind='rss',id='two')
        runtime = {}
        with patch('app.collectors.fetch', side_effect=[(b'User-agent: *\nAllow: /',{}),(rss,{}),(rss,{})]) as network, \
             patch('app.collectors.time.sleep') as sleep:
            collect_source(self.store,source1,runtime)
            collect_source(self.store,source2,runtime)
        self.assertEqual(network.call_count,3)
        self.assertGreaterEqual(sleep.call_count,2)


if __name__ == '__main__':
    unittest.main()
