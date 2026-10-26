from datetime import datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.models import Publication, utcnow, UTC
from app.storage import CTIStore
from app.collectors import ingest
from app.knowledge import extract_relations, exposure_rows, version_match
from app.enrichment import reindex
from app.graph import statements
from app.reporting import export_report

COMPANIES = [{'id': 'alpha', 'name': 'Альфа', 'aliases': ['Alpha'], 'domains': ['alpha.example'], 'sector': 'Торговля'},
             {'id': 'beta', 'name': 'Бета', 'aliases': ['Beta'], 'domains': ['beta.example'], 'sector': 'Торговля'}]
PRODUCTS = [{'id': 'testserver', 'name': 'TestServer', 'aliases': ['ТестСервер'], 'vendor': 'TestVendor'},
            {'id': 'testclient', 'name': 'TestClient', 'aliases': [], 'vendor': 'TestVendor'}]


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root / 'db.sqlite3')
        self.store.load_companies(COMPANIES)
        self.store.load_products(PRODUCTS)

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, text, slug='1'):
        pub = Publication('test', 'https://source.example/' + slug, 'Открытые сведения', text, published_at=utcnow())
        ingest(self.store, [pub])
        return pub

    def confirm(self, kind, attrs=None, subject=None):
        a = next(a for a in self.store.assertions() if a['kind'] == kind and (not subject or a['subject'] == subject))
        row = {k: a[k] for k in ('kind', 'subject', 'object', 'publication_id', 'excerpt')}
        row['attributes'] = attrs or {}
        identifier = self.store.add_assertion(row)
        self.store.review_assertion(identifier, 'confirmed', 'test-reviewer', 'Проверено на контрольном примере', confidence='medium', basis='research_report')
        return identifier

    def setup_exposure(self, version='1.2.3', day=None, ranges=None):
        self.add('Альфа использует TestServer версии 1.2.3.', 'use')
        self.add('Уязвимость CVE-2099-30001 затрагивает TestServer версии 1.2.3.', 'advisory')
        attrs = {'observed_day': day or utcnow()[:10]}
        if version:
            attrs['version'] = version
        self.confirm('uses_product', attrs)
        self.confirm('affects_product', ranges or {'affected_versions': ['1.2.3']})

    def test_product_mention_does_not_assert_use(self):
        self.add('Альфа упоминает TestServer в обзоре программных продуктов.')
        self.assertEqual(self.store.assertions(), [])
        pub = self.store.publications()[0]
        self.assertEqual(json.loads(pub['extraction'])['products'], ['testserver'])

    def test_use_phrase_creates_only_review_candidate(self):
        self.add('Альфа использует TestServer.')
        a = self.store.assertions()[0]
        self.assertEqual(a['kind'], 'uses_product')
        self.assertEqual(a['status'], 'needs_review')

    def test_denial_does_not_create_use_claim(self):
        self.add('Альфа не использует TestServer.')
        self.assertEqual(self.store.assertions(), [])

    def test_planned_deployment_is_not_use(self):
        self.add('Альфа планирует внедрить TestServer.')
        self.assertEqual(self.store.assertions(), [])

    def test_ambiguous_product_cve_pair_not_guessed(self):
        self.add('Уязвимость CVE-2099-30001 затрагивает TestServer и TestClient.')
        self.assertFalse(any(a['kind'] == 'affects_product' for a in self.store.assertions()))

    def test_membership_direction_preserved(self):
        self.add('Alpha входит в Beta.')
        a = self.store.assertions()[0]
        self.assertEqual((a['subject'], a['object'], a['kind']), ('alpha', 'beta', 'part_of'))

    def test_supplier_direction_preserved(self):
        self.add('Бета поставляет услуги Альфа.')
        a = self.store.assertions()[0]
        self.assertEqual((a['subject'], a['object'], a['kind']), ('beta', 'alpha', 'supplies_to'))

    def test_missing_version_remains_unknown(self):
        self.setup_exposure(version=None)
        self.assertEqual(exposure_rows(self.store)[0]['status'], 'version_unknown')

    def test_matching_version_requires_configuration_check(self):
        self.setup_exposure()
        row = exposure_rows(self.store)[0]
        self.assertEqual(row['status'], 'version_match_requires_configuration_check')
        self.assertIn('не установлен', row['interpretation'])

    def test_historical_use_never_claims_current_exposure(self):
        self.setup_exposure(day='2020-01-01')
        self.assertEqual(exposure_rows(self.store)[0]['status'], 'historical_use_only')

    def test_future_use_never_claims_exposure(self):
        day = (datetime.now(UTC) + timedelta(days=2)).date().isoformat()
        self.setup_exposure(day=day)
        self.assertEqual(exposure_rows(self.store)[0]['status'], 'future_evidence')

    def test_unreviewed_pair_stays_needs_review(self):
        self.add('Альфа использует TestServer версии 1.2.3.', 'use')
        self.add('Уязвимость CVE-2099-30001 затрагивает TestServer.', 'advisory')
        self.assertEqual(exposure_rows(self.store)[0]['status'], 'needs_review')

    def test_version_outside_range(self):
        self.setup_exposure(ranges={'affected_versions': ['1.2.2']})
        self.assertEqual(exposure_rows(self.store)[0]['status'], 'version_outside_reported_range')

    def test_numeric_versions_not_lexical(self):
        self.assertTrue(version_match('1.10.0', {'affected_ranges': [{'gte': '1.9', 'lt': '1.11'}]}))
        self.assertFalse(version_match('1.2.0', {'affected_ranges': [{'gte': '1.9', 'lt': '1.11'}]}))

    def test_fixed_version_does_not_imply_affected_range(self):
        self.assertIsNone(version_match('1.2.3', {'fixed_versions': ['1.2.4']}))

    def test_change_to_source_invalidates_review(self):
        self.add('Альфа использует TestServer версии 1.2.3.')
        identifier = self.confirm('uses_product', {'version': '1.2.3'})
        self.add('Альфа использует TestServer версии 1.2.4.')
        self.assertEqual(self.store.assertions()[0]['status'], 'needs_review')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM assertion_reviews').fetchone()[0], 1)

    def test_reindex_preserves_reviewed_version(self):
        self.setup_exposure()
        before = [(a['id'], a['attributes'], a['status']) for a in self.store.assertions()]
        reindex(self.store)
        after = [(a['id'], a['attributes'], a['status']) for a in self.store.assertions()]
        self.assertEqual(before, after)

    def test_asserted_version_must_appear_in_evidence(self):
        self.add('Альфа использует TestServer.')
        with self.assertRaises(ValueError):
            self.confirm('uses_product', {'version': '1.2.3'})

    def test_version_prefix_is_not_exact_version_evidence(self):
        self.add('Альфа использует TestServer версии 1.2.30.')
        with self.assertRaises(ValueError):
            self.confirm('uses_product', {'version': '1.2.3'})

    def test_import_cannot_self_confirm(self):
        pub = self.add('Альфа использует TestServer.')
        with self.assertRaises(ValueError):
            self.store.add_assertion({'kind':'uses_product','subject':'alpha','object':'testserver',
                'publication_id':pub.id,'excerpt':pub.text,'status':'confirmed'})

    def test_excerpt_must_exist(self):
        pub = self.add('Альфа использует TestServer.')
        with self.assertRaises(ValueError):
            self.store.add_assertion({'kind':'uses_product','subject':'alpha','object':'testserver',
                'publication_id':pub.id,'excerpt':'Бета использует TestServer.'})

    def test_refuted_use_drops_derived_exposure(self):
        self.setup_exposure()
        a = next(a for a in self.store.assertions() if a['kind'] == 'uses_product')
        self.store.review_assertion(a['id'], 'refuted', 'reviewer', 'Использование опровергнуто')
        self.assertEqual(exposure_rows(self.store), [])

    def test_company_relation_not_derived_from_cooccurrence(self):
        self.add('Альфа и Бета упомянуты в одном обзоре отрасли.')
        self.assertEqual(self.store.assertions(), [])

    def test_graph_has_products_domains_sectors_and_evidence(self):
        self.setup_exposure()
        qs = statements(self.store)
        combined = '\n'.join(q['statement'] for q in qs)
        for relation in ['USES_PRODUCT', 'AFFECTS', 'HAS_DOMAIN', 'IN_SECTOR', 'SUPPORTS', 'POTENTIALLY_AFFECTED_BY']:
            self.assertIn(relation, combined)
        rows = next(q['parameters']['rows'] for q in qs if 'r:USES_PRODUCT ' in q['statement'])
        evidence = next(a for a in self.store.assertions() if a['kind'] == 'uses_product')
        self.assertEqual(rows[0]['properties']['evidence_hash'], evidence['evidence_hash'])

    def test_pending_graph_does_not_have_confirmed_use_edge(self):
        self.add('Альфа использует TestServer.')
        combined = '\n'.join(q['statement'] for q in statements(self.store))
        self.assertIn('r:REPORTED_USES_PRODUCT ', combined)
        self.assertNotIn('r:USES_PRODUCT ', combined)

    def test_report_explains_technical_context(self):
        self.setup_exposure(version=None)
        export_report(self.store, self.root / 'report')
        data = json.loads((self.root / 'report/report.json').read_text())
        self.assertEqual(data['technical_context'][0]['status'], 'version_unknown')
        self.assertEqual(len(data['assertions']), 2)

    def test_refresh_failure_preserves_local_report(self):
        from app.main import parser, run
        sources = self.root / 'sources.json'
        sources.write_text(json.dumps([{'id':'test','url':'https://source.example/rss',
                                       'allowed_hosts':['source.example'],'enabled':False}]))
        args = parser().parse_args(['--db', str(self.store.path), 'refresh', '--sources', str(sources),
                                   '--output', str(self.root / 'report')])
        with patch('app.graph.sync_graph', side_effect=OSError('password=secret')):
            result = run(args)
        self.assertEqual(result['graph']['status'], 'error')
        self.assertNotIn('secret', json.dumps(result))
        self.assertTrue((self.root / 'report/report.html').exists())

    def test_worker_syncs_graph_without_stopping_on_graph_failure(self):
        from app.main import parser, run
        from app.automation import run_worker
        sources = self.root / 'sources.json'
        sources.write_text(json.dumps([{'id':'test','url':'https://source.example/rss',
                                       'allowed_hosts':['source.example'],'enabled':False}]))
        args = parser().parse_args(['--db', str(self.store.path), 'worker', '--sync-graph',
                                   '--sources', str(sources), '--output', str(self.root / 'report')])
        with patch('app.automation.sync_graph', side_effect=OSError('secret')) as sync, \
             patch('app.automation.run_worker', side_effect=lambda *a, **kw:
                   run_worker(*a, status_folder=self.root / 'status', **kw)), \
             patch('app.automation.threading.Event.wait', side_effect=KeyboardInterrupt), patch('builtins.print') as log:
            with self.assertRaises(KeyboardInterrupt):
                run(args)
        sync.assert_called_once()
        self.assertNotIn('secret', str(log.call_args_list))


if __name__ == '__main__':
    unittest.main()
