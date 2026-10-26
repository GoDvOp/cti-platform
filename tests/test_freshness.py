import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.collectors import collect_source, ingest, parse_feed, source_status
from app.freshness import summarize, audit
from app.kev import parse_kev
from app.models import Publication
from app.russian_sources import parse_article_date
from app.storage import CTIStore

NOW = '2026-10-24T10:00:00+00:00'
SOURCE = {'id': 'fresh_test', 'url': 'https://source.example/feed',
          'allowed_hosts': ['source.example'], 'freshness_days': 30}


class FreshnessTests(unittest.TestCase):
    def test_recent_download_does_not_refresh_old_evidence(self):
        result = summarize([{'published_at': '2022-02-25T11:00:00Z', 'collected_at': NOW}], 30, NOW)
        self.assertEqual(result['status'], 'stale')
        self.assertEqual(result['stale'], 1)
        self.assertEqual(result['newest_day'], '2022-02-25')

    def test_day_precision_unknown_and_future_are_separate(self):
        result = summarize([{'metadata': {'publication_day': '2026-10-23'}},
                            {'collected_at': NOW},
                            {'metadata': {'publication_day': '2027-01-01'}}], 7, NOW)
        self.assertEqual((result['recent'], result['unknown'], result['future']), (1, 1, 1))
        self.assertEqual(result['status'], 'future_dates')
        self.assertEqual(result['newest_day'], '2026-10-23')

    def test_window_boundary_and_malformed_day(self):
        result = summarize([{'metadata': {'publication_day': '2026-10-17'}},
                            {'metadata': {'publication_day': '2026-10-16'}},
                            {'metadata': {'publication_day': '2026-02-30'}}], 7, NOW)
        self.assertEqual((result['recent'], result['stale'], result['unknown']), (1, 1, 1))

    def test_catalog_inclusion_has_distinct_meaning(self):
        result = summarize([{'metadata': {'catalog_added_day': '2026-10-23'}}], 30, NOW)
        self.assertEqual(result['date_meanings'], {'catalog_added': 1})
        self.assertEqual(result['recent'], 1)

    def test_empty_is_not_recent(self):
        self.assertEqual(summarize([], 30, NOW)['status'], 'empty')

    def test_article_date_ignores_modified_and_copyright(self):
        data = b'<meta property="article:modified_time" content="2026-10-23T11:00:00Z"><footer>2026</footer>'
        self.assertEqual(parse_article_date(data), (None, None))
        data += b'<meta property="article:published_time" content="2022-02-25T12:00:00+03:00">'
        self.assertEqual(parse_article_date(data), ('2022-02-25T09:00:00+00:00', None))

    def test_article_day_does_not_invent_midnight(self):
        self.assertEqual(parse_article_date(b'<meta itemprop="datePublished" content="2026-10-23">'),
                         (None, '2026-10-23'))

    def test_atom_updated_is_not_publication_date(self):
        data = b'<feed><entry><title>Test</title><link href="https://source.example/one"/><updated>2026-10-23T12:00:00Z</updated></entry></feed>'
        pubs, _ = parse_feed(data, 'test')
        self.assertIsNone(pubs[0].published_at)


class FreshnessPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CTIStore(Path(self.tmp.name) / 'test.sqlite3')

    def tearDown(self):
        self.tmp.cleanup()

    def test_old_feed_is_partial_and_kept_as_evidence(self):
        xml = b'<rss><channel><item><title>Old</title><link>https://source.example/old</link><pubDate>Fri, 25 Feb 2022 11:00:00 GMT</pubDate></item></channel></rss>'
        with patch('app.collectors.checked_fetch', return_value=(xml, {})):
            result = collect_source(self.store, SOURCE)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['warnings'][0]['error_code'], 'data_stale')
        self.assertEqual(len(self.store.publications()), 1)
        self.assertEqual(source_status(self.store, [SOURCE])[0]['freshness']['status'], 'stale')

    def test_dates_persist_with_unchanged_text_without_resetting_reviews(self):
        original = Publication('test', 'https://source.example/one', 'Test', 'Text', collected_at='2026-10-20T12:00:00Z')
        ingest(self.store, [original])
        enriched = Publication('test', original.url, 'Test', 'Text', published_at='2026-10-19T12:00:00Z')
        self.assertEqual(ingest(self.store, [enriched]), {'updated': 1})
        row = self.store.publications()[0]
        self.assertEqual(row['published_at'], enriched.published_at)
        self.assertEqual(json.loads(row['data'])['collected_at'], original.collected_at)
        self.assertEqual(ingest(self.store, [Publication('test', original.url, 'Test', 'Text')]), {'unchanged': 1})
        self.assertEqual(self.store.publications()[0]['published_at'], enriched.published_at)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM publication_metadata_updates').fetchone()[0], 1)
            self.assertIsNone(json.loads(db.execute('SELECT data FROM publication_versions').fetchone()[0])['published_at'])

    def test_disabled_archive_and_manual_sources_are_visible(self):
        ingest(self.store, [Publication('manual', 'https://source.example/one', 'Test', 'Text')])
        rows = audit(self.store, [dict(SOURCE, enabled=False, freshness_mode='archive')], as_of=NOW)
        self.assertEqual(next(r for r in rows if r['source_id'] == 'manual')['mode'], 'manual')
        self.assertEqual(next(r for r in rows if r['source_id'] == SOURCE['id'])['mode'], 'archive')

    def test_securelist_reads_date_without_importing_full_text_and_caches_it(self):
        source = dict(SOURCE, kind='securelist_listing', max_date_documents=1)
        listing = b'<h3><a href="https://source.example/report/999999/">Research title</a></h3>'
        article = b'<meta property="article:published_time" content="2026-10-23T12:00:00Z"><p>Full article body excluded</p>'
        with patch('app.collectors.checked_fetch', side_effect=[(listing, {}), (article, {})]) as fetch:
            result = collect_source(self.store, source)
        self.assertEqual(fetch.call_count, 2)
        pub = json.loads(self.store.publications()[0]['data'])
        self.assertEqual(pub['published_at'], '2026-10-23T12:00:00+00:00')
        self.assertNotIn('Full article body', pub['text'])
        with self.store.connect() as db:
            db.execute('DELETE FROM source_runs')
        with patch('app.collectors.checked_fetch', return_value=(listing, {})) as fetch:
            collect_source(self.store, source)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(self.store.publications()[0]['published_at'], pub['published_at'])


class KEVTests(unittest.TestCase):
    def payload(self):
        items = [{'cveID': cve, 'dateAdded': day, 'vendorProject': 'Example', 'product': 'Product',
                  'vulnerabilityName': 'Example vulnerability', 'shortDescription': 'Example description',
                  'requiredAction': 'Apply fixes'} for cve, day in
                 [('CVE-2026-99999', '2026-01-01'), ('CVE-2018-99999', '2026-10-23')]]
        return json.dumps({'catalogVersion': 'test', 'dateReleased': '2026-10-23T12:00:00Z',
                           'count': 2, 'vulnerabilities': items}).encode()

    def test_sort_by_addition_not_cve_year(self):
        pubs, errors = parse_kev(self.payload(), dict(SOURCE, max_items=1))
        self.assertEqual(errors, [])
        self.assertEqual(pubs[0].external_id, 'CVE-2018-99999')
        self.assertIsNone(pubs[0].published_at)
        self.assertEqual(pubs[0].metadata['catalog_added_day'], '2026-10-23')
        self.assertNotIn('publication_day', pubs[0].metadata)

    def test_partial_record_and_invalid_schema(self):
        data = json.loads(self.payload()); data['vulnerabilities'][0]['dateAdded'] = '2026-02-30'
        pubs, errors = parse_kev(json.dumps(data).encode(), SOURCE)
        self.assertEqual(len(pubs), 1)
        self.assertEqual(errors, ['invalid_kev_record'])
        with self.assertRaises(ValueError):
            parse_kev(b'{"error":"Access denied"}', SOURCE)
