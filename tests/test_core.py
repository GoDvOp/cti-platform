import json
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.models import Publication, canonical_url, utcnow, UTC, redact
from app.extraction import extract, event_type
from app.collectors import parse_feed, ingest, import_jsonl, collect_source, validate_feed_url
from app.storage import CTIStore
from app.scoring import calculate
from app.reporting import export_report, csv_safe
from app.graph import statements

COMPANIES = [
    {'id': 'alpha', 'name': 'Учебная Альфа', 'aliases': ['АльфаБренд'], 'domains': ['alpha.example']},
    {'id': 'beta', 'name': 'Учебная Бета', 'aliases': [], 'domains': ['beta.example']},
]


def publication(**changes):
    return Publication(**dict({'source_id': 'test', 'url': 'https://news.example/1',
                              'title': 'Сообщение', 'text': 'Продаётся доступ к alpha.example.',
                              'published_at': utcnow()}, **changes))


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root / 'test.sqlite3')
        self.store.load_companies(COMPANIES)

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, pub=None):
        pub = pub or publication()
        ingest(self.store, [pub])
        return pub

    def factors(self, age=0):
        pub = self.add()
        signal = self.store.signals()[0]
        self.store.review(signal['id'], 'confirmed', 'unresolved', 'medium', 'аналитик',
                          'Компания сопоставлена; доступ не подтверждён')
        for key, score in [('I', 75), ('S', 75), ('H', 50)]:
            self.store.set_factor('alpha', key, {'score': score, 'reason': 'Контрольное обоснование',
                'reviewer': 'аналитик', 'evidence_ids': [pub.id],
                'evidence_hashes': {pub.id: pub.content_hash}, 'confidence': 'medium',
                'observed_at': (datetime.now(UTC) - timedelta(days=age)).isoformat()})
        return pub, signal

    def test_insert_has_company_in_latest_signal(self):
        self.add()
        self.assertEqual(self.store.signals()[0]['company_id'], 'alpha')

    def test_reimport_idempotent(self):
        pub = self.add()
        result = ingest(self.store, [pub])
        self.assertEqual(result, {'unchanged': 1})
        self.assertEqual(len(self.store.publications()), 1)
        self.assertEqual(len(self.store.signals()), 1)

    def test_reposts_preserved_with_same_content_hash(self):
        self.add()
        self.add(publication(source_id='repost', url='https://copy.example/1'))
        pubs = self.store.publications()
        self.assertEqual(len(pubs), 2)
        self.assertEqual(pubs[0]['content_hash'], pubs[1]['content_hash'])

    def test_changed_text_resets_review_and_preserves_version(self):
        pub = self.add()
        signal = self.store.signals()[0]
        self.store.review(signal['id'], 'confirmed', 'unresolved', 'medium', 'аналитик', 'Совпадает домен')
        self.add(publication(text='Продаётся доступ к alpha.example, условия изменены.'))
        self.assertEqual(self.store.signals()[0]['entity_status'], 'needs_review')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM publication_versions').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT count(*) FROM reviews').fetchone()[0], 1)

    def test_removed_claim_no_longer_active(self):
        self.add()
        self.add(publication(text='Обычная статья без упоминания компаний и угроз.'))
        self.assertEqual(self.store.signals(), [])

    def test_demo_separated_from_real(self):
        self.add(publication(is_demo=True))
        self.assertEqual(len(self.store.publications()), 0)
        self.assertEqual(len(self.store.signals(True)), 1)

    def test_identical_real_and_demo_urls_have_separate_ids(self):
        self.add(publication(is_demo=True))
        self.add(publication(is_demo=False))
        self.assertEqual(len(self.store.publications()), 1)
        self.assertEqual(len(self.store.publications(True)), 1)
        self.assertNotEqual(self.store.publications()[0]['id'], self.store.publications(True)[0]['id'])

    def test_wrong_review_status_rejected(self):
        self.add()
        with self.assertRaises(ValueError):
            self.store.review(self.store.signals()[0]['id'], 'confirmed', 'proven-by-magic', 'high', 'a', 'b')

    def test_no_factors_is_unknown_not_zero(self):
        self.add()
        row = calculate(self.store)[0]
        self.assertIsNone(row['score'])
        self.assertEqual(row['coverage'], 0)

    def test_reproducible_known_score(self):
        self.factors()
        at = utcnow()
        result = calculate(self.store, as_of=at)
        self.assertEqual(result, calculate(self.store, as_of=at))
        self.assertEqual(result[0]['score'], 70)
        self.assertEqual(result[0]['coverage'], 100)

    def test_ninety_day_half_life(self):
        self.factors(age=90)
        self.assertEqual(calculate(self.store)[0]['score'], 35)

    def test_future_observation_not_used(self):
        self.factors(age=-1)
        row = calculate(self.store)[0]
        self.assertIsNone(row['score'])
        self.assertIn('I', row['missing'])

    def test_historical_cut_excludes_newly_collected(self):
        self.factors()
        old = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        self.assertEqual(self.store.signals(as_of=old), [])
        self.assertIsNone(calculate(self.store, as_of=old)[0]['score'])

    def test_partial_scores_not_ranked(self):
        self.factors()
        with self.store.connect() as db:
            db.execute("DELETE FROM factors WHERE factor='H'")
        row = calculate(self.store)[0]
        self.assertIsNone(row['score'])
        self.assertEqual(row['partial_score'], 75)
        self.assertEqual(row['coverage'], 80)

    def test_rejected_company_excluded_from_direct_factor(self):
        _, signal = self.factors()
        self.store.review(signal['id'], 'rejected', 'refuted', 'high', 'analyst', 'Чужая компания')
        row = calculate(self.store)[0]
        self.assertIsNone(row['score'])
        self.assertEqual(row['review_queue'], [])

    def test_content_change_invalidates_factor_evidence(self):
        self.factors()
        self.add(publication(text='Учебная Альфа: продаётся другой доступ к alpha.example.'))
        self.assertIsNone(calculate(self.store)[0]['score'])

    def test_factor_requires_existing_evidence(self):
        with self.assertRaises(ValueError):
            self.store.set_factor('alpha', 'S', {'score': 50, 'reason': 'r', 'reviewer': 'r',
                'observed_at': utcnow(), 'evidence_ids': ['missing'],
                'evidence_hashes': {'missing': 'x'}, 'confidence': 'low'})

    def test_import_validates_whole_file_before_write(self):
        path = self.root / 'bad.jsonl'
        path.write_text(json.dumps(publication().asdict()) + '\n{broken', encoding='utf-8')
        with self.assertRaises(ValueError):
            import_jsonl(self.store, path)
        self.assertEqual(self.store.publications(), [])

    def test_demo_cannot_be_imported_as_real(self):
        path = self.root / 'demo.jsonl'
        path.write_text(json.dumps(publication(is_demo=True).asdict()), encoding='utf-8')
        with self.assertRaises(ValueError):
            import_jsonl(self.store, path, demo=False)

    def test_report_escapes_html_and_tracks_duplicates(self):
        self.add(publication(title='<script>alert(1)</script>'))
        self.add(publication(title='<script>alert(1)</script>', source_id='copy'))
        result = export_report(self.store, self.root / 'report')
        page = (self.root / 'report/report.html').read_text()
        self.assertNotIn('<script>', page)
        data = json.loads((self.root / 'report/report.json').read_text())
        self.assertEqual(len(data['duplicate_clusters']), 1)
        self.assertEqual(result['publications'], 2)

    def test_graph_does_not_invent_incidents_or_reverse_relationship(self):
        self.add()
        qs = statements(self.store)
        self.assertIn('(s)-[:MENTIONS]->(c)', qs[-1]['statement'])
        incident_rows = [row for q in qs if 'MERGE (n:Incident' in q['statement']
                         for row in q.get('parameters', {}).get('rows', [])]
        self.assertEqual(incident_rows, [])
        self.assertFalse(any('AFFECTED_ORGANIZATION' in q['statement'] and
                             q.get('parameters', {}).get('rows') for q in qs))
        self.assertIn('parameters', qs[-1])


    def test_collector_failure_recorded_without_secret(self):
        source = {'id': 'test_feed', 'url': 'https://feed.example/rss', 'allowed_hosts': ['feed.example']}
        with patch('app.collectors.robots_allowed', side_effect=OSError('password=secret')):
            result = collect_source(self.store, source)
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('secret', json.dumps(self.store.source_status()))

    def test_collector_success_and_cooldown(self):
        source = {'id': 'test_feed', 'url': 'https://feed.example/rss', 'allowed_hosts': ['feed.example']}
        data = b'<rss><channel><item><title>x</title><link>https://feed.example/1</link><description>x</description></item></channel></rss>'
        with patch('app.collectors.robots_allowed', return_value=True), patch('app.collectors.fetch', return_value=(data, {})):
            self.assertEqual(collect_source(self.store, source)['status'], 'ok')
            self.assertEqual(collect_source(self.store, source)['status'], 'cooldown')
        self.assertEqual(len(self.store.publications()), 1)


class ParsingTests(unittest.TestCase):
    def test_canonical_tracking_removed(self):
        self.assertEqual(canonical_url('https://NEWS.example/x?utm_source=t&a=1#fragment'), 'https://news.example/x?a=1')

    def test_missing_date_stays_none(self):
        self.assertIsNone(publication(published_at=None).published_at)

    def test_naive_date_rejected(self):
        with self.assertRaises(ValueError):
            publication(published_at='2026-10-23T10:00:00')

    def test_secret_redaction(self):
        text = redact('password=secret Иван user@example.org')
        self.assertNotIn('secret', text)
        self.assertNotIn('user@', text)

    def test_credentials_in_url_rejected(self):
        with self.assertRaises(ValueError):
            canonical_url('https://user:secret@news.example/1')

    def test_wrong_domain_suffix_not_matched(self):
        pub = publication(text='Продаётся доступ к alpha.example.attacker.example')
        self.assertEqual(extract(pub, COMPANIES)['signals'], [])

    def test_true_subdomain_is_candidate(self):
        pub = publication(text='Продаётся доступ к vpn.alpha.example')
        result = extract(pub, COMPANIES)['signals']
        self.assertEqual(result[0]['company_id'], 'alpha')
        self.assertEqual(result[0]['entity_status'], 'needs_review')

    def test_anonymous_access_sale_not_guessed(self):
        pub = publication(text='Продаётся доступ в крупную торговую компанию')
        self.assertEqual(extract(pub, COMPANIES)['signals'], [])

    def test_cve_never_proves_company_exposure(self):
        pub = publication(text='Учебная Альфа изучила уязвимость CVE-2025-12345')
        result = extract(pub, COMPANIES)
        self.assertEqual(result['cves'], ['CVE-2025-12345'])
        self.assertEqual(result['signals'], [])

    def test_denial_remains_unverified_candidate(self):
        pub = publication(text='Учебная Альфа опровергает утечку данных')
        self.assertEqual(extract(pub, COMPANIES)['signals'][0]['verification_status'], 'needs_review')

    def test_ambiguous_aliases_not_silently_merged(self):
        companies = [dict(c, aliases=['ОбщийБренд']) for c in COMPANIES]
        result = extract(publication(text='ОбщийБренд: утечка данных'), companies)['signals']
        self.assertEqual({s['company_id'] for s in result}, {'alpha', 'beta'})
        self.assertTrue(all(s['entity_status'] == 'needs_review' for s in result))

    def test_rss_html_and_missing_dates(self):
        data = b'<rss><channel><item><title>Hello</title><link>https://news.example/1</link><description>&lt;p&gt;Text&lt;/p&gt;</description></item></channel></rss>'
        pubs, errors = parse_feed(data, 'test')
        self.assertEqual(pubs[0].text, 'Text')
        self.assertIsNone(pubs[0].published_at)
        self.assertEqual(errors, [])

    def test_atom_namespace(self):
        data = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>1</id><title>Hello</title><link href="https://news.example/1"/><summary>Text</summary><published>2026-10-22T12:00:00Z</published></entry></feed>'
        pubs, _ = parse_feed(data, 'test')
        self.assertEqual(pubs[0].external_id, '1')
        self.assertEqual(pubs[0].url, 'https://news.example/1')

    def test_malformed_xml_rejected(self):
        with self.assertRaises(Exception):
            parse_feed(b'<rss><broken>', 'test')

    def test_xml_entities_rejected(self):
        with self.assertRaises(ValueError):
            parse_feed(b'<!DOCTYPE rss [<!ENTITY e "x">]><rss/>', 'test')

    def test_utf16_xml_entities_rejected(self):
        with self.assertRaises(ValueError):
            parse_feed('<!DOCTYPE rss [<!ENTITY e "x">]><rss/>'.encode('utf-16'), 'test')

    def test_invalid_item_does_not_drop_valid_item(self):
        data = b'<rss><channel><item><title>No link</title></item><item><title>OK</title><link>https://news.example/2</link></item></channel></rss>'
        pubs, errors = parse_feed(data, 'test')
        self.assertEqual(len(pubs), 1)
        self.assertEqual(errors, ['invalid_item'])

    def test_feed_redirect_host_guard(self):
        with self.assertRaises(ValueError):
            validate_feed_url('https://127.0.0.1/feed', ['news.example'])

    def test_csv_formula_guard(self):
        self.assertEqual(csv_safe('=1+1'), "'=1+1")




if __name__ == '__main__':
    unittest.main()
