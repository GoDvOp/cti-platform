import json
import socket
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from app.collectors import (RobotsPolicy, checked_fetch, collect_source, error_details,
                            parse_source, source_status, validate_sources, ingest)
from app.russian_sources import parse_listing, parse_nckci_json, json_links
from app.models import Publication
from app.storage import CTIStore
from app.graph import statements, sync_graph
from app.reporting import export_report

FIXTURES = Path(__file__).parent / 'fixtures'
SECURE = {'id': 'secure_test', 'kind': 'securelist_listing', 'url': 'https://securelist.ru/',
          'allowed_hosts': ['securelist.ru'], 'polling_minutes': 360}
NCKCI = {'id': 'nckci_test', 'kind': 'nckci_listing', 'url': 'https://www.cert.gov.ru/materialy/uyazvimosti/',
         'allowed_hosts': ['www.cert.gov.ru', 'cert.gov.ru'], 'polling_minutes': 360, 'max_json_documents': 1}


class RussianParserTests(unittest.TestCase):
    def test_securelist_titles_summary_and_date_precision(self):
        pubs, warnings = parse_listing((FIXTURES / 'securelist_listing_demo.html').read_bytes(), SECURE,
                                        is_demo=True)
        self.assertEqual(len(pubs), 2)
        self.assertEqual(warnings, [])
        self.assertIn('Вымышленная', pubs[0].text)
        self.assertIsNone(pubs[0].published_at)
        self.assertEqual(pubs[0].metadata['publication_day'], '2026-10-23')
        self.assertEqual(pubs[1].published_at, '2026-10-22T09:00:00+00:00')
        self.assertTrue(all(p.is_demo for p in pubs))

    def test_listing_rejects_login_or_changed_markup(self):
        with self.assertRaises(ValueError):
            parse_listing(b'<html><h1>Please log in</h1></html>', SECURE)

    def test_external_lookalike_domain_not_followed(self):
        html = '<h3><a href="https://securelist.ru.attacker.example/test/999999/">Unknown research link</a></h3>'
        with self.assertRaises(ValueError):
            parse_listing(html.encode(), SECURE)

    def test_duplicate_listing_cards_not_duplicate_publications(self):
        html = '<h3><a href="/test/999999/">Учебное исследование</a></h3>'
        pubs, _ = parse_listing((html * 2).encode(), SECURE)
        self.assertEqual(len(pubs), 1)

    def test_russian_date_remains_day_not_invented_time(self):
        html = '<article><h3><a href="/test/999999/">Учебное исследование</a></h3><p>21 Окт 2026</p></article>'
        pub = parse_listing(html.encode(), SECURE)[0][0]
        self.assertEqual(pub.metadata['publication_day'], '2026-10-21')
        self.assertIsNone(pub.published_at)

    def test_nckci_metadata_json_and_pdf_not_downloaded_by_parser(self):
        pubs, _ = parse_listing((FIXTURES / 'nckci_listing_demo.html').read_bytes(), NCKCI, is_demo=True)
        self.assertEqual(len(pubs), 2)
        self.assertEqual(pubs[0].metadata['attachment_format'], 'json')
        self.assertEqual(pubs[1].metadata['attachment_format'], 'pdf')
        self.assertEqual(pubs[0].metadata['advisory_id'], 'VULN.2099-01-01.1')
        self.assertEqual(pubs[0].metadata['publication_day'], '2099-01-01')

    def test_json_identifiers_extracted_without_exposure_claim(self):
        pubs, _ = parse_nckci_json((FIXTURES / 'nckci_json_demo.json').read_bytes(), NCKCI,
                                   'https://www.cert.gov.ru/upload/demo.json', is_demo=True)
        self.assertEqual(pubs[0].metadata['cves'], ['CVE-2099-10001', 'CVE-2099-10002'])
        self.assertIsNone(pubs[0].published_at)
        self.assertNotIn('cvss', pubs[0].metadata)

    def test_unknown_json_not_reported_as_success(self):
        with self.assertRaises(ValueError):
            parse_nckci_json(b'{"status":"login required"}', NCKCI, NCKCI['url'])

    def test_only_explicit_same_host_json_link_selected(self):
        data = b'<a href="/upload/demo.json">JSON</a><a href="https://external.example/file.json">JSON</a><a href="/upload/demo.pdf">PDF</a>'
        self.assertEqual(json_links(data, NCKCI, NCKCI['url']), ['https://www.cert.gov.ru/upload/demo.json'])

    def test_html_input_is_bounded(self):
        with self.assertRaises(ValueError):
            parse_listing(b'x' * 2_000_001, SECURE)

    def test_html_depth_is_bounded(self):
        with self.assertRaises(ValueError):
            parse_listing(('<div>' * 140).encode(), SECURE)


class RobotsAndDiagnosticsTests(unittest.TestCase):
    def test_wildcard_feed_disallow_respected(self):
        policy = RobotsPolicy('User-agent: *\nDisallow: */feed\nDisallow: */rss\n')
        self.assertTrue(policy.allowed('https://securelist.ru/'))
        self.assertFalse(policy.allowed('https://securelist.ru/feed/'))

    def test_user_agent_not_impersonated(self):
        policy = RobotsPolicy('User-agent: *\nDisallow: /\n\nUser-agent: ExampleCrawler\nAllow: /\n')
        self.assertFalse(policy.allowed('https://securelist.ru/'))

    def test_longest_allow_wins(self):
        policy = RobotsPolicy('User-agent: *\nDisallow: /docs/\nAllow: /docs/public/\n')
        self.assertTrue(policy.allowed('https://site.example/docs/public/a'))
        self.assertFalse(policy.allowed('https://site.example/docs/private/'))

    def test_specific_agent_rules_override_wildcard(self):
        policy = RobotsPolicy('User-agent: *\nDisallow: /\nUser-agent: CTI-Intern-Research\nAllow: /\n')
        self.assertTrue(policy.allowed('https://site.example/'))

    def test_dns_error_has_safe_code_without_upstream_secret(self):
        data = error_details(URLError(socket.gaierror('password=secret')), 'download')
        self.assertEqual(data['error_code'], 'dns_error')
        self.assertNotIn('secret', json.dumps(data))

    def test_http_retry_after_respected(self):
        exc = HTTPError('https://site.example/', 429, 'secret', {'Retry-After': '7200'}, None)
        data = error_details(exc, 'download')
        self.assertEqual(data['retry_after_seconds'], 7200)
        self.assertEqual(data['http_status'], 429)

    def test_invalid_source_kind_rejected(self):
        with self.assertRaises(ValueError):
            validate_sources([dict(SECURE, kind='crawl_all_sites')])


class SourcePipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root / 'db.sqlite3')

    def tearDown(self):
        self.tmp.cleanup()

    def test_cooldown_exposes_previous_failure_and_next_time(self):
        with patch('app.collectors.checked_fetch', side_effect=URLError(socket.gaierror('secret'))):
            failed = collect_source(self.store, SECURE)
            cooldown = collect_source(self.store, SECURE)
        self.assertEqual(failed['error_code'], 'dns_error')
        self.assertEqual(cooldown['previous_status'], 'error')
        self.assertEqual(cooldown['previous_error_code'], 'dns_error')
        self.assertGreater(cooldown['wait_seconds'], 0)
        self.assertEqual(failed['next_allowed_at'], cooldown['next_allowed_at'])

    def test_status_shows_never_checked_sources(self):
        row = source_status(self.store, [SECURE])[0]
        self.assertEqual(row['status'], 'never_checked')
        self.assertEqual(row['wait_seconds'], 0)

    def test_securelist_collection_and_reimport(self):
        payload = (FIXTURES / 'securelist_listing_demo.html').read_bytes()
        with patch('app.collectors.checked_fetch', return_value=(payload, {})):
            result = collect_source(self.store, SECURE)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['items'], 2)
        self.assertEqual(len(self.store.publications()), 2)

    def test_nckci_bounded_json_download_no_pdf(self):
        listing = (FIXTURES / 'nckci_listing_demo.html').read_bytes()
        json_data = (FIXTURES / 'nckci_json_demo.json').read_bytes()
        response = [(listing, {}), (b'<a href="/upload/test.json">JSON</a>', {}), (json_data, {})]
        with patch('app.collectors.checked_fetch', side_effect=response) as network:
            result = collect_source(self.store, NCKCI)
        self.assertEqual(network.call_count, 3)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['items'], 3)
        self.assertTrue(all(not args.args[1].endswith('.pdf') for args in network.call_args_list))

    def test_attachment_failure_preserves_listing_as_partial(self):
        listing = (FIXTURES / 'nckci_listing_demo.html').read_bytes()
        with patch('app.collectors.checked_fetch', side_effect=[(listing, {}), URLError('secret')]):
            result = collect_source(self.store, NCKCI)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['items'], 2)
        self.assertNotIn('secret', json.dumps(result))

    def test_no_json_link_is_explicit_partial_not_empty_success(self):
        listing = (FIXTURES / 'nckci_listing_demo.html').read_bytes()
        with patch('app.collectors.checked_fetch', side_effect=[(listing, {}), (b'<a href="/file.pdf">PDF</a>', {})]):
            result = collect_source(self.store, NCKCI)
        self.assertEqual(result['warnings'][0]['error_code'], 'json_link_not_found')
        self.assertEqual(result['status'], 'partial')

    def test_actual_robots_denial_never_downloads_source(self):
        source = dict(SECURE, url='https://securelist.ru/feed/')
        with patch('app.collectors.fetch', return_value=(b'User-agent: *\nDisallow: */feed', {})) as network:
            result = collect_source(self.store, source)
        self.assertEqual(result['error_code'], 'robots_denied')
        self.assertEqual(network.call_count, 1)

    def test_missing_robots_file_is_not_network_failure(self):
        responses = [HTTPError(SECURE['url'] + 'robots.txt', 404, 'not found', {}, None), (b'data', {})]
        with patch('app.collectors.fetch', side_effect=responses), patch('app.collectors.time.sleep'):
            data, _ = checked_fetch(dict(SECURE), SECURE['url'])
        self.assertEqual(data, b'data')

    def test_robots_429_preserves_retry_after(self):
        exc = HTTPError(SECURE['url'] + 'robots.txt', 429, 'limit', {'Retry-After': '7200'}, None)
        with patch('app.collectors.fetch', side_effect=exc):
            result = collect_source(self.store, SECURE)
        self.assertEqual(result['retry_after_seconds'], 7200)
        self.assertEqual(result['stage'], 'robots')

    def test_cve_and_source_graph_exists_without_company(self):
        pub = Publication('test', 'https://source.example/advisory', 'Уязвимость CVE-2099-10001',
                          'Техническое уведомление, компания не указана.')
        ingest(self.store, [pub])
        queries = statements(self.store)
        self.assertTrue(any('PUBLISHED_BY' in q['statement'] and q.get('parameters', {}).get('rows') for q in queries))
        cve_query = next(q for q in queries if 'MERGE (v:Vulnerability' in q['statement'])
        self.assertEqual(cve_query['parameters']['rows'][0]['cve'], 'CVE-2099-10001')
        self.assertFalse(any('USES_PRODUCT' in q['statement'] or 'AFFECTED' in q['statement'] for q in queries))

    def test_report_lists_technical_publications_without_signals(self):
        pub = Publication('test', 'https://source.example/advisory', 'Уязвимость CVE-2099-10001', 'Описание CVE-2099-10001')
        ingest(self.store, [pub])
        export_report(self.store, self.root / 'out')
        page = (self.root / 'out/report.html').read_text()
        self.assertIn('CVE-2099-10001', page)
        self.assertIn('Все публикации', page)

    def test_graph_schema_and_data_are_separate_transactions(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"errors":[]}'
        with patch.dict('os.environ', {'NEO4J_PASSWORD': 'test-password'}), patch('app.graph.urlopen', return_value=response) as network:
            sync_graph(self.store)
        self.assertEqual(network.call_count, 3)
        schema = json.loads(network.call_args_list[0].args[0].data)['statements']
        data = json.loads(network.call_args_list[1].args[0].data)['statements']
        self.assertTrue(all(q['statement'].startswith('CREATE CONSTRAINT') for q in schema))
        self.assertTrue(all(not q['statement'].startswith('CREATE CONSTRAINT') for q in data))


if __name__ == '__main__':
    unittest.main()
