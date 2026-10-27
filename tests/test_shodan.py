"""Shodan imports are context, never proof of a company's vulnerability."""
from copy import deepcopy
from datetime import datetime, timedelta
from io import BytesIO
import gzip
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from app import shodan
from app.collectors import ingest
from app.enrichment import reindex
from app.graph_scoring import calculate_graph
from app.graph_audit import prepare
from app.graph_view import payload as graph_payload
from app.models import Publication, utcnow
from app.storage import CTIStore


NOW = '2026-10-27T12:00:00+00:00'
KEY = 'testShodanKey12345678901234567890'


def sample(address='198.51.100.10'):
    return {'ip_str': address, 'org': 'Client', 'data': [{
        'port': 443, 'transport': 'tcp', 'timestamp': '2026-10-24T10:00:00Z',
        'product': 'GitLab', 'version': '19.5.0', 'hostnames': ['git.client.example'],
        'http': {'host': 'git.client.example'},
        'vulns': {'CVE-2099-20001': {'verified': False}}}]}


class Response(BytesIO):
    pass


class Client:
    def __init__(self, payload=None, error=None):
        self.payload = payload if payload is not None else sample('8.8.8.8')
        self.error = error
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        if self.error:
            raise self.error
        return Response(json.dumps(self.payload).encode())


class ShodanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root / 'test.sqlite3')
        self.store.load_companies([{'id': 'client', 'name': 'Client', 'domains': ['client.example'],
                                   'sector': 'test', 'monitor_target': True},
                                  {'id': 'demo-client', 'name': 'Example', 'domains': ['demo-alpha.example'],
                                   'is_demo': True}])
        self.store.load_products([{'id': 'gitlab', 'name': 'GitLab', 'aliases': []}])

    def imported(self, payload=None):
        return shodan.import_export(self.store, payload if payload is not None else sample(), imported_at=NOW)

    def row(self):
        return shodan.observations(self.store, now=NOW, include_demo=True)[0]

    def review(self, identifier, status='confirmed', company='client'):
        with patch('app.shodan.utcnow', return_value=NOW):
            return shodan.review_association(self.store, identifier, company, status, 'Project reviewer',
                                              'Compared the hostname with the organization reference',
                                              'https://client.example/about')

    def scores(self):
        result = calculate_graph(self.store, as_of=NOW, include_historical=True)
        return [(c['company_id'], c['interest'], c['technical'], c['historical_technical']) for c in result['companies']]

    def test_host_search_and_single_banner_formats(self):
        host = sample()
        rows = shodan.normalize_export(host)
        banner = dict(host['data'][0], ip_str=host['ip_str'], org=host['org'])
        self.assertEqual(rows, shodan.normalize_export({'matches': [banner]}))
        self.assertEqual(rows, shodan.normalize_export([banner]))
        self.assertEqual(rows, shodan.normalize_export(banner))

    def test_repeat_import_preserves_first_collection_and_review(self):
        identifier = self.imported()['ids'][0]
        self.review(identifier)
        again = shodan.import_export(self.store, sample(), imported_at='2026-10-28T12:00:00+00:00')
        self.assertEqual(again['counts'], {'unchanged': 1})
        self.assertEqual(self.row()['imported_at'], NOW)
        self.assertEqual(self.row()['association_review']['status'], 'confirmed')
        self.assertEqual(len(self.store.publications()), 1)

    def test_new_observation_snapshot_does_not_overwrite_old_review(self):
        identifier = self.imported()['ids'][0]
        self.review(identifier)
        newer = sample();newer['data'][0]['timestamp'] = '2026-10-25T10:00:00Z'
        self.imported(newer)
        rows = shodan.observations(self.store, now=NOW)
        self.assertEqual(len(rows), 2)
        self.assertIsNone(rows[0]['association_review'])
        self.assertEqual(rows[1]['association_review']['status'], 'confirmed')

    def test_missing_timestamp_is_unknown_not_import_time(self):
        value = sample();value['data'][0].pop('timestamp')
        self.imported(value)
        self.assertIsNone(self.row()['observed_at'])
        self.assertEqual(self.row()['freshness'], 'unknown')

    def test_naive_timestamp_is_explicit_utc_assumption(self):
        value = sample();value['data'][0]['timestamp'] = '2026-10-24T10:00:00'
        self.imported(value)
        self.assertTrue(self.row()['timestamp_utc_assumed'])
        self.assertEqual(self.row()['observed_at'], '2026-10-24T10:00:00+00:00')

    def test_stale_and_future_observations_are_visible_as_such(self):
        self.imported()
        self.assertEqual(shodan.observations(self.store, now='2026-12-27T12:00:00+00:00')[0]['freshness'], 'stale')
        self.assertEqual(shodan.observations(self.store, now='2026-01-01T00:00:00+00:00')[0]['freshness'], 'future')

    def test_hostname_is_only_a_candidate_and_org_does_not_prove_owner(self):
        self.imported()
        self.assertEqual([c['id'] for c in self.row()['company_candidates']], ['client'])
        self.assertIsNone(self.row()['association_review'])
        value = sample();value['data'][0]['hostnames'] = ['client.example.attacker.example'];value['data'][0]['http'] = {}
        self.imported(value)
        rows = shodan.observations(self.store, now=NOW)
        self.assertTrue(any(not r['company_candidates'] and r['reported_org'] == 'Client' for r in rows))

    def test_no_signals_assertions_or_score_change_even_after_review_and_reindex(self):
        before = self.scores()
        identifier = self.imported()['ids'][0]
        self.review(identifier)
        reindex(self.store)
        self.assertEqual(self.scores(), before)
        self.assertEqual(self.store.signals(), [])
        self.assertEqual(self.store.assertions(), [])
        self.assertFalse(self.row()['vulnerabilities'][0]['verified_by_shodan'])

    def test_verified_by_provider_is_not_company_vulnerability_confirmation(self):
        value = sample();value['data'][0]['vulns']['CVE-2099-20001']['verified'] = True
        before = self.scores();self.imported(value)
        self.assertTrue(self.row()['vulnerabilities'][0]['verified_by_shodan'])
        self.assertEqual(self.scores(), before)

    def test_existing_nonzero_indices_and_unknown_installed_version_stay_unchanged(self):
        pubs=[Publication('fixture','https://source.example/use','Client uses GitLab',
                          'Client uses GitLab.',published_at='2026-10-24T10:00:00Z',collected_at=NOW),
              Publication('fixture','https://source.example/cve','GitLab CVE-2099-20001',
                          'Уязвимость CVE-2099-20001 затрагивает GitLab.',published_at='2026-10-24T10:00:00Z',collected_at=NOW),
              Publication('fixture','https://source.example/event','Client: утечка данных',
                          'Client сообщила об утечке данных.',published_at='2026-10-24T10:00:00Z',collected_at=NOW)]
        ingest(self.store,pubs)
        with patch('app.storage.utcnow',return_value=NOW):
            for a in self.store.assertions():self.store.review_assertion(a['id'],'confirmed','Reviewer','Checked excerpt',confidence='high',basis='research_report')
            for s in self.store.signals():self.store.review(s['id'],'confirmed','unresolved','high','Reviewer','Statement checked')
        before=self.scores();self.assertGreater(before[0][1]['score'],0);self.assertGreater(before[0][2]['score'],0)
        identifier=self.imported()['ids'][0];self.review(identifier);reindex(self.store)
        self.assertEqual(self.scores(),before)
        self.assertNotIn('version',next(a for a in self.store.assertions() if a['kind']=='uses_product')['attributes'])

    def test_reviews_change_context_graph_only_and_can_be_revoked(self):
        identifier = self.imported()['ids'][0]
        self.assertFalse(any(r['relation'] == 'HAS_TECHNICAL_OBSERVATION' for r in prepare(self.store, NOW)['views'].values()))
        self.review(identifier)
        graph = graph_payload(self.store, NOW)
        links = [e for e in graph['edges'] if e['type'] == 'HAS_TECHNICAL_OBSERVATION']
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]['source'], 'client')
        self.assertEqual(links[0]['target'], identifier)
        self.assertEqual(links[0]['properties']['weight_role'], 'context_only')
        self.assertIsNone(links[0]['properties']['weight'])
        self.review(identifier, 'refuted')
        self.assertFalse(any(e['type'] == 'HAS_TECHNICAL_OBSERVATION' for e in graph_payload(self.store, NOW)['edges']))

    def test_import_does_not_accept_preconfirmed_association(self):
        value = sample();value['association_review'] = {'status': 'confirmed', 'company_id': 'client'}
        value['data'][0]['metadata'] = {'association_review': value['association_review']}
        self.imported(value)
        self.assertIsNone(self.row()['association_review'])

    def test_demo_cannot_be_attached_to_real_company(self):
        identifier = self.imported(json.loads(shodan.EXAMPLE.read_text()))['ids'][0]
        self.assertTrue(self.row()['is_demo'])
        self.assertEqual(self.store.publications(), [])
        with self.assertRaises(ValueError):self.review(identifier)

    def test_invalid_later_record_does_not_partially_import(self):
        value = sample();value['data'].append({'port': True})
        with self.assertRaises(ValueError):self.imported(value)
        self.assertFalse(self.store.publications())

    def test_database_failure_rolls_back_whole_batch(self):
        value = sample();value['data'].append(dict(value['data'][0], port=8443))
        original = self.store.save_publication
        def fail_second(pub, extraction, connection=None):
            result = original(pub, extraction, connection)
            if ':8443' in pub.title:raise sqlite3.DatabaseError('fixture')
            return result
        with patch.object(self.store, 'save_publication', side_effect=fail_second):
            with self.assertRaises(sqlite3.DatabaseError):self.imported(value)
        self.assertEqual(self.store.publications(), [])

    def test_raw_banners_cookies_credentials_and_unknown_fields_not_retained(self):
        value = sample();value['api_key'] = 'unwanted-key';value['data'][0]['data'] = 'Set-Cookie: session=secret'
        value['data'][0]['http']['html'] = 'unwanted-header'
        self.imported(value)
        stored = self.store.publications()[0]['data']
        for term in ('unwanted-key','Set-Cookie','session=secret','unwanted-header'):self.assertNotIn(term, stored)

    def test_reports_escape_untrusted_text_and_keep_unknowns(self):
        value = sample();value['data'][0]['product'] = '<img src=x onerror=alert(1)>'
        self.imported(value);shodan.export_report(self.store, self.root/'report')
        page = (self.root/'report/shodan.html').read_text()
        self.assertNotIn('<img', page);self.assertIn('&lt;img', page)

    def test_jsonl_gzip_and_limits(self):
        banner = dict(sample()['data'][0], ip_str='198.51.100.10')
        text = json.dumps(banner)+'\n'+json.dumps(dict(banner,port=8443))+'\n'
        path = self.root/'export.json.gz';path.write_bytes(gzip.compress(text.encode()))
        self.assertEqual(len(shodan.normalize_export(shodan.read_export(path))), 2)
        path.write_bytes(gzip.compress(b'x'*(shodan.MAX_BYTES+1)))
        with self.assertRaises(ValueError):shodan.read_export(path)
        for raw in (b'{"port":NaN}', b'not json'):
            with self.assertRaises(ValueError):shodan.decode_export(raw)

    def test_invalid_fields_are_rejected(self):
        for field,value in [('port',True),('port',65536),('transport','http'),('timestamp','yesterday'),('product',{}),('hostnames','client.example')]:
            payload = sample();payload['data'][0][field] = value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):self.imported(payload)
        for flag in (0,1,'false',[]):
            payload=sample();payload['data'][0]['vulns']['CVE-2099-20001']['verified']=flag
            with self.subTest(flag=flag),self.assertRaises(ValueError):self.imported(payload)

    def test_review_requires_public_evidence_and_company(self):
        identifier=self.imported()['ids'][0]
        for url in ('javascript:alert(1)','https://user:password@client.example','https://client.example/?key=secret'):
            with self.subTest(url=url),self.assertRaises(ValueError):
                shodan.review_association(self.store,identifier,'client','confirmed','reviewer','note',url)

    def test_api_is_explicit_get_to_existing_host_only(self):
        client=Client();before=self.scores()
        result=shodan.fetch_host(self.store,'8.8.8.8',api_key=KEY,opener=client,now=NOW)
        self.assertEqual(result['status'],'ok')
        self.assertEqual(len(client.requests),1)
        request=client.requests[0];self.assertEqual(request.get_method(),'GET')
        self.assertTrue(request.full_url.startswith('https://api.shodan.io/shodan/host/8.8.8.8?'))
        self.assertEqual(self.scores(),before)
        self.assertNotIn(KEY,json.dumps(self.store.source_status())+json.dumps(self.row()))

    def test_api_cooldown_persists_across_clients(self):
        client=Client();shodan.fetch_host(self.store,'8.8.8.8',api_key=KEY,opener=client,now=NOW)
        other=Client();reopened=CTIStore(self.store.path)
        self.assertEqual(shodan.fetch_host(reopened,'8.8.8.8',api_key=KEY,opener=other,now=NOW)['status'],'cooldown')
        self.assertEqual(other.requests,[])
        self.assertEqual(shodan.fetch_host(reopened,'1.1.1.1',api_key=KEY,opener=other,now=NOW)['status'],'cooldown')

    def test_no_key_or_nonpublic_ip_does_not_request_network(self):
        for address in ('127.0.0.1','192.168.1.1','198.51.100.10','8.8.8.8/24','https://8.8.8.8'):
            client=Client()
            with self.subTest(address=address),self.assertRaises(ValueError):shodan.fetch_host(self.store,address,api_key=KEY,opener=client)
            self.assertEqual(client.requests,[])
        with self.assertRaises(ValueError):shodan.fetch_host(self.store,'8.8.8.8',api_key='')

    def test_rate_limit_respects_retry_after_without_leaking_key(self):
        error=HTTPError('https://api.shodan.io/?key='+KEY,429,'fixture',{'Retry-After':'7200'},BytesIO())
        result=shodan.fetch_host(self.store,'8.8.8.8',api_key=KEY,opener=Client(error=error),now=NOW)
        self.assertEqual(result['error_code'],'rate_limited')
        self.assertEqual(result['next_allowed_at'],'2026-10-27T14:00:00+00:00')
        self.assertNotIn(KEY,json.dumps(result)+json.dumps(self.store.source_status()))
        result=shodan.fetch_host(self.store,'1.1.1.1',api_key=KEY,opener=Client(),now='2026-10-27T13:00:00+00:00')
        self.assertEqual(result['status'],'cooldown')

    def test_api_errors_do_not_import_and_do_not_leak_request_url(self):
        for status in (301,401,403,404,500):
            store=CTIStore(self.root/(str(status)+'.sqlite3'))
            error=HTTPError('https://api.shodan.io/?key='+KEY,status,'secret '+KEY,{},BytesIO())
            result=shodan.fetch_host(store,'8.8.8.8',api_key=KEY,opener=Client(error=error),now=NOW)
            self.assertEqual(result['status'],'error');self.assertNotIn(KEY,json.dumps(result));self.assertEqual(store.publications(),[])
        result=shodan.fetch_host(self.store,'8.8.8.8',api_key=KEY,opener=Client(error=URLError(KEY)),now=NOW)
        self.assertEqual(result['error_code'],'network_error');self.assertNotIn(KEY,json.dumps(result))

    def test_mismatched_api_host_is_not_imported(self):
        result=shodan.fetch_host(self.store,'8.8.8.8',api_key=KEY,opener=Client(sample('1.1.1.1')),now=NOW)
        self.assertEqual(result['error_code'],'invalid_response');self.assertEqual(self.store.publications(),[])

    def test_api_key_echo_is_removed_from_stored_response(self):
        value=sample('8.8.8.8');value['data'][0]['product']=KEY
        self.assertEqual(shodan.fetch_host(self.store,'8.8.8.8',api_key=KEY,opener=Client(value),now=NOW)['status'],'ok')
        self.assertNotIn(KEY,json.dumps(self.store.publications()))


if __name__ == '__main__':
    unittest.main()
