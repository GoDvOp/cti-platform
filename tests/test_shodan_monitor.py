"""Domain discovery, persistent budgets, attribution review and worker integration."""
from datetime import datetime, timedelta
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, parse_qs

from app import shodan
from app.automation import AutoUpdater
from app.main import parser, run
from app.shodan_monitor import configure_target, fetch_domain, monitor_status, poll
from app.storage import CTIStore
from app.workbench import Workbench, make_server
from tests.test_shodan import Client, KEY, NOW, sample


def later(seconds):
    return (datetime.fromisoformat(NOW) + timedelta(seconds=seconds)).isoformat()


def search_payload(hostname='git.client.example', ip='8.8.8.8'):
    host = sample(ip)
    banner = dict(host['data'][0], ip_str=ip, hostnames=[hostname], http={})
    return {'matches': [banner], 'total': 1}


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root / 'data/test.sqlite3')
        self.store.load_companies([{'id': 'client', 'name': 'Client', 'domains': ['client.example', 'other.example']},
                                   {'id': 'demo', 'name': 'Demo', 'domains': ['demo.example'], 'is_demo': True}])
        self.target = configure_target(self.store, 'client', 'client.example')['id']

    def fetch(self, payload=None, **kwargs):
        client = Client(payload if payload is not None else search_payload())
        result = fetch_domain(self.store, self.target, api_key=KEY, opener=client, now=kwargs.get('now', NOW))
        return result, client

    def test_search_only_queries_shodan_and_persists_unconfirmed_candidates(self):
        result, client = self.fetch()
        request = client.requests[0]
        self.assertEqual(request.get_method(), 'GET')
        url = urlsplit(request.full_url)
        self.assertEqual((url.hostname, url.path), ('api.shodan.io', '/shodan/host/search'))
        self.assertEqual(parse_qs(url.query)['query'], ['hostname:"client.example"'])
        self.assertEqual(parse_qs(url.query)['page'], ['1'])
        rows = shodan.observations(self.store, now=NOW)
        self.assertEqual(result['observations'], 1)
        self.assertIsNone(rows[0]['association_review'])
        self.assertEqual(rows[0]['company_candidates'][0]['id'], 'client')
        self.assertEqual(self.store.signals(), [])
        self.assertEqual(self.store.assertions(), [])
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM shodan_discoveries').fetchone()[0], 1)
        self.assertNotIn(KEY, json.dumps(self.store.source_status()) + json.dumps(rows))

    def test_query_validation_rejects_injection_unlisted_domains_demo_and_invalid_types(self):
        for company, domain, enabled in [('client','client.example org:other',True),('client','https://client.example',True),
                                         ('client','unlisted.example',True),('demo','demo.example',True),
                                         ('unknown','client.example',True),('client','client.example',1),
                                         ('client',[],True)]:
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                configure_target(self.store, company, domain, enabled)
        self.assertEqual(len(monitor_status(self.store, NOW)['targets']), 1)

    def test_idempotent_disable_and_resume_persist(self):
        self.assertEqual(configure_target(self.store,'client','CLIENT.EXAMPLE.')['id'],self.target)
        configure_target(self.store,'client','client.example',False)
        reopened=CTIStore(self.store.path)
        self.assertFalse(monitor_status(reopened,NOW)['targets'][0]['enabled'])
        client=Client(search_payload())
        self.assertEqual(poll(reopened,api_key=KEY,opener=client,now=NOW)['status'],'no_targets')
        self.assertEqual(client.requests,[])
        configure_target(reopened,'client','client.example',True)
        self.assertEqual(poll(reopened,api_key=KEY,opener=client,now=NOW)['status'],'ok')

    def test_empty_results_are_successful_and_wait_a_day(self):
        result,_=self.fetch({'matches':[],'total':0})
        self.assertEqual(result['status'],'ok');self.assertEqual(result['observations'],0)
        client=Client(search_payload())
        self.assertEqual(poll(CTIStore(self.store.path),api_key=KEY,opener=client,now=later(3600))['status'],'waiting')
        self.assertEqual(client.requests,[])
        self.assertEqual(poll(self.store,api_key=KEY,opener=client,now=later(86400))['status'],'ok')

    def test_hostname_substring_shared_org_and_nonpublic_addresses_are_discarded(self):
        for n,(hostname,ip) in enumerate([('client.example.attacker.example','8.8.8.8'),('otherclient.example','8.8.8.8'),
                            ('git.client.example','127.0.0.1')]):
            with self.subTest(hostname=hostname,ip=ip):
                result,_=self.fetch(search_payload(hostname,ip),now=later(86400 * n))
                self.assertEqual(result['observations'],0);self.assertEqual(result['discarded'],1)
        self.assertEqual(self.store.publications(),[])

    def test_large_search_is_explicitly_partial_and_does_not_fetch_more_pages(self):
        payload=search_payload();payload['total']=501
        result,client=self.fetch(payload)
        self.assertTrue(result['partial']);self.assertEqual(result['returned'],1)
        self.assertEqual(len(client.requests),1)

    def test_malformed_response_does_not_partially_import(self):
        payload=search_payload();payload['matches'].append({'ip_str':'8.8.4.4','port':True});payload['total']=2
        result,_=self.fetch(payload)
        self.assertEqual(result['error_code'],'invalid_response')
        self.assertEqual(self.store.publications(),[])

    def test_missing_or_invalid_key_never_requests_network(self):
        client=Client()
        for key,status in [('', 'not_configured'),('bad value','invalid_key')]:
            self.assertEqual(poll(self.store,api_key=key,opener=client,now=NOW)['status'],status)
        self.assertEqual(client.requests,[])

    def test_limits_are_atomic_and_shared_between_search_and_host(self):
        self.fetch()
        other=configure_target(self.store,'client','other.example')['id']
        client=Client()
        self.assertEqual(fetch_domain(CTIStore(self.store.path),other,api_key=KEY,opener=client,now=NOW)['status'],'cooldown')
        self.assertEqual(shodan.fetch_host(self.store,'1.1.1.1',api_key=KEY,opener=client,now=NOW)['status'],'cooldown')
        self.assertEqual(client.requests,[])

    def test_rolling_search_budget_persists_and_recovers(self):
        for n in range(10):
            self.store.source_run('shodan_search_fake'+str(n),'requested',{},NOW)
        client=Client(search_payload())
        result=fetch_domain(CTIStore(self.store.path),self.target,api_key=KEY,opener=client,now=later(60))
        self.assertEqual(result['status'],'budget_exhausted');self.assertEqual(client.requests,[])
        self.assertEqual(monitor_status(self.store,later(60))['search_requests_24h'],10)
        self.assertEqual(poll(self.store,api_key=KEY,opener=client,now=later(86400))['status'],'ok')

    def test_failures_backoff_globally_and_never_leak_key(self):
        error=HTTPError('https://api.shodan.io/?key='+KEY,429,KEY,{'Retry-After':'7200'},BytesIO())
        result=poll(self.store,api_key=KEY,opener=Client(error=error),now=NOW)
        self.assertEqual(result['error_code'],'rate_limited')
        self.assertEqual(result['next_allowed_at'],later(7200))
        client=Client(search_payload())
        self.assertEqual(poll(self.store,api_key=KEY,opener=client,now=later(3600))['status'],'cooldown')
        self.assertEqual(client.requests,[])
        self.assertNotIn(KEY,json.dumps(result)+json.dumps(monitor_status(self.store,NOW)))

    def test_auth_failure_pauses_other_targets_and_network_error_does_not_block_them(self):
        configure_target(self.store,'client','other.example')
        error=HTTPError('https://api.shodan.io/?key='+KEY,403,KEY,{},BytesIO())
        result=poll(self.store,api_key=KEY,opener=Client(error=error),now=NOW)
        self.assertEqual(result['error_code'],'forbidden')
        client=Client(search_payload())
        self.assertEqual(poll(self.store,api_key=KEY,opener=client,now=later(60))['status'],'cooldown')
        self.assertEqual(client.requests,[])

    def test_unconfirmed_ip_is_not_polled_but_confirmed_ip_is_refreshed(self):
        result,_=self.fetch()
        client=Client(sample('8.8.8.8'))
        self.assertEqual(poll(self.store,api_key=KEY,opener=client,now=later(60))['status'],'waiting')
        identifier=result['ids'][0]
        with patch('app.shodan.utcnow',return_value=NOW):
            shodan.review_association(self.store,identifier,'client','confirmed','Reviewer','Public reference','https://client.example')
        refreshed=poll(self.store,api_key=KEY,opener=client,now=later(60))
        self.assertEqual(refreshed['kind'],'host');self.assertEqual(refreshed['status'],'ok')
        self.assertEqual(len(client.requests),1)
        self.assertEqual(poll(self.store,api_key=KEY,opener=client,now=later(3600))['status'],'waiting')
        with patch('app.shodan.utcnow',return_value=later(120)):
            shodan.review_association(self.store,identifier,'client','refuted','Reviewer','Revoked','https://client.example')
        search=Client(search_payload())
        self.assertEqual(poll(self.store,api_key=KEY,opener=search,now=later(86460))['kind'],'domain')
        self.assertEqual(poll(self.store,api_key=KEY,opener=client,now=later(86520))['status'],'waiting')
        self.assertEqual(len(client.requests),1)

    def test_catalog_removal_stops_domain_and_host_jobs(self):
        self.store.load_companies([{'id':'client','name':'Client','domains':['new.example']}])
        self.assertFalse(monitor_status(self.store,NOW)['targets'][0]['catalog_valid'])
        configure_target(self.store,'client','client.example',False)
        self.assertFalse(monitor_status(self.store,NOW)['targets'][0]['enabled'])
        client=Client()
        self.assertEqual(poll(self.store,api_key=KEY,opener=client,now=NOW)['status'],'no_targets')
        self.assertEqual(client.requests,[])

    def test_cli_and_workbench_configure_without_using_key(self):
        result=run(parser().parse_args(['--db',str(self.store.path),'shodan-watch','--company','client','--domain','other.example']))
        self.assertTrue(result['enabled'])
        app=Workbench(self.root,self.store.path)
        self.addCleanup(app.close)
        data=app.shodan()
        self.assertEqual(len(data['monitor']['targets']),2)
        self.assertNotIn('api_key',json.dumps(data))
        app.configure_shodan({'company_id':'client','domain':'client.example','enabled':False})
        self.assertFalse(next(t for t in app.shodan()['monitor']['targets'] if t['id']==self.target)['enabled'])
        with self.assertRaises(ValueError):app.configure_shodan({'company_id':'client','domain':'client.example','enabled':1})
        app.offline=True
        with self.assertRaises(ValueError):app.configure_shodan({'company_id':'client','domain':'client.example','enabled':True})

    def test_worker_polls_only_live_unfiltered_cycles_and_continues_after_api_error(self):
        sources=self.root/'sources.json';sources.write_text('[]')
        updater=AutoUpdater(self.store,self.root/'out',self.root/'status',sources,sync=False)
        with patch('app.shodan_monitor.poll',return_value={'status':'error','error_code':'forbidden'}) as mocked:
            updater.step(collection=[])
            mocked.assert_not_called()
            state=updater.step(now=NOW)
            mocked.assert_called_once_with(self.store,now=NOW)
            self.assertEqual(state['phase'],'waiting')
            self.assertEqual(state['shodan_monitor']['error_code'],'forbidden')
            import threading
            updater.stop_event=threading.Event();updater.stop_event.set()
            mocked.reset_mock()
            self.assertEqual(updater.step(now=NOW)['phase'],'stopping')
            mocked.assert_not_called()

    def test_monitor_http_route_requires_token_and_rejects_invalid_body(self):
        app=Workbench(self.root,self.store.path);self.addCleanup(app.close)
        # Dispatch the real HTTP handler in memory: no socket or network needed.
        with patch('app.workbench.ThreadingHTTPServer',side_effect=lambda address,handler:handler):
            handler=make_server(app)
        def request(body,token=True):
            instance=object.__new__(handler)
            raw=json.dumps(body).encode()
            instance.headers={'Host':'127.0.0.1:8765','Content-Type':'application/json','Content-Length':str(len(raw))}
            if token:instance.headers['X-CTI-Token']=app.token
            instance.path='/api/shodan/monitor';instance.rfile=BytesIO(raw)
            output=[];instance.send=lambda code,data:output.append((code,data))
            instance.do_POST()
            return output[0]
        body={'company_id':'client','domain':'client.example','enabled':False}
        self.assertEqual(request(body,False)[0],403)
        self.assertEqual(request(body)[0],200)
        self.assertEqual(request(dict(body,enabled='false'))[0],400)
        self.assertFalse(monitor_status(self.store,NOW)['targets'][0]['enabled'])

    def test_active_target_limit_can_be_freed_by_pausing(self):
        domains=['d'+str(n)+'.example' for n in range(51)]
        self.store.load_companies([{'id':'many','name':'Many','domains':domains}])
        configure_target(self.store,'client','client.example',False)
        for domain in domains[:50]:configure_target(self.store,'many',domain)
        with self.assertRaises(ValueError):configure_target(self.store,'many',domains[-1])
        configure_target(self.store,'many',domains[0],False)
        self.assertTrue(configure_target(self.store,'many',domains[-1])['enabled'])

    def test_concurrent_polls_reserve_global_interval_before_network_call(self):
        from concurrent.futures import ThreadPoolExecutor
        configure_target(self.store,'client','other.example')
        client=Client({'matches':[],'total':0})
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures=[executor.submit(poll,self.store,api_key=KEY,opener=client,now=NOW) for _ in range(2)]
            results=[f.result() for f in futures]
        self.assertEqual(len(client.requests),1)
        self.assertEqual(sorted(r['status'] for r in results),['cooldown','ok'])
