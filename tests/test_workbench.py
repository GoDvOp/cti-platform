from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app.config import ROOT
from app.collectors import ingest
from app.models import Publication, utcnow
from app.monitoring_case import seed, analyze
from app.review_snapshot import content_hash, tables, restore_snapshot
from app.graph_scoring import calculate_graph
from app.storage import CTIStore
from app.workbench import Workbench, make_server
from app.workbench_control import WorkerControl, request
from app.workbench_data import dashboard, runtime, snapshot

NOW = '2026-10-24T19:20:00+00:00'


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'config').mkdir()
        (self.root / 'config/sources.json').write_text('[]')
        (self.root / 'config/source_metadata.json').write_text('{}')
        self.store = CTIStore(self.root / 'data/cti.sqlite3')
        seed(self.store)

    def state(self, **changes):
        folder = self.root / 'data/diagnostics/auto_update'
        folder.mkdir(parents=True, exist_ok=True)
        value = {'runtime': 'docker', 'database': '/app/data/cti.sqlite3', 'phase': 'waiting',
                 'heartbeat_at': utcnow(), 'last_graph_success': utcnow()}
        value.update(changes)
        (folder / 'status.json').write_text(json.dumps(value))
        return folder

    def test_positive_case_has_action_provenance_and_distinct_observation_date(self):
        result = dashboard(self.store, self.root, NOW)
        card = result['companies'][0]
        self.assertEqual(card['id'], 'ispras')
        self.assertEqual(card['priority'], 0)
        self.assertIn('Сверить', card['next_action'])
        observation = next(e for e in card['evidence'] if e['observed_at'])
        self.assertIsNone(observation['published_at'])
        self.assertIsNone(observation['publication_day'])
        self.assertEqual(len(card['evidence']), 3)
        self.assertNotIn('extraction_predictions', json.dumps(result))

    def test_refuted_vendor_scope_cannot_keep_positive_queue(self):
        vendor = next(c for c in self.store.assertions() if c['kind'] == 'affects_product')
        self.store.review_assertion(vendor['id'], 'refuted', 'human', 'Scope is refuted for this fixture')
        result = dashboard(self.store, self.root, NOW)
        card = result['companies'][0]
        self.assertNotEqual(card['priority'], 0)
        self.assertFalse(card['hypotheses'])

    def test_source_list_excludes_retired_sources_without_removing_evidence(self):
        ids = [p['source_id'] for p in self.store.publications()]
        active, retired = ids[:2]
        configs = [dict(id=active, url='https://example.org/news', allowed_hosts=['example.org'], enabled=True),
                   dict(id=retired, url='https://example.org/old', allowed_hosts=['example.org'], enabled=False)]
        (self.root / 'config/sources.json').write_text(json.dumps(configs))
        before = content_hash(tables(self.store))
        result = dashboard(self.store, self.root, NOW)
        self.assertEqual([s['id'] for s in result['sources']], [active])
        self.assertEqual(result['counts']['sources_enabled'], 1)
        card = next(c for c in result['companies'] if c['id'] == 'ispras')
        self.assertEqual({e['source_id'] for e in card['evidence']}, set(ids))
        self.assertEqual(content_hash(tables(self.store)), before)

    def test_historical_example_uses_real_scores_without_joining_current_queue(self):
        source = ROOT / 'data/review_snapshot.json.gz'
        if not source.exists():
            source = ROOT / 'bundle/review_snapshot.json.gz'
        database = self.root / 'historical.sqlite3'
        restore_snapshot(source, database)
        store = CTIStore(database)
        before = content_hash(tables(store))
        result = dashboard(store, self.root, NOW)
        card = next(c for c in result['companies'] if c['id'] == 'equifax')
        self.assertEqual(card['example']['case_url'], '/cases/equifax-2017/case.html')
        self.assertFalse(card['monitor_target'])
        self.assertEqual(card['priority'], 6)
        self.assertEqual(card['decision_label'], 'Исторический пример')
        original = next(c for c in calculate_graph(store, as_of=NOW, include_historical=True)['companies']
                        if c['company_id'] == 'equifax')
        for dimension in ('interest', 'technical'):
            self.assertEqual(card[dimension], original[dimension])
            self.assertGreater(card[dimension]['score'], 0)
            self.assertTrue(any(p['selected'] and p['dimension'] == dimension for p in card['paths']))
        example = card['example']['reconstruction']
        self.assertEqual(example['as_of'], '2017-09-15T23:59:59+00:00')
        self.assertFalse(example['is_backtest'])
        self.assertAlmostEqual(example['interest']['score'], 6.8734580891158945)
        self.assertAlmostEqual(example['technical']['score'], 3.893067567677261)
        self.assertEqual(example['historical_technical']['score'], 90)
        allowed = set(example['publication_ids'])
        self.assertEqual(len(allowed), 2)
        for path in example['paths']:
            self.assertTrue(all(e['publication_id'] in allowed for e in path['edges']))
        self.assertEqual(example['weights_sha256'], calculate_graph(store, as_of=NOW)['weights_sha256'])
        self.assertLess(card['interest']['score'], .001)
        self.assertLess(card['technical']['score'], .001)
        self.assertGreaterEqual(len(card['evidence']), 2)
        self.assertEqual(result['counts']['review_queue'], sum(c['monitor_target'] and c['priority'] <= 2
                                                             for c in result['companies']))
        self.assertEqual(content_hash(tables(store)), before)

    def test_old_or_historical_unreviewed_message_does_not_become_fresh_priority(self):
        self.store.load_companies([{'id': 'past', 'name': 'Past company', 'aliases': ['Past company']}])
        pub = Publication('test', 'https://example.org/old', 'Past company',
                          'Past company: сообщается об атаке.', published_at='2025-01-01T00:00:00Z',
                          collected_at=NOW, metadata={'signal_scope': 'historical_incident'})
        ingest(self.store, [pub])
        card = next(c for c in dashboard(self.store, self.root, NOW)['companies'] if c['id'] == 'past')
        self.assertGreater(card['priority'], 2)

    def test_read_only_backup_does_not_change_working_data(self):
        before = content_hash(tables(self.store))
        with snapshot(self.store.path, self.root / 'scratch') as copied:
            dashboard(copied, self.root, NOW)
            copied.load_companies([{'id': 'temporary', 'name': 'Temporary'}])
        self.assertEqual(content_hash(tables(self.store)), before)
        self.assertFalse(list((self.root / 'scratch').iterdir()))

    def test_runtime_distinguishes_stopped_offline_and_docker_without_socket(self):
        self.state()
        self.assertEqual(runtime(self.root)['mode'], 'docker')
        self.assertTrue(runtime(self.root)['controls_available'])
        self.assertFalse(runtime(self.root, offline=True)['controls_available'])
        self.state(heartbeat_at='2020-01-01T00:00:00Z')
        self.assertFalse(runtime(self.root)['controls_available'])

    def test_pause_refresh_resume_are_shared_and_old_refresh_is_not_replayed(self):
        folder = self.state()
        control = WorkerControl(folder)
        request(folder, 'pause')
        self.assertTrue(control.paused)
        with self.assertRaises(ValueError):
            request(folder, 'refresh')
        request(folder, 'resume')
        request(folder, 'refresh')
        self.assertTrue(control.refresh_requested())
        self.assertFalse(control.refresh_requested())
        self.assertFalse(WorkerControl(folder).refresh_requested())
        self.assertFalse(control.paused)
        (folder / 'preferences.json').write_text('["invalid"]')
        self.assertFalse(control.paused)

    def test_http_rejects_other_hosts_cross_origin_and_missing_action_token(self):
        folder = self.state()
        app = Workbench(self.root, self.store.path)
        app.as_of = NOW
        server = make_server(app, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = 'http://127.0.0.1:' + str(server.server_port)
        with urlopen(base + '/api/dashboard') as r:
            self.assertEqual(json.load(r)['companies'][0]['id'], 'ispras')
        for headers in ({}, {'X-CTI-Token': app.token, 'Origin': 'http://evil.example'},
                        {'X-CTI-Token': app.token, 'Host': 'evil.example'}):
            req = Request(base + '/api/control', data=b'{"action":"pause"}',
                          headers={'Content-Type': 'application/json', **headers})
            with self.assertRaises(HTTPError) as raised:
                urlopen(req)
            self.assertEqual(raised.exception.code, 403)
            raised.exception.close()
        req = Request(base + '/api/control', data=b'{"action":"pause"}',
                      headers={'Content-Type': 'application/json', 'X-CTI-Token': app.token})
        with urlopen(req) as r:
            self.assertEqual(r.status, 202)
        self.assertTrue(WorkerControl(folder).paused)
        for path in ['/.env', '/evaluation/extraction_predictions.json', '/cases/../.env', '/data/cti.sqlite3']:
            with self.assertRaises(HTTPError) as raised:
                urlopen(base + path)
            self.assertEqual(raised.exception.code, 404)
            raised.exception.close()
