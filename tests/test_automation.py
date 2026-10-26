import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from app.automation import AutoUpdater, input_fingerprint
from app.collectors import ingest
from app.models import Publication
from app.storage import CTIStore
from app.graph_audit import prepare
from tests.test_graph_audit import projected_fixture

NOW = '2026-10-24T15:00:00+00:00'


class AutomationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root / 'db.sqlite3')
        self.store.load_companies([{'id': 'alpha', 'name': 'Example Alpha', 'aliases': [], 'sector': 'Example'}])
        self.store.load_products([{'id': 'sample', 'name': 'Example Product', 'aliases': []}])
        self.pub = Publication('test', 'https://example.org/test', 'Fictional fixture',
                               'Example Alpha использует Example Product.',
                               published_at=NOW, collected_at=NOW)
        ingest(self.store, [self.pub])
        self.claim = self.store.add_assertion({'publication_id': self.pub.id, 'kind': 'uses_product',
            'subject': 'alpha', 'object': 'sample', 'excerpt': self.pub.text,
            'attributes': {'observed_day': '2026-10-24'}})
        self.sources = self.root / 'sources.json'
        self.sources.write_text('[]')
        self.syncer = Mock()
        self.reader = Mock(side_effect=lambda: projected_fixture(prepare(self.snapshot, self.at)))
        def report(snapshot, output, as_of):
            self.snapshot, self.at = snapshot, as_of
        self.reporter = Mock(side_effect=report)
        self.writer = Mock()
        self.updater = AutoUpdater(self.store, self.root / 'report', self.root / 'status', self.sources,
            syncer=self.syncer, reader=self.reader, reporter=self.reporter, view_writer=self.writer)

    def tearDown(self):
        self.tmp.cleanup()

    def step(self, clock=0, **kwargs):
        return self.updater.step(monotonic=clock, now=kwargs.pop('now', NOW), collection=[], **kwargs)

    def test_success_requires_readback_and_writes_audited_consistent_snapshot(self):
        state = self.step()
        self.assertFalse(state['graph_pending'])
        self.assertIsNotNone(state['last_graph_success'])
        self.assertNotEqual(self.snapshot.path, self.store.path)
        receipt = json.loads((self.root / 'status/audit.json').read_text())
        self.assertEqual(receipt['status'], 'passed')
        self.assertEqual(len(receipt['checks']), 9)
        self.assertEqual(receipt['input_fingerprint'], self.updater.last_fingerprint)
        self.step(60)
        self.assertEqual(self.syncer.call_count, 1)

    def test_review_changes_update_graph_without_new_publications(self):
        self.step()
        self.store.review_assertion(self.claim, 'confirmed', 'Test analyst', 'Fictional review', confidence='medium', basis='research_report')
        state = self.step(60)
        self.assertEqual(self.syncer.call_count, 2)
        self.assertFalse(state['graph_pending'])

    def test_clock_and_config_changes_update_projection(self):
        self.step()
        self.step(900)
        self.assertEqual(self.syncer.call_count, 2)
        self.step(960, now='2026-10-25T00:01:00+00:00')
        self.assertEqual(self.syncer.call_count, 3)
        self.sources.write_text('[ ]')
        self.step(1020, now='2026-10-25T00:02:00+00:00')
        self.assertEqual(self.syncer.call_count, 4)

    def test_connection_failure_retries_with_backoff_and_preserves_report(self):
        self.syncer.side_effect = ValueError('Neo4j unavailable')
        state = self.step()
        self.assertTrue(state['graph_pending'])
        self.assertIsNone(state['last_graph_success'])
        self.assertEqual(self.reporter.call_count, 1)
        self.step(30)
        self.assertEqual(self.syncer.call_count, 1)
        self.step(60)
        self.assertEqual(self.syncer.call_count, 2)
        self.syncer.side_effect = None
        state = self.step(61, force=True)
        self.assertEqual(self.syncer.call_count, 3)
        self.assertFalse(state['graph_pending'])
        self.assertIsNone(state['last_graph_error'])

    def test_incomplete_projection_is_not_reported_as_success(self):
        self.reader.side_effect = lambda: {'nodes': [], 'relationships': []}
        state = self.step()
        self.assertTrue(state['graph_pending'])
        self.assertIsNone(state['last_graph_success'])
        receipt = json.loads((self.root / 'status/audit.json').read_text())
        self.assertEqual(receipt['status'], 'failed')

    def test_polling_bookkeeping_is_ignored_but_evidence_changes_are_detected(self):
        before = input_fingerprint(self.store)
        with self.store.connect() as db:
            db.execute("UPDATE publications SET last_seen_at='2099-01-01T00:00:00Z'")
        self.assertEqual(input_fingerprint(self.store), before)
        self.store.review_assertion(self.claim, 'refuted', 'Test analyst', 'Fictional retraction')
        self.assertNotEqual(input_fingerprint(self.store), before)

    def test_source_filter_and_force_preserve_collector_cooldowns(self):
        sources = [dict(id=s, url='https://example.org/feed', allowed_hosts=['example.org'], polling_minutes=60)
                   for s in ('first', 'second')]
        self.sources.write_text(json.dumps(sources))
        self.updater.source_id = 'second'
        with patch('app.automation.collect_source', return_value={'source_id': 'second', 'status': 'cooldown'}) as collect:
            self.updater.step(force=True, now=NOW, monotonic=0)
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(collect.call_args.args[1]['id'], 'second')
        self.assertEqual(collect.call_args.kwargs, {})
