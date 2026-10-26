from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.container import bootstrap, healthy
from app.review_snapshot import export_snapshot, content_hash, tables
from app.storage import CTIStore


class ContainerTests(unittest.TestCase):
    def setUp(self):
        # Tiny fixtures should not depend on the capacity of the test temp mount.
        disk = patch('app.container.shutil.disk_usage', return_value=SimpleNamespace(free=1024 ** 3))
        disk.start()
        self.addCleanup(disk.stop)
        supplement = patch('app.monitoring_case.seed', return_value={})
        supplement.start()
        self.addCleanup(supplement.stop)

    def test_first_start_restores_snapshot_and_repeat_preserves_analyst_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = CTIStore(root / 'source.sqlite3')
            source.load_companies([{'id': 'fixture', 'name': 'Fixture company', 'aliases': []}])
            snapshot = root / 'snapshot.json.gz'
            export_snapshot(source, snapshot)
            target = root / 'runtime/cti.sqlite3'
            self.assertTrue(bootstrap(target, snapshot=snapshot)['restored_public_snapshot'])
            store = CTIStore(target)
            self.assertEqual(content_hash(tables(source)), content_hash(tables(store)))
            store.load_companies([{'id': 'analyst', 'name': 'Analyst addition', 'aliases': []}])
            before = content_hash(tables(store))
            self.assertFalse(bootstrap(target, snapshot=snapshot)['restored_public_snapshot'])
            self.assertEqual(content_hash(tables(store)), before)

    def test_invalid_snapshot_does_not_publish_a_partial_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / 'broken.gz'
            snapshot.write_bytes(b'not gzip')
            target = root / 'runtime/cti.sqlite3'
            with self.assertRaises(OSError):
                bootstrap(target, snapshot=snapshot)
            self.assertFalse(target.exists())

    def test_empty_start_initializes_catalog_without_loading_publications(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'cti.sqlite3'
            result = bootstrap(target, mode='empty')
            self.assertGreater(result['companies'], 0)
            self.assertEqual(CTIStore(target).publications(), [])
            with self.assertRaises(ValueError):
                bootstrap(target, mode='typo')

    def test_insufficient_space_is_explained_without_creating_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'cti.sqlite3'
            with patch('app.container.shutil.disk_usage') as usage:
                usage.return_value.free = 0
                with self.assertRaisesRegex(ValueError, '256 MiB'):
                    bootstrap(target)
            self.assertFalse(target.exists())

    def test_health_rejects_missing_stale_failed_or_unaudited_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'status.json'
            now = datetime(2026, 10, 24, 20, 0, tzinfo=timezone.utc)
            self.assertFalse(healthy(path, now))
            good = {'heartbeat_at': now.isoformat(), 'phase': 'waiting',
                    'worker_started_at': now.isoformat(),
                    'last_graph_success': now.isoformat(), 'last_graph_error': None}
            path.write_text(json.dumps(good))
            self.assertTrue(healthy(path, now))
            for changes in ({'heartbeat_at': '2026-10-24T19:00:00+00:00'},
                            {'phase': 'error'}, {'phase': 'stopped'},
                            {'last_graph_success': '2026-10-24T19:59:59+00:00'},
                            {'last_graph_success': None}, {'last_graph_error': 'Connection refused'}):
                path.write_text(json.dumps(good | changes))
                self.assertFalse(healthy(path, now))
