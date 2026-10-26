import gzip
import json
import sqlite3
from contextlib import closing
from pathlib import Path
import tempfile
import unittest

from app.collectors import ingest
from app.models import Publication
from app.review_snapshot import export_snapshot, restore_snapshot, read_snapshot, tables, content_hash
from app.storage import CTIStore
from app.graph_scoring import calculate_graph


class ReviewSnapshotTests(unittest.TestCase):
    def test_restore_preserves_evidence_and_review_without_mutating_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);store=CTIStore(root/'working.sqlite3')
            store.load_companies([{'id':'alpha','name':'Example Alpha','aliases':[]}])
            pub=Publication('test','https://example.org/1','Fictional','Example Alpha: продаётся доступ.',
                            published_at='2026-10-23T12:00:00Z',collected_at='2026-10-23T13:00:00Z')
            ingest(store,[pub]);sig=store.signals()[0]
            store.review(sig['id'],'confirmed','unresolved','medium','Analyst','Fictional fixture')
            before=content_hash(tables(store));path=root/'snapshot.json.gz'
            exported=export_snapshot(store,path,'2026-10-24T23:59:59+00:00')
            restore_snapshot(path,root/'restored.sqlite3')
            # The published file must contain every committed page itself,
            # without depending on WAL sidecars left in the temporary folder.
            with closing(sqlite3.connect(root/'restored.sqlite3')) as db:
                self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0], 'delete')
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            restored=CTIStore(root/'restored.sqlite3')
            self.assertEqual(content_hash(tables(restored)),before)
            self.assertEqual(content_hash(tables(store)),before)
            self.assertEqual(calculate_graph(store,as_of=exported['frozen_at']),
                             calculate_graph(restored,as_of=exported['frozen_at']))
            original=(root/'restored.sqlite3').read_bytes()
            with self.assertRaisesRegex(ValueError,'уже существует'):
                restore_snapshot(path,root/'restored.sqlite3')
            self.assertEqual(original,(root/'restored.sqlite3').read_bytes())

    def test_corrupted_snapshot_rejected_before_creating_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'snapshot.gz'
            export_snapshot(CTIStore(root/'working.sqlite3'),path)
            data=read_snapshot(path);data['tables']['companies'].append({'id':'tampered','data':'{}'})
            path.write_bytes(gzip.compress(json.dumps(data).encode()))
            with self.assertRaisesRegex(ValueError,'Хеш'):
                restore_snapshot(path,root/'restored.sqlite3')
            self.assertFalse((root/'restored.sqlite3').exists())
