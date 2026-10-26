from pathlib import Path
import tempfile
import unittest
from app.models import Publication
from app.extraction import extract,event_type
from app.collectors import ingest
from app.storage import CTIStore

class IdentifierHyphenTests(unittest.TestCase):
    def test_typographic_identifiers_are_canonical_but_source_hash_is_unchanged(self):
        text='Уязвимости CVE‑2026‑109618, CVE–2026–109619 и BDU:2026‑12345.'
        p=Publication('test','https://example.org/1','Fictional typography fixture',text)
        before=p.content_hash
        result=extract(p,[])
        self.assertEqual(result['cves'],['CVE-2026-109618','CVE-2026-109619'])
        self.assertEqual(result['bdu_ids'],['BDU:2026-12345'])
        self.assertEqual(p.text,text);self.assertEqual(p.content_hash,before)
    def test_identifier_only_announcement_is_classified(self):
        self.assertEqual(event_type('CVE‑2026‑123456'),'vulnerability_advisory')
    def test_evidence_check_accepts_canonical_id_in_original_typographic_excerpt(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=CTIStore(Path(tmp)/'db.sqlite3')
            store.load_products([{'id':'product','name':'Example Product','aliases':[]}])
            p=Publication('test','https://example.org/2','Fictional advisory','Уязвимость CVE‑2026‑123456 затрагивает Example Product.')
            ingest(store,[p])
            claim=store.assertions()[0]
            self.assertEqual(claim['subject'],'CVE-2026-123456')
            self.assertEqual(claim['status'],'needs_review')
            self.assertIn('CVE‑2026‑123456',claim['excerpt'])
            self.assertEqual(claim['evidence_hash'],p.content_hash)
