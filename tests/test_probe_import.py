from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
from app.collectors import parse_source,ingest
from app.storage import CTIStore
from app.probe_import import import_probe

STAMP='2026-10-24T10:00:00+00:00'
class ProbeImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        (self.root/'html').mkdir()
        self.source={'id':'test_programs','kind':'bounty_listing','url':'https://example.org/programs/',
                     'allowed_hosts':['example.org'],'program_path':r'/programs/[^/]+/?','platform':'Test bounty','enabled':True}
        payload=b'<article><a href="/programs/example"><div data-testid="programName">Example Co</div><p>Reward and statistics must not enter the name.</p></a></article>'
        (self.root/'html/test_programs.html').write_bytes(payload)
        captured=CTIStore(self.root/'captured.sqlite3')
        pubs,_=parse_source(payload,self.source)
        for p in pubs:p.collected_at=STAMP
        ingest(captured,pubs)
        (self.root/'parsed.json').write_text(json.dumps(captured.publications()))
        receipt={'checked_at':STAMP,'mode':'isolated_public_source_probe','results':[{'source_id':'test_programs','status':'ok','items':1,'counts':{'inserted':1},'freshness':{'as_of':STAMP},'next_allowed_at':'2026-10-25T10:00:00+00:00'}]}
        (self.root/'results.json').write_text(json.dumps(receipt))
        self.store=CTIStore(self.root/'working.sqlite3')
    def tearDown(self):self.tmp.cleanup()
    def test_import_is_offline_preserves_capture_time_and_records_origin(self):
        with patch('app.collectors.checked_fetch',side_effect=AssertionError('No network expected')):
            result=import_probe(self.store,self.root,[self.source])
        self.assertEqual(result['counts'],{'inserted':1})
        pub=self.store.publications()[0]
        self.assertEqual(pub['collected_at'],STAMP)
        self.assertEqual(json.loads(pub['data'])['title'],'Example Co')
        self.assertEqual(self.store.source_status()[0]['attempted_at'],STAMP)
        self.assertEqual(json.loads(pub['data'])['metadata']['capture_receipt_sha256'],result['capture_receipt_sha256'])
    def test_repeat_does_not_duplicate_publications_or_source_runs(self):
        import_probe(self.store,self.root,[self.source])
        self.assertEqual(import_probe(self.store,self.root,[self.source])['counts'],{'unchanged':1})
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM source_runs').fetchone()[0],1)
    def test_changed_payload_set_is_rejected_before_import(self):
        (self.root/'html/test_programs.html').write_text('<a href="/programs/other">Other Co</a>')
        with self.assertRaisesRegex(ValueError,'URL'):import_probe(self.store,self.root,[self.source])
        self.assertEqual(self.store.publications(),[])
    def test_missing_capture_timestamp_is_rejected_before_writes(self):
        r=json.loads((self.root/'results.json').read_text());r['results'][0]['freshness']={}
        (self.root/'results.json').write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,'время'):import_probe(self.store,self.root,[self.source])
        self.assertEqual(self.store.publications(),[])
    def test_tampered_publication_hash_is_rejected(self):
        rows=json.loads((self.root/'parsed.json').read_text());rows[0]['content_hash']='wrong'
        (self.root/'parsed.json').write_text(json.dumps(rows))
        with self.assertRaisesRegex(ValueError,'Хеш'):import_probe(self.store,self.root,[self.source])
        self.assertEqual(self.store.publications(),[])
