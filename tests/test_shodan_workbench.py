"""Local upload and review use the same passive importer as the CLI."""
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app.config import ROOT
from app.main import parser, run
from app.shodan import EXAMPLE, observations
from app.storage import CTIStore
from app.workbench import Workbench, make_server


class ShodanWorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.database=self.root/'data/test.sqlite3'
        store=CTIStore(self.database);store.load_companies([{'id':'client','name':'Client','domains':['client.example']}])
        for name in ('app/assets/workbench.html','app/assets/workbench.js','app/assets/shodan.js','app/assets/workbench.css','examples/shodan_demo.json'):
            target=self.root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
        self.app=Workbench(self.root,self.database)
        self.addCleanup(self.app.close)
        self.server=make_server(self.app,port=0)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.base='http://127.0.0.1:'+str(self.server.server_port)

    def get(self,path):
        with urlopen(self.base+path) as r:return json.load(r)

    def post(self,path,body,token=True):
        headers={'Content-Type':'application/json'}
        if token:headers['X-CTI-Token']=self.app.token
        with urlopen(Request(self.base+path,data=json.dumps(body).encode(),headers=headers)) as r:return json.load(r)

    def sample(self):
        data=json.loads(EXAMPLE.read_text());data.pop('_cti_example');data['data'][0]['hostnames']=['git.client.example'];return data

    def test_example_is_side_effect_free_and_marked_synthetic(self):
        with patch('app.shodan.fetch_host',side_effect=AssertionError('Network must not be requested')):
            example=self.get('/api/shodan/example')
            self.assertTrue(example['example_only']);self.assertTrue(example['observations'][0]['is_demo'])
        self.assertEqual(self.get('/api/shodan')['observations'],[])

    def test_upload_review_and_refutation_are_audited(self):
        identifier=self.post('/api/shodan/import',self.sample())['ids'][0]
        row=self.get('/api/shodan')['observations'][0]
        self.assertIsNone(row['association_review']);self.assertEqual(row['company_candidates'][0]['id'],'client')
        review={'id':identifier,'company_id':'client','status':'confirmed','reviewer':'Reviewer','note':'Compared public reference','evidence_url':'https://client.example/about'}
        result=self.post('/api/shodan/review',review);self.assertFalse(result['scores_changed_by_review'])
        self.assertEqual(self.get('/api/shodan')['observations'][0]['association_review']['status'],'confirmed')
        review['status']='refuted';self.post('/api/shodan/review',review)
        with CTIStore(self.database).connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM publication_metadata_updates').fetchone()[0],2)

    def test_authentication_and_import_validation_preserve_database(self):
        with self.assertRaises(HTTPError) as raised:self.post('/api/shodan/import',self.sample(),False)
        self.assertEqual(raised.exception.code,403);raised.exception.close()
        value=self.sample();value['data'][0]['port']=True
        with self.assertRaises(HTTPError) as raised:self.post('/api/shodan/import',value)
        self.assertEqual(raised.exception.code,400);raised.exception.close()
        self.assertEqual(self.get('/api/shodan')['observations'],[])
        with self.assertRaises(HTTPError) as raised:self.post('/api/shodan/scan',{'ip':'8.8.8.8'})
        self.assertEqual(raised.exception.code,404);raised.exception.close()

    def test_assets_and_empty_view_are_available_without_api_key(self):
        with urlopen(self.base+'/') as r:self.assertIn('Наблюдения Shodan',r.read().decode())
        with urlopen(self.base+'/shodan.js') as r:self.assertIn('javascript',r.headers['Content-Type'])
        self.assertFalse(self.get('/api/shodan')['changes_company_indices'])

    def test_cli_import_and_report_use_the_same_observations(self):
        path=self.root/'saved.json';path.write_text(json.dumps(self.sample()))
        result=run(parser().parse_args(['--db',str(self.database),'shodan-import',str(path),'--output',str(self.root/'report')]))
        self.assertEqual(result['counts'],{'inserted':1});self.assertTrue((self.root/'report/shodan.html').exists())
        self.assertEqual(self.get('/api/shodan')['observations'][0]['id'],result['ids'][0])

    def test_demo_database_is_separate_even_with_working_database_in_environment(self):
        for name in ('config/products.json','examples/companies_demo.json'):
            target=self.root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
        with patch('app.main.ROOT',self.root),patch.dict('os.environ',{'CTI_DB_PATH':str(self.database)}):
            run(parser().parse_args(['shodan-demo','--output',str(self.root/'report')]))
        self.assertEqual(observations(CTIStore(self.database),include_demo=True),[])
        self.assertTrue((self.root/'data/demo.sqlite3').exists())
        self.assertTrue(observations(CTIStore(self.root/'data/demo.sqlite3'),include_demo=True)[0]['is_demo'])


if __name__=='__main__':unittest.main()
