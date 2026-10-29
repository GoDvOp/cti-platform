"""Profile edits survive catalogue reloads and preserve evidence and concurrent edits."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app.company_edit import profile, revision, save
from app.monitoring_case import seed
from app.shodan_monitor import configure_target, monitor_status
from app.storage import CTIStore
from app.workbench import Workbench, make_server


class CompanyEditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'config').mkdir()
        (self.root / 'config/sources.json').write_text('[]')
        self.store = CTIStore(self.root / 'data/cti.sqlite3')
        seed(self.store)
        self.company = next(c for c in self.store.companies() if c['id'] == 'ispras')
        self.body = {'id': 'ispras', 'revision': revision(self.company), 'profile': profile(self.company)}
        self.app = Workbench(self.root, self.store.path)
        self.addCleanup(self.app.close)

    def test_save_and_catalogue_reload_keep_local_fields_and_uneditable_flags(self):
        before = self.store.publications()
        self.body['profile'].update(name='Новое название', description='Заметка аналитика',
                                    domains=['GIT.EXAMPLE.'], sector='Исследования')
        result = self.app.edit_company(self.body)
        reopened = CTIStore(self.store.path)
        reopened.load_companies([{**self.company, 'country': 'ZZ', 'monitor_target': False}])
        company = reopened.companies()[0]
        self.assertEqual(company['name'], 'Новое название')
        self.assertEqual(company['domains'], ['git.example'])
        self.assertEqual(company['country'], self.company.get('country', ''))
        self.assertFalse(company['monitor_target'])
        self.assertEqual(reopened.publications(), before)
        self.assertNotEqual(result['revision'], self.body['revision'])
        with reopened.connect() as db:
            audit = db.execute('SELECT * FROM company_edit_history').fetchone()
            self.assertEqual(json.loads(audit['before_data'])['name'], self.company['name'])
            self.assertEqual(json.loads(audit['after_data'])['name'], 'Новое название')

    def test_concurrent_edit_is_rejected_without_overwriting_first_writer(self):
        self.body['profile']['name'] = 'Первый редактор'
        self.app.edit_company(self.body)
        self.body['profile']['name'] = 'Второй редактор'
        with self.assertRaisesRegex(ValueError, 'уже изменена'):
            save(CTIStore(self.store.path), self.body)
        self.assertEqual(self.store.companies()[0]['name'], 'Первый редактор')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM company_edit_history').fetchone()[0], 1)

    def test_unchanged_form_returns_current_revision_without_an_audit_entry(self):
        result = self.app.edit_company(self.body)
        self.assertEqual(result['revision'], self.body['revision'])
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM company_edit_history').fetchone()[0], 0)

    def test_invalid_input_never_changes_profile_or_records_an_edit(self):
        for patch in ({'name': ''}, {'domains': ['example.com org:other']},
                      {'domains': ['https://example.com']}, {'domains': ['127.0.0.1']},
                      {'reference_url': 'javascript:alert(1)'}, {'reference_url': 'https://user:pass@example.com'},
                      {'aliases': 'text'}, {'id': 'replacement'}, {'description': 'x' * 4001}):
            with self.subTest(patch=list(patch)):
                body = {**self.body, 'profile': {**self.body['profile'], **patch}}
                with self.assertRaises(ValueError):
                    self.app.edit_company(body)
        self.assertEqual(self.store.companies()[0], self.company)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM company_edit_history').fetchone()[0], 0)

    def test_dashboard_cache_is_invalidated_and_offline_edit_is_refused(self):
        old = self.app.data()['companies'][0]
        self.body['profile']['name'] = 'Обновлённая компания'
        self.app.edit_company(self.body)
        new = self.app.data()['companies'][0]
        self.assertEqual(new['name'], 'Обновлённая компания')
        self.assertEqual(new['profile']['name'], new['name'])
        self.assertNotEqual(old['profile_revision'], new['profile_revision'])
        self.app.offline = True
        with self.assertRaises(ValueError):
            self.app.edit_company(self.body)

    def test_removing_domain_invalidates_existing_watch_without_deleting_history(self):
        configure_target(self.store, 'ispras', self.company['domains'][0])
        self.body['profile']['domains'] = ['new.example']
        self.app.edit_company(self.body)
        targets = monitor_status(self.store)['targets']
        self.assertEqual(len(targets), 1)
        self.assertFalse(targets[0]['catalog_valid'])

    def test_edit_route_requires_token_and_success_persists_across_server_restart(self):
        server = make_server(self.app, port=0)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url = 'http://127.0.0.1:' + str(server.server_port) + '/api/company/edit'
            self.body['profile']['description'] = 'Сохранено через HTTP'
            headers = {'Content-Type': 'application/json'}
            request = Request(url, json.dumps(self.body).encode(), headers=headers)
            with self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=5)
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
            headers['X-CTI-Token'] = self.app.token
            with urlopen(Request(url, json.dumps(self.body).encode(), headers=headers), timeout=5) as response:
                self.assertEqual(json.load(response)['status'], 'ok')
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
        reopened = Workbench(self.root, self.store.path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.data()['companies'][0]['profile']['description'], 'Сохранено через HTTP')
