import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from app.graph import execute_requests, graph_status, sync_graph
from app.storage import CTIStore
from app.models import Publication
from app.collectors import ingest


def response(data):
    obj = MagicMock()
    obj.__enter__.return_value.read.return_value = json.dumps(data).encode()
    return obj


class GraphDiagnosticsTests(unittest.TestCase):
    def test_connection_refused_does_not_blame_terminal(self):
        with patch('app.graph.urlopen', side_effect=URLError(ConnectionRefusedError('secret'))):
            with self.assertRaisesRegex(ValueError, 'Соединение отклонено') as result:
                execute_requests('http://127.0.0.1:17474', 'auth', [], 'создание схемы')
        self.assertIn('17474', str(result.exception))
        self.assertNotIn('обычном терминале', str(result.exception))
        self.assertNotIn('secret', str(result.exception))

    def test_permission_failure_identifies_environment(self):
        with patch('app.graph.urlopen', side_effect=URLError(PermissionError('secret'))):
            with self.assertRaisesRegex(ValueError, 'Среда запрещает соединение'):
                execute_requests('http://127.0.0.1:7474', 'auth', [], 'schema')

    def test_timeout_identifies_waiting_for_response(self):
        with patch('app.graph.urlopen', side_effect=TimeoutError('secret')):
            with self.assertRaisesRegex(ValueError, 'Истекло время ожидания'):
                execute_requests('http://127.0.0.1:7474', 'auth', [], 'schema')

    def test_auth_error_explains_password_without_echo(self):
        error = HTTPError('http://127.0.0.1:7474', 401, 'secret', {}, None)
        with patch('app.graph.urlopen', side_effect=error):
            with self.assertRaisesRegex(ValueError, 'пароль из .env отклонён') as result:
                execute_requests('http://127.0.0.1:7474', 'encoded-secret', [], 'schema')
        self.assertNotIn('encoded-secret', str(result.exception))

    def test_cypher_error_includes_stage_and_server_code(self):
        data = {'errors':[{'code':'Neo.ClientError.Statement.SyntaxError','message':'Invalid input near SET'}]}
        with patch('app.graph.urlopen', return_value=response(data)):
            with self.assertRaisesRegex(ValueError, 'загрузка данных.*SyntaxError'):
                execute_requests('http://127.0.0.1:7474', 'auth', [], 'загрузка данных')

    def test_graph_status_reads_labels_and_relationship_counts(self):
        data = {'errors':[], 'results':[
            {'columns':['labels','count'],'data':[{'row':[['Product'],2]},{'row':[['Company'],5]}]},
            {'columns':['type','count'],'data':[{'row':['USED_PRODUCT',1]}]}]}
        with patch.dict('os.environ', {'NEO4J_HTTP_URL':'http://127.0.0.1:7474','NEO4J_PASSWORD':'test-password'}), \
             patch('app.graph.urlopen', return_value=response(data)):
            result = graph_status()
        self.assertEqual(result['nodes'][0], {'labels':['Product'],'count':2})
        self.assertEqual(result['relationships'][0]['type'], 'USED_PRODUCT')

    def test_sync_does_not_claim_success_when_products_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CTIStore(Path(tmp) / 'db.sqlite3')
            store.load_products([{'id':'test-product','name':'TestProduct','aliases':[]}])
            ingest(store,[Publication('test','https://source.example/1','Описание TestProduct','Продукт TestProduct')])
            empty = {'errors':[], 'results':[{'columns':['labels','count'],'data':[]},
                                            {'columns':['type','count'],'data':[]}]}
            with patch.dict('os.environ', {'NEO4J_HTTP_URL':'http://127.0.0.1:7474','NEO4J_PASSWORD':'test-password'}), \
                 patch('app.graph.urlopen', return_value=response(empty)):
                with self.assertRaisesRegex(ValueError, 'не найдены узлы Product'):
                    sync_graph(store)


if __name__ == '__main__':
    unittest.main()
