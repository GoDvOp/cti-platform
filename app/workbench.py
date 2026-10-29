"""Local analyst workbench. Standard library only; no arbitrary file or command API."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import threading
import time
from urllib.parse import urlsplit, parse_qs

from .config import ROOT
from .graph_view import payload as graph_payload
from .models import utcnow
from .workbench_control import request as request_control
from .workbench_data import dashboard, runtime, snapshot


class Workbench:
    def __init__(self, root=ROOT, database=None, offline=False):
        self.root = Path(root).resolve()
        self.database = Path(database or os.getenv('CTI_DB_PATH') or self.root / 'data/cti.sqlite3').resolve()
        self.offline = offline or not self.database.is_file()
        self.as_of = None
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.cached = None
        self.cache_at = 0
        self.folder = self.root / 'data/diagnostics/workbench'
        self.folder.mkdir(parents=True, exist_ok=True)
        if self.offline:
            self._prepare_offline()

    def _prepare_offline(self):
        from .review_snapshot import read_snapshot, restore_snapshot
        from .storage import CTIStore
        source = self.root / 'data/review_snapshot.json.gz'
        if not source.exists():
            source = self.root / 'bundle/review_snapshot.json.gz'
        metadata = read_snapshot(source)
        # A fresh copy is independent of the user's review and annotation files.
        target_folder = Path(tempfile.mkdtemp(prefix='offline-', dir=self.folder))
        self.database = target_folder / 'workbench.sqlite3'
        restore_snapshot(source, self.database)
        self.as_of = metadata['frozen_at']
        bundle = self.root / 'examples/ispras_gitlab_case.json'
        if bundle.exists():
            from .monitoring_case import seed
            seed(CTIStore(self.database), bundle)
            contents = json.loads(bundle.read_text())
            self.as_of = contents.get('as_of') or contents.get('AS_OF') or self.as_of
        self.offline_folder = target_folder

    def close(self):
        import shutil
        if hasattr(self, 'offline_folder'):
            shutil.rmtree(self.offline_folder)

    def data(self, graph=False):
        with self.lock:
            if not graph and self.cached is not None and time.monotonic() - self.cache_at < 5:
                result = dict(self.cached)
                result['runtime'] = runtime(self.root, self.offline)
                return result
            with snapshot(self.database, self.folder) as store:
                if graph:
                    return graph_payload(store, self.as_of, status=runtime(self.root, self.offline))
                result = dashboard(store, self.root, self.as_of, self.offline)
            self.cached, self.cache_at = result, time.monotonic()
            return result

    def control(self, action):
        current = runtime(self.root, self.offline)
        if not current['controls_available']:
            raise ValueError('Сборщик не работает или открыт офлайн-снимок. Запустите сборщик выбранным способом.')
        return request_control(self.root / 'data/diagnostics/auto_update', action)

    def shodan(self):
        from .shodan import observations
        from .shodan_monitor import monitor_status
        with snapshot(self.database, self.folder) as store:
            return {'observations': observations(store, include_demo=True), 'offline': self.offline,
                    'monitor': monitor_status(store), 'runtime': runtime(self.root, self.offline),
                    'companies': store.companies(), 'changes_company_indices': False}

    def configure_shodan(self, body):
        if self.offline:
            raise ValueError('Откройте обычный стенд для настройки наблюдения')
        if not isinstance(body, dict) or set(body) != {'company_id', 'domain', 'enabled'}:
            raise ValueError('Shodan: выберите компанию, домен и состояние наблюдения')
        from .shodan_monitor import configure_target
        from .storage import CTIStore
        with self.lock:
            return configure_target(CTIStore(self.database), **body)

    def import_shodan(self, body):
        if self.offline:
            raise ValueError('Офлайн-панель использует временную базу. Импортируйте файл после обычного запуска стенда.')
        from .shodan import import_export
        from .storage import CTIStore
        with self.lock:
            result = import_export(CTIStore(self.database), body)
            self.cached = None
        return result

    def review_shodan(self, body):
        if self.offline:
            raise ValueError('Временная офлайн-база не сохраняет проверки. Откройте обычный стенд.')
        from .shodan import review_association
        from .storage import CTIStore
        required = {'id', 'company_id', 'status', 'reviewer', 'note', 'evidence_url'}
        if not isinstance(body, dict) or set(body) != required:
            raise ValueError('Shodan: заполните компанию, статус, проверяющего, объяснение и ссылку')
        with self.lock:
            result = review_association(CTIStore(self.database), body['id'], body['company_id'],
                                        body['status'], body['reviewer'], body['note'], body['evidence_url'])
            self.cached = None
        return result


def make_server(app, host='127.0.0.1', port=8765):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'CTIWorkbench'

        def log_message(self, fmt, *args):
            # Bodies, query strings and local tokens never appear in logs.
            pass

        def allowed_host(self):
            try:
                parsed = urlsplit('http://' + self.headers.get('Host', ''))
                return parsed.hostname in ('localhost', '127.0.0.1', '::1') and parsed.username is None
            except ValueError:
                return False

        def send(self, status, body, mime='application/json; charset=utf-8'):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Frame-Options', 'SAMEORIGIN')
            self.end_headers()
            self.wfile.write(body)

        def file(self, path, mime):
            if not path.is_file():
                return self.send(404, {'error': 'Файл пока не сформирован'})
            return self.send(200, path.read_bytes(), mime)

        def do_GET(self):
            if not self.allowed_host():
                return self.send(403, {'error': 'Недопустимый адрес панели'})
            path = urlsplit(self.path).path
            try:
                if path == '/':
                    page = (app.root / 'app/assets/workbench.html').read_text()
                    return self.send(200, page.replace('__TOKEN__', app.token), 'text/html; charset=utf-8')
                if path in ('/workbench.js', '/workbench.css', '/shodan.js'):
                    mime = 'application/javascript; charset=utf-8' if path.endswith('.js') else 'text/css; charset=utf-8'
                    return self.file(app.root / 'app/assets' / path[1:], mime)
                if path == '/api/dashboard':
                    return self.send(200, app.data())
                if path == '/api/shodan':
                    return self.send(200, app.shodan())
                if path == '/api/shodan/example':
                    from .shodan import normalize_export
                    records = normalize_export(json.loads((app.root / 'examples/shodan_demo.json').read_text()))
                    return self.send(200, {'observations': records, 'companies': [], 'example_only': True})
                if path == '/shodan-example.json':
                    return self.file(app.root / 'examples/shodan_demo.json', 'application/json; charset=utf-8')
                if path == '/health':
                    return self.send(200, {'ok': True, 'service': 'cti-workbench', 'offline': app.offline})
                if path == '/graph':
                    data = app.data(graph=True)
                    encoded = json.dumps(data, ensure_ascii=False).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
                    page = (app.root / 'app/assets/graph_view.html').read_text()
                    script = (app.root / 'app/assets/graph_view.js').read_text()
                    return self.send(200, page.replace('__SCRIPT__', script, 1).replace('__DATA__', encoded, 1), 'text/html; charset=utf-8')
                if path == '/review':
                    return self.file(app.root / 'evaluation/blind_review.html', 'text/html; charset=utf-8')
                if path == '/review-result':
                    folder = app.root / 'data/processed/extraction_evaluation'
                    if not (folder / 'extraction.html').exists():
                        from .extraction_evaluation import assess_files
                        assess_files(app.root / 'evaluation', folder)
                    return self.file(folder / 'extraction.html', 'text/html; charset=utf-8')
                # Publish only known case artifacts, never a general filesystem tree.
                if path.startswith('/cases/'):
                    parts = Path(path).parts
                    folders = {'ispras-gitlab-2026', 'trueconf-php-2026', 'novabev-2025', 'equifax-2017'}
                    files = {'case.html', 'graph_view.html', 'graph.svg', 'evidence.json', 'decision.json', 'score_snapshot.json', 'graph.cypher', 'snapshot.json.gz', 'snapshot_manifest.json'}
                    if len(parts) == 4 and parts[2] in folders and parts[3] in files:
                        mime = {'html': 'text/html; charset=utf-8', 'pdf': 'application/pdf', 'svg': 'image/svg+xml', 'json': 'application/json; charset=utf-8', 'gz': 'application/gzip'}.get(parts[3].rsplit('.', 1)[-1], 'text/plain; charset=utf-8')
                        return self.file(app.root / 'docs/cases' / parts[2] / parts[3], mime)
                return self.send(404, {'error': 'Страница не найдена'})
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
                return self.send(503, {'error': str(exc) if isinstance(exc, ValueError) else 'Не удалось прочитать данные панели'})

        def do_POST(self):
            if not self.allowed_host():
                return self.send(403, {'error': 'Недопустимый адрес панели'})
            origin = self.headers.get('Origin')
            if origin is not None and origin != 'http://' + self.headers.get('Host', ''):
                return self.send(403, {'error': 'Запрос с другого сайта отклонён'})
            token = self.headers.get('X-CTI-Token', '')
            if not secrets.compare_digest(token, app.token):
                return self.send(403, {'error': 'Обновите страницу панели перед действием'})
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                return self.send(415, {'error': 'Нужен JSON'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 2_000_000:
                    return self.send(413, {'error': 'Недопустимый размер запроса'})
                body = json.loads(self.rfile.read(length))
                if urlsplit(self.path).path == '/api/shodan/import':
                    return self.send(200, app.import_shodan(body))
                if urlsplit(self.path).path == '/api/shodan/review':
                    return self.send(200, app.review_shodan(body))
                if urlsplit(self.path).path == '/api/shodan/monitor':
                    return self.send(200, app.configure_shodan(body))
                if urlsplit(self.path).path == '/api/control':
                    if not isinstance(body, dict) or set(body) != {'action'}:
                        raise ValueError('Нужно выбрать действие панели')
                    return self.send(202, app.control(body['action']))
                if urlsplit(self.path).path == '/api/labels':
                    from .extraction_evaluation import import_labels
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', dir=app.folder, delete=False) as stream:
                        target = Path(stream.name)
                        json.dump(body, stream, ensure_ascii=False)
                    try:
                        result = import_labels(target, folder=app.root / 'evaluation',
                                               output=app.root / 'data/processed/extraction_evaluation')
                    finally:
                        target.unlink(missing_ok=True)
                    return self.send(200, result)
                return self.send(404, {'error': 'Действие не найдено'})
            except (ValueError, KeyError, TypeError) as exc:
                return self.send(400, {'error': str(exc)})
            except (OSError, sqlite3.Error):
                return self.send(503, {'error': 'Не удалось сохранить результат'})

    return ThreadingHTTPServer((host, port), Handler)


def main():
    parser = argparse.ArgumentParser(description='Локальная аналитическая панель CTI')
    parser.add_argument('--host', default='127.0.0.1', choices=['127.0.0.1', '0.0.0.0'])
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--db', type=Path)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    app = Workbench(database=args.db, offline=args.offline)
    server = None
    try:
        server = make_server(app, args.host, args.port)
        print(f'CTI: http://127.0.0.1:{server.server_port}/', flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server is not None:
            server.server_close()
        app.close()


if __name__ == '__main__':
    main()
