"""Load and audit the graph on an isolated SQLite copy, with an optional repeat check."""
import argparse
from contextlib import closing
import html
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.config import load_env
from app.graph import sync_graph
from app.graph_audit import prepare, read_live, audit, fingerprint
from app.models import utcnow, date_iso, redact
from app.review_snapshot import content_hash, tables
from app.storage import CTIStore


def save(result, folder):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    esc = lambda value: html.escape(str(value))
    rows = ''.join('<tr><td>' + esc(c['name']) + '</td><td>' + esc(c['status']) + '</td><td>' +
                   esc(c.get('problem_count', 0)) + '</td></tr>' for c in result.get('checks', []))
    details = json.dumps(result, ensure_ascii=False, indent=2)
    page = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Проверка Neo4j</title><style>body{font:16px/1.6 system-ui;max-width:1080px;margin:32px auto;padding:0 22px;color:#1b2c43}table{border-collapse:collapse;width:100%}th,td{padding:10px;border:1px solid #ccd5df;text-align:left}pre{white-space:pre-wrap;font-size:13px;background:#edf2f8;padding:18px}</style><h1>Проверка проекции Neo4j</h1>'''
    page += '<p>Статус: <strong>' + esc(result['status']) + '</strong>; ' + esc(result.get('checked_at')) + '</p>'
    page += '<p>Локальная подготовка и живое подтверждение различаются. prepared означает, что сервер не проверялся. Ошибки и предупреждения показаны ниже.</p>'
    if rows:
        page += '<table><tr><th>Проверка</th><th>Статус</th><th>Расхождения</th></tr>' + rows + '</table>'
    page += '<p><a href="audit.json">Машиночитаемый результат</a></p><pre>' + esc(details) + '</pre></html>'
    (folder / 'audit.html').write_text(page, encoding='utf-8')


def main():
    p = argparse.ArgumentParser(description='Проверить Neo4j по неизменяемой копии SQLite; запускать в обычном терминале')
    p.add_argument('--db', type=Path)
    p.add_argument('--as-of', help='Дата расчёта, например из submission_manifest.json')
    p.add_argument('--output', type=Path, default=ROOT / 'data/diagnostics/neo4j_audit')
    p.add_argument('--prepare-only', action='store_true', help='Только подготовка, без Neo4j')
    p.add_argument('--sync', action='store_true', help='Загрузить новую проекцию перед проверкой')
    p.add_argument('--repeat', action='store_true', help='Повторить загрузку и проверить идентичность графа; требует --sync')
    args = p.parse_args()
    if args.repeat and not args.sync:
        p.error('--repeat требует --sync')
    load_env()
    source = (args.db or Path(os.getenv('CTI_DB_PATH') or ROOT / 'data/cti.sqlite3')).resolve()
    result = {'status': 'preparing', 'checked_at': utcnow(), 'sqlite': str(source),
              'live_verified': False, 'sync_requested': args.sync, 'repeat_requested': args.repeat}
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        if not source.is_file():
            raise ValueError('SQLite не найдена. Для поставляемого снимка сначала выполните scripts/review.py')
        at = date_iso(args.as_of or utcnow())
        print('Подготовка на отдельной копии SQLite...', flush=True)
        with tempfile.TemporaryDirectory(prefix='audit-snapshot-', dir=args.output) as tmp:
            copied = Path(tmp) / 'snapshot.sqlite3'
            with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as original, \
                    closing(sqlite3.connect(copied)) as destination:
                original.backup(destination)
            store = CTIStore(copied)
            result['snapshot_content_sha256'] = content_hash(tables(store))
            expected = prepare(store, at)
            result.update(as_of=at, statements=expected['statement_count'],
                          expected_nodes_by_label={k: len(v) for k, v in expected['nodes'].items()},
                          expected_semantic_edges=len(expected['semantic']),
                          expected_overview_edges=len(expected['views']))
            if args.prepare_only:
                result.update(status='prepared', note='Сервер не проверялся. Рабочая SQLite не переизвлекалась.')
            else:
                if args.sync:
                    print('Загрузка проекции Neo4j...', flush=True)
                    result['sync'] = sync_graph(store, as_of=at)
                print('Сверка связей, доказательств и оценок...', flush=True)
                actual = read_live()
                result.update(audit(expected, actual), live_verified=True)
                result['graph_fingerprint'] = fingerprint(actual)
                if args.repeat and result['status'] == 'passed':
                    print('Повторная загрузка для проверки идемпотентности...', flush=True)
                    sync_graph(store, as_of=at)
                    repeated = read_live()
                    second = audit(expected, repeated)
                    unchanged = fingerprint(repeated) == result['graph_fingerprint']
                    result['repeat'] = {'status': second['status'], 'graph_unchanged': unchanged,
                                        'graph_fingerprint': fingerprint(repeated)}
                    if not unchanged or second['status'] != 'passed':
                        result['status'] = 'failed'
                        result['repeat']['checks'] = second['checks']
            if content_hash(tables(store)) != result['snapshot_content_sha256']:
                raise ValueError('Во время аудита изменились данные копии SQLite')
    except (ValueError, OSError, sqlite3.Error) as exc:
        result.update(status='error', error=redact(str(exc)), error_type=type(exc).__name__)
    save(result, args.output)
    print(json.dumps({k: result[k] for k in ('status', 'live_verified', 'error', 'counts', 'repeat') if k in result}, ensure_ascii=False, indent=2))
    print('Результат: ' + str((args.output / 'audit.html').resolve()))
    return 0 if result['status'] in ('passed', 'prepared') else 1


if __name__ == '__main__':
    raise SystemExit(main())
