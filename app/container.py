"""Container startup and health checks; never replace an existing database."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys

from .config import ROOT, load_env
from .storage import CTIStore


def bootstrap(database, mode='snapshot', snapshot=None):
    import fcntl
    from .review_snapshot import restore_snapshot

    if mode not in ('snapshot', 'empty'):
        raise ValueError('CTI_BOOTSTRAP: допустимы snapshot или empty')
    database = Path(database)
    database.parent.mkdir(parents=True, exist_ok=True)
    with (database.parent / '.cti-bootstrap.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        restored = not database.exists() and mode == 'snapshot'
        if restored:
            if shutil.disk_usage(database.parent).free < 256 * 1024 ** 2:
                raise ValueError('Для восстановления снимка нужно минимум 256 MiB свободного места в data')
            restore_snapshot(snapshot or ROOT / 'bundle/review_snapshot.json.gz', database)
        store = CTIStore(database)
        if not store.companies():
            store.load_companies(json.loads((ROOT / 'config/companies.json').read_text()))
        if mode == 'snapshot':
            from .monitoring_case import seed
            seed(store)
        return {'database': str(database), 'restored_public_snapshot': restored,
                'companies': len(store.companies())}


def healthy(path=None, now=None):
    try:
        state = json.loads(Path(path or ROOT / 'data/diagnostics/auto_update/status.json').read_text())
        heartbeat = datetime.fromisoformat(state['heartbeat_at'])
        age = ((now or datetime.now(timezone.utc)) - heartbeat).total_seconds()
        return (0 <= age < 900 and state.get('phase') not in ('error', 'stopped', 'stopping')
                and bool(state.get('last_graph_success')) and not state.get('last_graph_error')
                and datetime.fromisoformat(state['last_graph_success'])
                    >= datetime.fromisoformat(state['worker_started_at']))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def main():
    args = sys.argv[1:] or ['status']
    if args == ['health']:
        return 0 if healthy() else 1
    if args[0] == 'review':
        # No load_env, source collection or bootstrap in the offline path.
        os.execv(sys.executable, [sys.executable, str(ROOT / 'scripts/review.py'),
                                 '--snapshot', str(ROOT / 'bundle/review_snapshot.json.gz'), *args[1:]])
    if args[0] == 'workbench':
        os.execv(sys.executable, [sys.executable, '-m', 'app.workbench', *args[1:]])
    if args[0] in ('python', 'python3'):
        os.execv(sys.executable, [sys.executable, *args[1:]])
    load_env()
    if args[0] in ('worker', 'bootstrap'):
        try:
            result = bootstrap(os.getenv('CTI_DB_PATH') or ROOT / 'data/cti.sqlite3',
                               os.getenv('CTI_BOOTSTRAP', 'snapshot'))
        except (ValueError, OSError, sqlite3.Error) as exc:
            print('Подготовка контейнера: ' + (str(exc) if isinstance(exc, ValueError)
                                               else type(exc).__name__), file=sys.stderr)
            return 1
        print(json.dumps(result, ensure_ascii=False), flush=True)
        if args[0] == 'bootstrap':
            return 0
    os.execv(sys.executable, [sys.executable, '-m', 'app.main', *args])


if __name__ == '__main__':
    raise SystemExit(main())
