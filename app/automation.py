"""Persistent passive collection and graph refresh, including analyst/config changes."""
from contextlib import closing
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import threading
import time

from .collectors import collect_source, validate_sources
from .config import ROOT
from .graph import sync_graph
from .graph_audit import prepare, read_live, audit, fingerprint
from .graph_view import atomic_text, export as export_view
from .models import utcnow, redact
from .reporting import export_report
from .storage import CTIStore
from .workbench_control import WorkerControl


FINGERPRINT_COLUMNS = {
    'companies': 'id,data', 'products': 'id,data', 'knowledge_entities': 'id,entity_type,data',
    'publications': 'id,source_id,url,content_hash,published_at,collected_at,is_demo,data,extraction',
    'signals': 'id,data', 'assertions': 'id,data', 'attack_snapshots': 'sha256,data,active',
    'attack_mappings': 'local_id,stix_id,data',
}


def input_fingerprint(store, config_paths=()):
    """Exclude score logs, poll history and last_seen_at which our own loop changes."""
    checksum = hashlib.sha256()
    with store.connect() as db:
        for table, columns in FINGERPRINT_COLUMNS.items():
            checksum.update(table.encode())
            for row in db.execute('SELECT ' + columns + ' FROM ' + table + ' ORDER BY 1,2'):
                checksum.update(json.dumps(list(row), ensure_ascii=False, separators=(',', ':')).encode())
    for path in config_paths:
        path = Path(path)
        checksum.update(path.name.encode())
        checksum.update(path.read_bytes())
    return checksum.hexdigest()


class AutoUpdater:
    def __init__(self, store, output, status_folder, sources_path, *, sync=True,
                 syncer=None, reader=None, reporter=None, view_writer=None, max_age_seconds=900,
                 source_id=None, stop_event=None):
        self.store = store
        self.output = Path(output)
        self.folder = Path(status_folder)
        self.sources_path = Path(sources_path)
        self.sync_enabled = sync
        self.syncer = syncer or sync_graph
        self.reader = reader or read_live
        self.reporter = reporter or export_report
        self.view_writer = view_writer or export_view
        self.max_age_seconds = max_age_seconds
        self.source_id = source_id
        self.stop_event = stop_event
        self.runtime = {}
        self.last_attempt = None
        self.last_success_monotonic = None
        self.last_fingerprint = None
        self.last_day = None
        self.state = {'phase': 'starting', 'graph_pending': sync, 'last_graph_success': None,
                      'last_graph_error': None, 'graph_sync_enabled': sync,
                      'worker_started_at': utcnow(),
                      'runtime': os.getenv('CTI_RUNTIME', 'desktop'),
                      'database': str(store.path.resolve())}
        path = self.folder / 'status.json'
        if path.exists():
            try:
                old = json.loads(path.read_text())
                if old.get('database') == self.state['database']:
                    self.state['last_graph_success'] = old.get('last_graph_success')
            except (OSError, ValueError):
                pass
        self.save()

    def save(self):
        self.state['heartbeat_at'] = utcnow()
        atomic_text(self.folder / 'status.json', json.dumps(self.state, ensure_ascii=False, indent=2) + '\n')

    def step(self, *, force=False, now=None, monotonic=None, collection=None):
        at = now or utcnow()
        clock = time.monotonic() if monotonic is None else monotonic
        self.state.update(phase='collecting', cycle_started_at=at)
        self.state.pop('last_error', None)
        self.save()
        try:
            sources = validate_sources(json.loads(self.sources_path.read_text()))
            if self.source_id:
                sources = [s for s in sources if s['id'] == self.source_id]
                if not sources:
                    raise ValueError('Неизвестный source-id: ' + self.source_id)
            results = collection
            if results is None:
                results = []
                if self.stop_event and self.stop_event.is_set():
                    self.state['phase'] = 'stopping'
                    self.save()
                    return self.state
                if not self.source_id:
                    # Run Shodan before slow feeds, but never during the initial
                    # local projection (collection=[]), offline reviews or filters.
                    from .shodan_monitor import poll
                    self.state['shodan_monitor'] = poll(self.store, now=now)
                    self.save()
                for source in sources:
                    if self.stop_event and self.stop_event.is_set():
                        self.state['phase'] = 'stopping'
                        self.save()
                        return self.state
                    results.append(collect_source(self.store, source, self.runtime))
            at = now or utcnow()
            self.state['source_summary'] = [{k: r.get(k) for k in ('source_id', 'status', 'error_code', 'items')} for r in results]
            configs = [self.sources_path, ROOT / 'config/source_metadata.json', ROOT / 'config/graph_weights.json']
            current = input_fingerprint(self.store, configs)
            day = at[:10]
            dirty = force or current != self.last_fingerprint or day != self.last_day
            periodic = self.last_success_monotonic is None or clock - self.last_success_monotonic >= self.max_age_seconds
            self.state['graph_pending'] = self.sync_enabled and (self.state['graph_pending'] or dirty or periodic)
            due = self.sync_enabled and self.state['graph_pending'] and (force or self.last_attempt is None or clock - self.last_attempt >= 60)
            if due:
                self.last_attempt = clock
                self.state.update(phase='updating', graph_attempt_at=at)
                self.save()
                self.folder.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(prefix='projection-', dir=self.folder) as tmp:
                    copied = Path(tmp) / 'snapshot.sqlite3'
                    with self.store.connect() as original, closing(sqlite3.connect(copied)) as destination:
                        original.backup(destination)
                    frozen = CTIStore(copied)
                    # Newly collected evidence must precede the projection time.
                    at = now or utcnow()
                    frozen_fingerprint = input_fingerprint(frozen, configs)
                    self.reporter(frozen, self.output, as_of=at)
                    try:
                        self.syncer(frozen, as_of=at)
                        expected = prepare(frozen, at)
                        actual = self.reader()
                        checked = audit(expected, actual)
                        checked.update(checked_at=utcnow(), live_verified=True, execution='automatic_user_service',
                                       input_fingerprint=frozen_fingerprint, graph_fingerprint=fingerprint(actual))
                        atomic_text(self.folder / 'audit.json', json.dumps(checked, ensure_ascii=False, indent=2) + '\n')
                        if checked['status'] != 'passed':
                            raise ValueError('После загрузки найдены расхождения: ' + ', '.join(
                                c['name'] for c in checked['checks'] if c['status'] != 'passed'))
                        self.state.update(last_graph_success=checked['checked_at'], graph_as_of=at,
                                          last_graph_error=None, graph_pending=False,
                                          graph_counts=checked['counts'], graph_checks_passed=len(checked['checks']))
                        self.last_fingerprint = frozen_fingerprint
                        self.last_day = at[:10]
                        self.last_success_monotonic = clock
                    except (ValueError, OSError, sqlite3.Error) as exc:
                        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
                        self.state.update(last_graph_error=redact(message), graph_pending=True)
                    self.view_writer(frozen, self.output, as_of=at, status=self.state)
            elif self.output.joinpath('graph_view.json').exists():
                # Refresh the status badge even if evidence is unchanged or Neo4j is offline.
                self.view_writer(self.store, self.output, as_of=at, status=self.state)
            self.state.update(phase='waiting', cycle_finished_at=utcnow())
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as exc:
            message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            self.state.update(phase='error', last_error=redact(message), graph_pending=self.sync_enabled)
        self.save()
        return self.state


def run_worker(store, sources_path, output, *, sync=True, interval=60, source_id=None, status_folder=None):
    # An advisory lock prevents a desktop worker and a manual worker competing.
    import fcntl
    folder = Path(status_folder) if status_folder else ROOT / 'data/diagnostics/auto_update'
    folder.mkdir(parents=True, exist_ok=True)
    wake = threading.Event()
    stopped = threading.Event()
    forced = threading.Event()
    def request_update(signum, frame):
        forced.set()
        wake.set()
    def request_stop(signum, frame):
        stopped.set()
        wake.set()
    previous = {}
    for sig, handler in ((signal.SIGUSR1, request_update), (signal.SIGTERM, request_stop)):
        previous[sig] = signal.signal(sig, handler)
    try:
        with (folder / 'worker.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError('Автообновление уже запущено другим процессом. '
                                 'Для перехода с настольной службы на Docker выполните ./start-cti.sh.') from exc
            updater = AutoUpdater(store, output, folder, sources_path, sync=sync,
                                  source_id=source_id, stop_event=stopped)
            control = WorkerControl(folder)
            # Publish the local snapshot before potentially slow network polling.
            print(json.dumps(updater.step(collection=[]), ensure_ascii=False), flush=True)
            next_cycle = 0
            was_paused = control.paused
            while not stopped.is_set():
                force = forced.is_set() or control.refresh_requested()
                forced.clear()
                paused = control.paused
                if paused:
                    updater.state.update(phase='paused', paused=True)
                    updater.save()
                elif force or was_paused or time.monotonic() >= next_cycle:
                    updater.state['paused'] = False
                    state = updater.step(force=force)
                    print(json.dumps(state, ensure_ascii=False), flush=True)
                    next_cycle = time.monotonic() + interval
                was_paused = paused
                wake.wait(1)
                wake.clear()
            updater.state['phase'] = 'stopped'
            updater.save()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
