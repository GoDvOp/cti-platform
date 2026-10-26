"""Portable, checksummed public research snapshot. Configuration secrets are not exported."""
from contextlib import closing
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile

from .models import utcnow
from .storage import CTIStore

TABLES = ('companies', 'products', 'knowledge_entities', 'publications', 'publication_versions',
          'publication_metadata_updates', 'signals', 'reviews', 'factors', 'factor_history',
          'source_runs', 'assertions', 'assertion_reviews', 'attack_snapshots', 'attack_objects',
          'attack_mappings', 'attack_mapping_reviews')
MAX_BYTES = 120_000_000


def _encode(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def tables(store):
    with store.connect() as db:
        return {table: [dict(r) for r in db.execute('SELECT * FROM ' + table + ' ORDER BY rowid')]
                for table in TABLES}


def content_hash(data):
    return hashlib.sha256(_encode(data)).hexdigest()


def export_snapshot(store, path, as_of=None):
    # SQLite backup supplies one consistent state, even if the collector is running.
    with tempfile.TemporaryDirectory(prefix='cti-release-snapshot-') as tmp:
        target = Path(tmp) / 'snapshot.sqlite3'
        with store.connect() as source, closing(sqlite3.connect(target)) as destination:
            source.backup(destination)
        data = tables(CTIStore(target))
    result = {'format': 'cti-review-snapshot-v1', 'frozen_at': as_of or utcnow(),
              'content_sha256': content_hash(data), 'tables': data,
              'provenance': 'Public source summaries, collected listings/catalogue records, reviews and MITRE reference data. No .env or user configuration included.'}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(_encode(result), mtime=0))
    return {k: v for k, v in result.items() if k != 'tables'} | {
        'file': str(path), 'counts': {name: len(rows) for name, rows in data.items()}}


def read_snapshot(path):
    with gzip.open(path, 'rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('Снимок превышает допустимый размер')
    data = json.loads(raw)
    if data.get('format') != 'cti-review-snapshot-v1' or set(data.get('tables', {})) != set(TABLES):
        raise ValueError('Неизвестный формат снимка')
    if content_hash(data['tables']) != data.get('content_sha256'):
        raise ValueError('Хеш снимка не совпадает')
    return data


def restore_snapshot(path, destination):
    data = read_snapshot(path)
    destination = Path(destination)
    if destination.exists():
        raise ValueError('База уже существует; снимок восстанавливается только в новый файл')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cti-restore-', dir=destination.parent) as tmp:
        temp_path = Path(tmp) / 'restored.sqlite3'
        store = CTIStore(temp_path)
        with store.connect() as db:
            # Publish one self-contained file. A WAL checkpoint can fail under
            # disk pressure while committed rows remain readable in the sidecar;
            # moving only the main file would then publish an incomplete DB.
            db.execute('PRAGMA journal_mode=DELETE')
            for table in TABLES:
                columns = [r['name'] for r in db.execute('PRAGMA table_info(' + table + ')')]
                rows = data['tables'][table]
                if any(not isinstance(row, dict) or set(row) != set(columns) for row in rows):
                    raise ValueError('Неизвестные столбцы таблицы ' + table)
                query = 'INSERT INTO ' + table + '(' + ','.join(columns) + ') VALUES(' + ','.join('?' for _ in columns) + ')'
                db.executemany(query, [tuple(row[c] for c in columns) for row in rows])
        if content_hash(tables(store)) != data['content_sha256']:
            raise ValueError('Восстановленный снимок не совпадает с исходным')
        with store.connect() as db:
            if db.execute('PRAGMA foreign_key_check').fetchall():
                raise ValueError('Нарушена ссылочная целостность снимка')
            if [r[0] for r in db.execute('PRAGMA integrity_check')] != ['ok']:
                raise ValueError('Нарушена целостность восстановленной базы')
        temp_path.replace(destination)
    return {'database': str(destination), 'frozen_at': data['frozen_at'], 'content_sha256': data['content_sha256']}
