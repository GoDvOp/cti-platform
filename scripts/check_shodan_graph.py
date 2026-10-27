"""Acceptance on a disposable Neo4j instance: confirmed observation and revocation.

Run only inside check_docker.py's isolated Compose project. SQLite input is copied;
the fictional service below must never be projected into a working graph.
"""
from contextlib import closing
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
from app.graph_audit import audit, prepare, read_live
from app.graph_scoring import calculate_graph
from app.models import utcnow
from app.shodan import EXAMPLE, import_export, review_association
from app.storage import CTIStore


def main():
    if os.getenv('CTI_DISPOSABLE_GRAPH_CHECK') != '1':
        raise SystemExit('Запускайте через scripts/check_docker.py на одноразовом графе.')
    load_env()
    source = Path(os.getenv('CTI_DB_PATH', ROOT / 'data/cti.sqlite3'))
    with tempfile.TemporaryDirectory(dir=ROOT / 'data/diagnostics', prefix='shodan-check-') as tmp:
        copied = Path(tmp) / 'snapshot.sqlite3'
        with closing(sqlite3.connect(source)) as original, closing(sqlite3.connect(copied)) as destination:
            original.backup(destination)
        store = CTIStore(copied)
        store.load_companies([{'id': 'shodan-test-client', 'name': 'Вымышленный клиент проверки',
                              'domains': ['client.example'], 'monitor_target': False}])
        example = json.loads(EXAMPLE.read_text())
        example.pop('_cti_example')
        example['data'][0]['hostnames'] = ['git.client.example']
        identifier = import_export(store, example)['ids'][0]
        review_association(store, identifier, 'shodan-test-client', 'confirmed', 'Acceptance test',
                           'Fictional fixture association; not evidence about an organisation',
                           'https://client.example/about')
        at = utcnow()
        sync_graph(store, as_of=at)
        live = read_live()
        assert audit(prepare(store, at), live)['status'] == 'passed'
        edges = [e for e in live['relationships'] if e['relation'] == 'HAS_TECHNICAL_OBSERVATION']
        assert len(edges) == 1 and edges[0]['object'] == identifier
        assert edges[0]['properties']['weight_role'] == 'context_only'
        assert edges[0]['properties'].get('current_vulnerability_established') is False
        assert edges[0]['properties'].get('weight') is None
        before = calculate_graph(CTIStore(source), as_of=at)['companies']
        after = calculate_graph(store, as_of=at)['companies']
        assert before == [c for c in after if c['company_id'] != 'shodan-test-client']
        review_association(store, identifier, 'shodan-test-client', 'refuted', 'Acceptance test',
                           'Revoke the fictional association', 'https://client.example/about')
        at = utcnow()
        sync_graph(store, as_of=at)
        live = read_live()
        assert not any(e['relation'] == 'HAS_TECHNICAL_OBSERVATION' for e in live['relationships'])
        assert audit(prepare(store, at), live)['status'] == 'passed'
        with store.connect() as db:
            assert db.execute('SELECT count(*) FROM publication_metadata_updates WHERE publication_id=?',
                              (identifier,)).fetchone()[0] == 2
        print(json.dumps({'status': 'passed', 'confirmed_context_edge': True, 'indices_unchanged': True,
                          'revocation_removes_edge': True, 'review_history_preserved': True}))


if __name__ == '__main__':
    main()
