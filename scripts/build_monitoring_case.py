"""Build the separate GitLab case without touching the original snapshot or review corpus."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.monitoring_case import seed, analyze, export_case, BUNDLE
from app.review_snapshot import read_snapshot, restore_snapshot
from app.storage import CTIStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/cases/ispras-gitlab-2026')
    parser.add_argument('--db', type=Path, help='Явно указать базу для импорта; по умолчанию отдельная временная БД')
    parser.add_argument('--snapshot', type=Path, help='Воспроизвести ранее сохранённый дополнительный снимок')
    parser.add_argument('--as-of', help='Дата расчёта; по умолчанию исходный AS_OF дополнительного набора')
    args = parser.parse_args()
    if args.db and args.snapshot:
        parser.error('--db и --snapshot задаются отдельно')
    bundle = json.loads(BUNDLE.read_text())
    with tempfile.TemporaryDirectory(prefix='cti-case-build-') as tmp:
        database = args.db or Path(tmp) / 'case.sqlite3'
        if args.snapshot:
            metadata = read_snapshot(args.snapshot)
            restore_snapshot(args.snapshot, database)
            imported = {'snapshot_restored': True}
            at = args.as_of or metadata['frozen_at']
        else:
            imported = seed(CTIStore(database))
            at = args.as_of or bundle['AS_OF']
        store = CTIStore(database)
        result = analyze(store, at)
        exported = export_case(result, store, args.output)
        print(json.dumps({'seed': imported, **exported}, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
