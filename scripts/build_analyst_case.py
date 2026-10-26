"""Rebuild the TrueConf/PHP case from the public frozen snapshot, offline."""
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.analyst_case import analyze, export_case
from app.review_snapshot import read_snapshot
from app.storage import CTIStore

metadata = read_snapshot(ROOT / 'data/review_snapshot.json.gz')
store = CTIStore(ROOT / 'data/review/review.sqlite3')
print(json.dumps(export_case(analyze(store, metadata['frozen_at']), store,
                             ROOT / 'docs/cases/trueconf-php-2026'), ensure_ascii=False, indent=2))
