"""Refresh submitted examples from the immutable public review snapshot, offline."""
from pathlib import Path
import json
import shutil
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.review_snapshot import read_snapshot
from app.storage import CTIStore
from app.graph_scoring import calculate_graph
from app.sensitivity import analyze, export
from scripts.review import main as review_main


def main():
    # Restore/validate first; this does not open the working database or load .env.
    review_main()
    metadata = read_snapshot(ROOT / 'data/review_snapshot.json.gz')
    at = metadata['frozen_at']
    store = CTIStore(ROOT / 'data/review/review.sqlite3')
    result = calculate_graph(store, as_of=at, include_historical=True)
    for folder, ids in [('novabev-2025', ['novabev', 'winelab']), ('equifax-2017', ['equifax'])]:
        subset = dict(result)
        subset['companies'] = [c for c in result['companies'] if c['company_id'] in ids]
        (ROOT / 'docs/cases' / folder / 'score_snapshot.json').write_text(json.dumps(subset, ensure_ascii=False, indent=2) + '\n')
    # Historical engine comparisons are archived results, not new calculations
    # made by passing an old version label to the current implementation.
    sensitivity = analyze(store, as_of=at)
    out = ROOT / 'data/processed/sensitivity'
    export(sensitivity, out)
    case = ROOT / 'docs/cases/weight-sensitivity'
    for name in ('sensitivity.json', 'sensitivity.csv', 'sensitivity.html'):
        shutil.copy2(out / name, case / name)
    evidence = {'method': 'coefficient_sensitivity_on_frozen_snapshot',
        'source_snapshot_content_sha256': metadata['content_sha256'],
        'analysis': {k: v for k, v in sensitivity.items() if k != 'scenarios'}}
    (case / 'evidence.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')
    # Keep the running worker's report separate from the immutable submission.
    # build_submission --report-dir data/review/report packages the latter.
    for name in ('evaluation', 'extraction_evaluation'):
        shutil.copytree(ROOT / 'data/review' / name, ROOT / 'data/processed' / name, dirs_exist_ok=True)
    print('Frozen examples refreshed at', at)

if __name__ == '__main__':
    main()
