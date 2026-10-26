"""One offline review command; reads a public snapshot, never the working database/.env."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.review_snapshot import read_snapshot, restore_snapshot, content_hash, tables
from app.storage import CTIStore
from app.graph_scoring import calculate_graph
from app.reporting import export_report
from app.graph import export_graph
from app.evaluation import evaluate, export as export_evaluation


def main():
    p = argparse.ArgumentParser(description='Офлайн-проверка проекта на изолированном снимке')
    p.add_argument('--snapshot', type=Path, default=ROOT / 'data/review_snapshot.json.gz')
    p.add_argument('--output', type=Path, default=ROOT / 'data/review')
    args = p.parse_args()
    metadata = read_snapshot(args.snapshot)
    args.output.mkdir(parents=True, exist_ok=True)
    database = args.output / 'review.sqlite3'
    if not database.exists():
        restore_snapshot(args.snapshot, database)
    store = CTIStore(database)
    if content_hash(tables(store)) != metadata['content_sha256']:
        raise ValueError('Существующая review.sqlite3 изменена; выберите новый каталог через --output')
    scored = calculate_graph(store, as_of=metadata['frozen_at'], include_historical=True)
    report = export_report(store, args.output / 'report', as_of=metadata['frozen_at'])
    graph = export_graph(store, args.output / 'graph.json', as_of=metadata['frozen_at'])
    pilot = export_evaluation(evaluate(ROOT / 'evaluation/pilot_real.json'), args.output / 'evaluation')
    from app.analyst_case import analyze, export_case
    from app.extraction_evaluation import assess_files
    analyst_case = export_case(analyze(store, metadata['frozen_at']), store, args.output / 'analyst_case')
    extraction = assess_files(ROOT / 'evaluation', args.output / 'extraction_evaluation')
    result = {'status': 'ok', 'offline': True, 'as_of': metadata['frozen_at'], 'snapshot_sha256': metadata['content_sha256'],
              'model': scored['model_version'], 'publications': report['publications'],
              'assertions': len(store.assertions()), 'companies': len(scored['companies']),
              'report': str((args.output / 'report/report.html').resolve()), 'graph': graph,
              'classification_pilot': pilot,
              'analyst_case': analyst_case, 'extraction_evaluation': extraction,
              'note': 'Обрабатывается копия публичного снимка. Рабочая БД, сеть, .env и Neo4j не используются.'}
    (args.output / 'review_result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError) as exc:
        raise SystemExit(str(exc))
