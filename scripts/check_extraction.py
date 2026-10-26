"""Prepare a blind human extraction audit or import its completed labels, offline."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.extraction_evaluation import prepare, export_blind, assess_files, import_labels
from app.graph_view import atomic_text
from app.review_snapshot import read_snapshot
from app.storage import CTIStore


def main():
    parser = argparse.ArgumentParser(description='Слепая проверка извлечения из фиксированных текстов')
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--annotations', type=Path)
    parser.add_argument('--folder', type=Path, default=ROOT / 'evaluation')
    parser.add_argument('--output', type=Path, default=ROOT / 'data/processed/extraction_evaluation')
    args = parser.parse_args()
    if args.prepare:
        metadata = read_snapshot(ROOT / 'data/review_snapshot.json.gz')
        store = CTIStore(ROOT / 'data/review/review.sqlite3')
        corpus, predictions = prepare(store, metadata['frozen_at'], json.loads((ROOT / 'evaluation/pilot_real.json').read_text()))
        for name, value in (('extraction_corpus.json', corpus), ('extraction_predictions.json', predictions)):
            path = args.folder / name
            if path.exists():
                old = json.loads(path.read_text())
                # Predictions contain their original generation time; preserve the first frozen run.
                if old.get('corpus_id') != corpus['corpus_id']:
                    raise ValueError('Корпус уже зафиксирован; выберите новый --folder')
                if name == 'extraction_predictions.json':
                    continue
            atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        export_blind(corpus, args.folder)
    if args.annotations:
        result = import_labels(args.annotations, args.folder, args.output)
    else:
        result = assess_files(args.folder, args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise SystemExit('Проверка не завершена: ' + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__))
