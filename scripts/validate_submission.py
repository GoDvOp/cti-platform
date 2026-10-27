"""Validate the 3.0.0 submission against its frozen inputs and current receipts."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.extraction_evaluation import assess, files_fingerprint
from app.review_snapshot import read_snapshot
from scripts.check_docker import runtime_fingerprint


def validate(root=ROOT):
    root = Path(root)
    read = lambda name: json.loads((root / name).read_text())
    snapshot = read_snapshot(root / 'data/review_snapshot.json.gz')
    manifest = read('data/submission_manifest.json')
    settings = read('config/submission.json')
    release = read('RELEASE_CHECKS.json')
    version = tomllib.loads((root / 'pyproject.toml').read_text())['project']['version']
    model = read('config/graph_weights.json')['model_version']
    at = snapshot['frozen_at']
    counts = {name: len(rows) for name, rows in snapshot['tables'].items()}
    checks = []
    def check(name, valid):
        checks.append({'name': name, 'status': 'passed' if valid else 'failed'})
    check('snapshot_manifest_and_configuration', manifest['content_sha256'] == snapshot['content_sha256']
          and manifest['frozen_at'] == at and manifest['counts'] == counts and settings['frozen_at'] == at)
    report_path = root / 'data/review/report/report.json'
    if not report_path.exists():
        raise ValueError('Сначала выполните python3 scripts/review.py для проверки снимка')
    report = json.loads(report_path.read_text())
    check('frozen_report_uses_current_model', report['as_of'] == at and report['model_version'] == model
          and report['weighted_graph']['model_version'] == model)
    pubs = {r['id']: r for r in snapshot['tables']['publications']}
    case = read('docs/cases/trueconf-php-2026/decision.json')
    check('case_evidence_matches_snapshot', case['as_of'] == at
          and all(e['publication_id'] in pubs and e['content_hash'] == pubs[e['publication_id']]['content_hash']
                  for e in case['evidence']))
    check('closed_network_case_does_not_invent_external_target', case['decision'] == 'internal_patch_review'
          and case['named_external_target_supported'] is False and case['attack_established_by_this_chain'] is False)
    scores = [read('docs/cases/' + folder + '/score_snapshot.json')
              for folder in ('novabev-2025', 'equifax-2017', 'trueconf-php-2026')]
    check('case_scores_use_current_model_and_fixed_date', all(r['calculated_at'] == at and r['model_version'] == model for r in scores))
    eq = next(r for r in scores[1]['companies'] if r['company_id'] == 'equifax')
    check('historical_fact_is_separate_from_current_applicability', eq['historical_technical']['score'] == 90
          and eq['historical_technical']['current_vulnerability_established'] is False
          and eq['technical']['score'] < .001)
    corpus = read('evaluation/extraction_corpus.json')
    predictions = read('evaluation/extraction_predictions.json')
    labels_path = root / 'evaluation/extraction_annotations.json'
    labels = json.loads(labels_path.read_text()) if labels_path.exists() else None
    assessment = assess(corpus, predictions, labels)
    check('extraction_inputs_belong_to_snapshot', corpus['as_of'] == at
          and all(r['publication_id'] in pubs and r['content_hash'] == pubs[r['publication_id']]['content_hash'] for r in corpus['records']))
    catalogs = {name: {r['id']: json.loads(r['data']) for r in snapshot['tables'][name]} for name in ('companies', 'products')}
    check('extraction_catalogs_match_snapshot', all({r['id']: r for r in corpus[name]} == catalogs[name] for name in catalogs))
    check('extractor_code_matches_frozen_predictions', predictions['extractor_sha256'] == files_fingerprint())
    check('no_fabricated_human_metrics', read('data/review/extraction_evaluation/extraction.json') == assessment)
    protected = read('docs/analysis/release-3.0.0/protected_inputs.json')
    check('review_inputs_match_recorded_hashes', all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
          for name, digest in protected['files'].items()))
    check('release_version_and_snapshot', version == release['project_version'] == '3.0.0'
          and release['model_version'] == model and release['snapshot_as_of'] == at
          and release['snapshot_content_sha256'] == manifest['content_sha256'])
    texts = [(root / 'README.md').read_text()]
    check('public_summaries_use_current_version_and_counts', all(version in text and str(counts['publications']) in text for text in texts))
    additional = read_snapshot(root / 'docs/cases/ispras-gitlab-2026/snapshot.json.gz')
    new_case = read('docs/cases/ispras-gitlab-2026/decision.json')
    bundle = read('examples/ispras_gitlab_case.json')
    check('additional_case_has_separate_snapshot', additional['frozen_at'] == bundle['AS_OF'] == new_case['as_of']
          and len(additional['tables']['publications']) == 3
          and not {p['id'] for p in additional['tables']['publications']} & set(pubs))
    check('positive_case_preserves_unknown_version_and_attack', new_case['decision'] == 'conditional_monitoring_candidate'
          and new_case['named_external_target_supported'] is False
          and new_case['attack_established_by_this_chain'] is False and new_case['decision_gates']['affected_installed_version'] is None)
    browser_path = root / 'docs/analysis/release-3.0.0/browser/checks.json'
    browser = json.loads(browser_path.read_text()) if browser_path.exists() else {}
    check('real_browser_acceptance', browser.get('status') == 'passed' and not browser.get('page_errors'))
    receipt_path = root / 'docs/analysis/release-3.0.0/docker.json'
    receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else {}
    check('clean_archive_docker_acceptance', receipt.get('status') == 'passed'
          and receipt.get('project_version') == version and receipt.get('isolated_resource_cleanup') == 'passed')
    check('docker_receipt_matches_runtime_files', receipt.get('runtime_input_sha256') == runtime_fingerprint(root))
    return {'status': 'passed' if all(r['status'] == 'passed' for r in checks) else 'failed',
            'project_version': version, 'model_version': model, 'as_of': at,
            'snapshot_sha256': manifest['content_sha256'], 'checks': checks,
            'human_extraction_review': assessment['status']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = validate()
        value = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(value)
        print(value, end='')
        raise SystemExit(0 if result['status'] == 'passed' else 1)
    except (ValueError, KeyError, OSError) as exc:
        raise SystemExit('Проверка комплекта не завершена: ' + str(exc))
