"""Frozen extraction predictions and blind human labels; never invent missing gold."""
import hashlib
import html
import json
from pathlib import Path
import re

from .config import ROOT
from .extraction import extract
from .graph_view import atomic_text
from .models import Publication, normalized, identifier_text, utcnow

KINDS = ('uses_product', 'affects_product', 'part_of', 'subsidiary_of', 'supplies_to', 'partners_with')
QUOTAS = {'securitylab_news': 6, 'securitylab_analytics': 3, 'securelist_research': 2,
          'trueconf_advisories': 5, 'cisa_kev': 5, 'bizone_news': 3, 'standoff_programs': 2,
          'trueconf_php_notice': 1, 'manual_web_trueconf_cases': 3}


def checksum(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def files_fingerprint():
    return checksum({name: hashlib.sha256((ROOT / 'app' / name).read_bytes()).hexdigest()
                     for name in ('extraction.py', 'knowledge.py', 'models.py')})


def prepare(store, as_of, pilot, count=30):
    if count != sum(QUOTAS.values()):
        raise ValueError('Объём определяется заранее зафиксированными квотами')
    prior = pilot['records']
    catalog_sources = {'trueconf_advisories', 'cisa_kev'}
    excluded_urls = {r['publication']['url'] for r in prior
                     if r['publication']['source_id'] not in catalog_sources}
    excluded_ids = {r['publication_id'] for r in prior}
    excluded_hashes = {r['content_hash'] for r in prior}
    eligible = [p for p in store.publications() if p['id'] not in excluded_ids and p['url'] not in excluded_urls
                and p['content_hash'] not in excluded_hashes and p['collected_at'] <= as_of]
    rows, used_urls, used_hashes = [], set(), set()
    for source, amount in QUOTAS.items():
        candidates = sorted((p for p in eligible if p['source_id'] == source),
                            key=lambda p: checksum(['extraction-review-20261024', p['id']]))
        chosen = []
        for p in candidates:
            if (source not in catalog_sources and p['url'] in used_urls) or p['content_hash'] in used_hashes:
                continue
            chosen.append(p)
            used_urls.add(p['url']); used_hashes.add(p['content_hash'])
            if len(chosen) == amount:
                break
        if len(chosen) != amount:
            raise ValueError('Недостаточно непересекающихся текстов: ' + source)
        rows.extend(chosen)
    rows.sort(key=lambda p: checksum(['presentation-order', p['id']]))
    companies = store.companies()
    products = store.products()
    corpus = {'format': 'cti-extraction-corpus-v1', 'as_of': as_of,
              'sampling': {'method': 'predeclared_source_quotas_then_sha256_order',
                           'seed': 'extraction-review-20261024', 'quotas': QUOTAS,
                           'excluded_prior_pilot_urls': len(excluded_urls),
                           'excluded_prior_pilot_ids': len(excluded_ids),
                           'catalog_entry_identity': 'publication_id_and_content_hash; catalogue URL may repeat',
                           'prediction_based_selection': False,
                           'unseen_development_holdout': False},
              'limitations': ['Оцениваются сохранённые тексты и каталог, а не весь интернет или HTML-парсер.',
                             'Часть входов — краткие пересказы; они помечены в форме.',
                             'Материалы могли использоваться при разработке; это не скрытый holdout.',
                             'Человеческая независимость декларируется рецензентом, а не устанавливается программой.'],
              'companies': companies, 'products': products,
              'records': [{'sample_id': i + 1, 'publication_id': p['id'], 'content_hash': p['content_hash'],
                           'publication': json.loads(p['data'])} for i, p in enumerate(rows)]}
    corpus['corpus_id'] = checksum(corpus)
    predictions = {'format': 'cti-extraction-predictions-v1', 'corpus_id': corpus['corpus_id'],
                   'frozen_at': utcnow(), 'extractor_sha256': files_fingerprint(), 'records': []}
    for row in corpus['records']:
        p = Publication(**row['publication'])
        result = extract(p, companies, products)
        predictions['records'].append({'sample_id': row['sample_id'], 'content_hash': p.content_hash,
            'products': result['products'], 'vulnerabilities': sorted(result['cves'] + result['bdu_ids']),
            'relations': [{k: a[k] for k in ('kind', 'subject', 'object')} for a in result['assertions']]})
    predictions['run_id'] = checksum(predictions)
    return corpus, predictions


def validate_inputs(corpus, predictions):
    body = {k: v for k, v in corpus.items() if k != 'corpus_id'}
    if corpus.get('format') != 'cti-extraction-corpus-v1' or checksum(body) != corpus.get('corpus_id'):
        raise ValueError('Изменился корпус проверки')
    body = {k: v for k, v in predictions.items() if k != 'run_id'}
    if predictions.get('format') != 'cti-extraction-predictions-v1' or checksum(body) != predictions.get('run_id'):
        raise ValueError('Изменились зафиксированные ответы алгоритма')
    if predictions['corpus_id'] != corpus['corpus_id']:
        raise ValueError('Ответы алгоритма относятся к другому корпусу')
    expected = {r['sample_id']: r for r in corpus['records']}
    actual = {r['sample_id']: r for r in predictions['records']}
    if len(expected) != len(corpus['records']) or set(actual) != set(expected) or len(actual) != len(predictions['records']):
        raise ValueError('Неполный набор ответов алгоритма или повтор ID')
    for row in corpus['records']:
        pub = Publication(**row['publication'])
        if pub.content_hash != row['content_hash'] or pub.id != row['publication_id']:
            raise ValueError('Изменился текст проверки')
        if actual[row['sample_id']]['content_hash'] != row['content_hash']:
            raise ValueError('Ответ алгоритма относится к другой версии текста')


def _identifiers(values):
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ValueError('Нужен список идентификаторов CVE/BDU')
    result = [identifier_text(v).strip().upper() for v in values]
    if any(not re.fullmatch(r'(?:CVE-\d{4}-\d{4,}|BDU:\d{4}-\d{4,})', v) for v in result):
        raise ValueError('Некорректный идентификатор CVE/BDU')
    if len(set(result)) != len(result):
        raise ValueError('Повтор идентификатора CVE/BDU')
    return result


def validate_labels(corpus, labels):
    if labels.get('format') != 'cti-extraction-labels-v1' or labels.get('corpus_id') != corpus['corpus_id']:
        raise ValueError('Разметка относится к другому корпусу')
    reviewer = labels.get('reviewer', {})
    if not isinstance(reviewer.get('name'), str) or not reviewer['name'].strip():
        raise ValueError('Нужно имя или псевдоним рецензента')
    if reviewer.get('role') not in ('project_author', 'external_reviewer'):
        raise ValueError('Нужно указать отношение рецензента к проекту')
    if reviewer.get('predictions_seen') is not False or reviewer.get('external_assistance') is not False:
        raise ValueError('Слепая человеческая проверка требует самостоятельной разметки без ответов алгоритма и внешних подсказок')
    expected = {r['sample_id']: r for r in corpus['records']}
    rows = labels.get('records')
    if not isinstance(rows, list) or len({r['sample_id'] for r in rows}) != len(rows):
        raise ValueError('Некорректный набор разметки или повтор ID')
    if {r['sample_id'] for r in rows} != set(expected):
        raise ValueError('Нужно разметить весь корпус; непроверенные тексты нельзя считать пустыми')
    companies = {c['id'] for c in corpus['companies'] if not c.get('is_demo', False)}
    products = {p['id'] for p in corpus['products'] if not p.get('is_demo', False)}
    for row in rows:
        original = expected[row['sample_id']]
        if row.get('content_hash') != original['content_hash']:
            raise ValueError('Разметка относится к другой версии текста')
        if row.get('status') not in ('reviewed', 'excluded'):
            raise ValueError('Есть непроверенные тексты')
        if row['status'] == 'excluded':
            if not isinstance(row.get('note'), str) or not row['note'].strip():
                raise ValueError('Для исключения нужно обоснование')
            continue
        if not isinstance(row.get('products'), list) or not set(row['products']) <= products:
            raise ValueError('Неизвестный продукт в разметке')
        if len(set(row['products'])) != len(row['products']):
            raise ValueError('Повтор продукта в разметке')
        _identifiers(row.get('vulnerabilities'))
        if not isinstance(row.get('relations'), list):
            raise ValueError('Нужен список связей, включая пустой')
        seen = set()
        for relation in row['relations']:
            kind, subject, obj = (relation.get(k) for k in ('kind', 'subject', 'object'))
            if kind not in KINDS:
                raise ValueError('Неизвестный тип связи')
            if kind == 'affects_product':
                _identifiers([subject])
                if subject not in _identifiers(row['vulnerabilities']) or obj not in products:
                    raise ValueError('Концы связи CVE → продукт не совпадают с разметкой')
            elif subject not in companies or obj not in (products if kind == 'uses_product' else companies):
                raise ValueError('Неизвестные концы связи')
            if kind != 'affects_product' and subject == obj:
                raise ValueError('Связь с собой недопустима')
            if kind in ('affects_product', 'uses_product') and obj not in row['products']:
                raise ValueError('Продукт связи должен быть отмечен в тексте')
            key = kind, subject, obj
            if key in seen:
                raise ValueError('Повтор связи в разметке')
            seen.add(key)
            excerpt = relation.get('excerpt')
            text = original['publication']['title'] + '\n' + original['publication']['text']
            if not isinstance(excerpt, str) or not excerpt.strip() or normalized(excerpt) not in normalized(text):
                raise ValueError('Доказательный фрагмент связи не найден в тексте')
    if not any(r['status'] == 'reviewed' for r in rows):
        raise ValueError('Все тексты исключены: качество измерить нельзя')


def metrics(gold, predicted):
    tp, fp, fn = len(gold & predicted), len(predicted - gold), len(gold - predicted)
    return {'tp': tp, 'fp': fp, 'fn': fn, 'gold_count': len(gold), 'predicted_count': len(predicted),
            'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def assess(corpus, predictions, labels=None):
    validate_inputs(corpus, predictions)
    common = {'corpus_id': corpus['corpus_id'], 'run_id': predictions['run_id'], 'as_of': corpus['as_of'],
              'task': 'exact_directed_relations_and_catalog_product_and_vulnerability_mentions',
              'count': len(corpus['records']), 'sampling': corpus['sampling'], 'limitations': corpus['limitations'],
              'prediction_quality_measured': False, 'extractor_sha256': predictions['extractor_sha256']}
    if labels is None:
        return dict(common, status='awaiting_human_labels', reviewed=0, excluded=0, metrics=None,
                    reviewer=None, independence='not_established')
    validate_labels(corpus, labels)
    predicted = {r['sample_id']: r for r in predictions['records']}
    gold_sets = {task: set() for task in ('relations', 'products', 'vulnerabilities')}
    predicted_sets = {task: set() for task in gold_sets}
    mistakes, exact = [], 0
    for row in labels['records']:
        if row['status'] == 'excluded':
            continue
        uid = row['sample_id']
        correct_document = True
        for task in gold_sets:
            def values(record):
                if task == 'relations':
                    return {(r['kind'], r['subject'], r['object']) for r in record[task]}
                if task == 'vulnerabilities':
                    return set(_identifiers(record[task]))
                return set(record[task])
            gold, got = values(row), values(predicted[uid])
            gold_sets[task].update((uid, value) for value in gold)
            predicted_sets[task].update((uid, value) for value in got)
            if gold != got:
                correct_document = False
                mistakes.append({'sample_id': uid, 'task': task, 'false_positive': sorted(got - gold),
                                 'false_negative': sorted(gold - got)})
        exact += correct_document
    reviewed = sum(r['status'] == 'reviewed' for r in labels['records'])
    per_kind = {kind: metrics({r for r in gold_sets['relations'] if r[1][0] == kind},
                              {r for r in predicted_sets['relations'] if r[1][0] == kind}) for kind in KINDS}
    return dict(common, status='completed_human_review', reviewed=reviewed,
                excluded=len(labels['records']) - reviewed, reviewer=labels['reviewer'],
                independence=('external_reviewer_self_declared' if labels['reviewer']['role'] == 'external_reviewer'
                              else 'blind_project_author_review_not_external'),
                labels_sha256=checksum(labels),
                metrics={task: metrics(gold_sets[task], predicted_sets[task]) for task in gold_sets},
                per_relation_kind=per_kind, exact_documents=exact, exact_document_rate=exact / reviewed,
                mistakes=mistakes)


def blind_payload(corpus):
    return {'corpus_id': corpus['corpus_id'], 'as_of': corpus['as_of'], 'kinds': KINDS,
            'companies': [{'id': c['id'], 'name': c['name']} for c in corpus['companies'] if not c.get('is_demo', False)],
            'products': [{'id': p['id'], 'name': p['name']} for p in corpus['products'] if not p.get('is_demo', False)],
            'records': [{'sample_id': r['sample_id'], 'content_hash': r['content_hash'],
                         'title': r['publication']['title'], 'text': r['publication']['text'],
                         'url': r['publication']['url'],
                         'content_scope': r['publication'].get('metadata', {}).get('content_scope', 'saved_source_text')}
                        for r in corpus['records']]}


def export_blind(corpus, folder):
    folder = Path(folder)
    payload = json.dumps(blind_payload(corpus), ensure_ascii=False).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    template = (ROOT / 'app/assets/extraction_review.html').read_text()
    script = (ROOT / 'app/assets/extraction_review.js').read_text()
    page = template.replace('__SCRIPT__', script, 1).replace('__DATA__', payload, 1)
    atomic_text(folder / 'blind_review.html', page)


def export_result(result, folder):
    folder = Path(folder)
    atomic_text(folder / 'extraction.json', json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    esc = lambda value: html.escape(str(value))
    page = '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Проверка извлечения связей</title><style>body{font:16px/1.6 system-ui;max-width:1000px;margin:32px auto;padding:20px}table{border-collapse:collapse;width:100%}td,th{padding:10px;border:1px solid #ccd5df}pre{white-space:pre-wrap;word-break:break-word}</style><h1>Проверка извлечения связей</h1>'
    page += '<p>Корпус: ' + esc(result['count']) + ' текстов; срез ' + esc(result['as_of']) + '.</p>'
    if result['status'] == 'awaiting_human_labels':
        page += '<p><strong>Ожидается человеческая разметка. Precision, Recall и F1 пока не измерены.</strong></p>'
    else:
        page += '<p>Рецензент: ' + esc(result['reviewer']['name']) + '; ' + esc(result['independence']) + '. Проверено: ' + esc(result['reviewed']) + '; исключено: ' + esc(result['excluded']) + '.</p>'
        page += '<table><tr><th>Задача</th><th>TP / FP / FN</th><th>Precision</th><th>Recall</th><th>F1</th></tr>'
        for task, row in result['metrics'].items():
            show = lambda v: 'нет оценки' if v is None else f'{v:.3f}'
            page += '<tr><td>' + esc(task) + '</td><td>' + esc(f'{row["tp"]} / {row["fp"]} / {row["fn"]}') + '</td>' + ''.join('<td>' + show(row[k]) + '</td>' for k in ('precision', 'recall', 'f1')) + '</tr>'
        page += '</table><h2>Ошибки</h2><pre>' + esc(json.dumps(result['mistakes'], ensure_ascii=False, indent=2)) + '</pre>'
    page += '<p>Оценивается совпадение с разметкой на фиксированных текстах. Проверка не измеряет прогноз атак, полноту интернета или истинность источников.</p><ul>'
    page += ''.join('<li>' + esc(value) + '</li>' for value in result['limitations']) + '</ul></html>'
    atomic_text(folder / 'extraction.html', page)
    return {'directory': str(folder.resolve()), 'status': result['status'], 'reviewed': result['reviewed'], 'count': result['count']}


def assess_files(folder, output):
    folder = Path(folder)
    corpus = json.loads((folder / 'extraction_corpus.json').read_text())
    predictions = json.loads((folder / 'extraction_predictions.json').read_text())
    labels_path = folder / 'extraction_annotations.json'
    labels = json.loads(labels_path.read_text()) if labels_path.exists() else None
    return export_result(assess(corpus, predictions, labels), output)


def import_labels(path, folder=ROOT / 'evaluation', output=ROOT / 'data/processed/extraction_evaluation'):
    folder = Path(folder)
    if Path(path).stat().st_size > 3_000_000:
        raise ValueError('Файл разметки слишком большой')
    labels = json.loads(Path(path).read_text())
    corpus = json.loads((folder / 'extraction_corpus.json').read_text())
    predictions = json.loads((folder / 'extraction_predictions.json').read_text())
    result = assess(corpus, predictions, labels)
    current = folder / 'extraction_annotations.json'
    if current.exists() and current.read_bytes() != Path(path).read_bytes():
        backup = ROOT / 'data/evaluation_history' / (checksum(json.loads(current.read_text())) + '.json')
        atomic_text(backup, current.read_text())
    atomic_text(current, json.dumps(labels, ensure_ascii=False, indent=2) + '\n')
    summary = export_result(result, output)
    return {'ok': True, 'output': 'Разметка принята. Отчёт проверки извлечения готов.', **summary}
