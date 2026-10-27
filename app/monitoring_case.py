"""Separate, source-reviewed GitLab monitoring case; the original review corpus is untouched."""
from datetime import datetime, timedelta
import html
import json
from pathlib import Path
import re
import tempfile

from .config import ROOT
from .collectors import ingest
from .graph_scoring import calculate_graph
from .graph_view import atomic_text, payload, export_payload
from .knowledge import claim_id
from .models import Publication, date_iso, utcnow
from .research_context import build
from .review_snapshot import export_snapshot, TABLES
from .storage import CTIStore, dumps

CASE_ID = 'ispras-gitlab-2026'
BUNDLE = ROOT / 'examples/ispras_gitlab_case.json'
NOTICE_URL = 'https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/'


def _bundle(path=None):
    data = json.loads(Path(path or BUNDLE).read_text(encoding='utf-8'))
    if data.get('format') != 'cti-monitoring-case-v1' or data.get('case_id') != CASE_ID:
        raise ValueError('Неизвестный набор аналитического кейса')
    date_iso(data['AS_OF'])
    date_iso(data['source_reviewed_at'])
    return data


def seed(store, bundle_path=None):
    """Import missing facts only; a previously reviewed or superseded row always wins.

    A curated review keeps its original source-review timestamp. The import time
    is recorded separately rather than being presented as a new source review.
    """
    bundle = _bundle(bundle_path)
    company = bundle['company']
    product = bundle['product']
    if company['id'] not in {r['id'] for r in store.companies()}:
        store.load_companies([company])
    if product['id'] not in {r['id'] for r in store.products()}:
        store.load_products([product])
    with store.connect() as db:
        previous_claims = {r[0] for r in db.execute('SELECT id FROM assertions')}
        previous_pubs = {r['id']: r['content_hash'] for r in db.execute('SELECT id,content_hash FROM publications')}
    publications = {}
    for item in bundle['publications']:
        row = dict(item)
        key = row.pop('key')
        publications[key] = Publication(**row)
    missing = [p for p in publications.values() if p.id not in previous_pubs]
    counts = ingest(store, missing) if missing else {}
    added, preserved, conflicts = [], [], []
    for item in bundle['claims']:
        row = dict(item)
        publication = publications[row.pop('publication_key')]
        note = row.pop('review_note')
        row['publication_id'] = publication.id
        identifier = claim_id(publication.id, row['kind'], row['subject'], row['object'])
        if identifier in previous_claims:
            preserved.append(identifier)
            continue
        if publication.id in previous_pubs and previous_pubs[publication.id] != publication.content_hash:
            conflicts.append(identifier)
            continue
        identifier = store.add_assertion(row)
        store.review_assertion(identifier, 'confirmed', 'project_source_review', note)
        # Replaying the recorded review is distinct from reviewing it again now.
        with store.connect() as db:
            current = json.loads(db.execute('SELECT data FROM assertions WHERE id=?', (identifier,)).fetchone()[0])
            current.update(reviewed_at=bundle['source_reviewed_at'],
                           review_origin='curated_primary_source_review', imported_at=utcnow())
            db.execute('UPDATE assertions SET data=? WHERE id=?', (dumps(current), identifier))
            review_id = db.execute('SELECT MAX(id) FROM assertion_reviews WHERE assertion_id=?', (identifier,)).fetchone()[0]
            db.execute('UPDATE assertion_reviews SET reviewed_at=?,data=? WHERE id=?',
                       (bundle['source_reviewed_at'], dumps(current), review_id))
        added.append(identifier)
    return {'case_id': CASE_ID, 'AS_OF': bundle['AS_OF'], 'counts': counts,
            'added_assertions': added, 'preserved_assertions': preserved,
            'conflicting_source_assertions_skipped': conflicts,
            'provenance': bundle['provenance']}


def analyze(store, as_of=None):
    at = date_iso(as_of or utcnow())
    context = build(store, at)
    matches = [r for r in context['hypotheses'] if r['company_id'] == 'ispras'
               and r['product_id'] == 'gitlab' and r['notice_url'] == NOTICE_URL]
    assertions = [r for r in store.assertions() if not r.get('reviewed_at') or r['reviewed_at'] <= at]
    use = next((r for r in assertions if r['kind'] == 'uses_product' and r['subject'] == 'ispras'
                and r['object'] == 'gitlab' and r['status'] == 'confirmed'), None)
    affected = next((r for r in assertions if r['kind'] == 'affects_product'
                     and r['subject'] == 'CVE-2026-110264' and r['object'] == 'gitlab'
                     and r['status'] == 'confirmed' and r['publication']['url'] == NOTICE_URL), None)
    basis_valid = use is not None and affected is not None and bool(matches)
    row = matches[0] if basis_valid else None
    decision = row['status'] if row else 'insufficient_verified_basis'
    publications = {p['id']: p for p in store.publications(as_of=at)}
    roles = {'manual_ispras_lab_reference': ['organization_to_service_reference'],
             'manual_ispras_service_observation': ['dated_public_service_observation'],
             'manual_gitlab_security_notice': ['vendor_security_notice']}
    evidence = []
    for uid, p in sorted(publications.items()):
        if p['source_id'] not in roles:
            continue
        content = json.loads(p['data'])
        evidence.append({'publication_id': uid, 'roles': roles[p['source_id']],
                         'url': p['url'], 'title': content['title'], 'text': content['text'],
                         'published_at': p['published_at'], 'collected_at': p['collected_at'],
                         'content_hash': p['content_hash'], 'source_id': p['source_id'],
                         'metadata': content.get('metadata', {})})
    scores = calculate_graph(store, as_of=at, include_historical=True)
    scores['companies'] = [r for r in scores['companies'] if r['company_id'] == 'ispras']
    until = (datetime.fromisoformat(at) + timedelta(days=30)).date().isoformat()
    positive = decision == 'conditional_monitoring_candidate'
    return {'case_id': CASE_ID, 'as_of': at, 'horizon_end': until,
            'hypothesis': 'Достаточно ли свежих публичных оснований повысить приоритет проверки обновления конкретного GitLab-сервиса ИСП РАН?',
            'decision': decision, 'queue_entry': row,
            'monitoring_priority_increased': positive,
            'named_external_target_supported': False,
            'attack_established_by_this_chain': False,
            'exploitation_of_this_service_established': False,
            'is_probability': False,
            'decision_summary': ('Повысить приоритет внутренней проверки версии и обновления; это условная гипотеза мониторинга.'
                                 if positive else 'Положительное основание для текущей условной очереди отсутствует; учитывать решение и причины ниже.'),
            'decision_gates': {'verified_use': use is not None, 'verified_vendor_scope': affected is not None,
                               'recent_service_observation': bool(row and row['use_age_days'] is not None and row['use_age_days'] <= 180),
                               'recent_notice': bool(row and row['notice_age_days'] is not None and row['notice_age_days'] <= 30),
                               'affected_installed_version': row['version_match'] if row else None,
                               'public_page_observed': bool(row and row['network_exposure'] == 'internet_reported'),
                               'vulnerable_handler_reachability': None,
                               'direct_attack_evidence': False},
            'use_assertion': ({k: use[k] for k in ('id', 'status', 'excerpt', 'evidence_hash', 'attributes', 'reviewer', 'reviewed_at')}
                              if use else None),
            'evidence': evidence, 'source_groups': sorted({e['metadata'].get('independence_group', 'unknown') for e in evidence}),
            'next_actions': ['Владельцу системы: сверить фактическую версию с бюллетенем и подтвердить установку исправления.',
                             'Аналитику: отслеживать официальные сообщения о версии, обновлении и применимости CVE.',
                             'Проверять журналы по правилам разработчика только внутри своего разрешённого контура.'],
            'limitations': ['Номер установленной версии и состояние исправления неизвестны.',
                            'Обычная публичная страница не доказывает достижимость уязвимого обработчика.',
                            'Атака на институт, эксплуатация его сервиса и интерес конкретной группировки не установлены.',
                            'Описание лаборатории недатировано; дата 24.10.2026 относится к отдельному наблюдению сервиса.',
                            'Описание лаборатории и её сервис — одна группа источников, не два независимых подтверждения.',
                            'Наблюдение касается одного публичного сервиса; вывод не переносится на весь институт.',
                            'В кейсе сохранены краткие пересказы и проектная проверка; независимая экспертиза не заявляется.'],
            'scores': scores}


def _case_snapshot(store, result, destination):
    """Export only the case, including retractions, without the main 374-item snapshot."""
    publication_ids = {r['publication_id'] for r in result['evidence']}
    with tempfile.TemporaryDirectory(prefix='cti-case-snapshot-') as tmp:
        small = CTIStore(Path(tmp) / 'case.sqlite3')
        with store.connect() as source, small.connect() as target:
            targets = {'companies': ('id', ['ispras']), 'products': ('id', ['gitlab']),
                       'publications': ('id', sorted(publication_ids)),
                       'publication_versions': ('publication_id', sorted(publication_ids)),
                       'publication_metadata_updates': ('publication_id', sorted(publication_ids))}
            claim_ids = []
            for r in source.execute('SELECT id,data FROM assertions'):
                value = json.loads(r['data'])
                case_endpoint = (value.get('kind') == 'uses_product' and value.get('subject') == 'ispras'
                                 or value.get('kind') == 'affects_product' and value.get('subject') == 'CVE-2026-110264')
                if value.get('publication_id') in publication_ids and case_endpoint and value.get('object') == 'gitlab':
                    claim_ids.append(r['id'])
            targets['assertions'] = ('id', claim_ids)
            targets['assertion_reviews'] = ('assertion_id', claim_ids)
            for table in TABLES:
                if table not in targets:
                    continue
                column, values = targets[table]
                if not values:
                    continue
                columns = [r['name'] for r in source.execute('PRAGMA table_info(' + table + ')')]
                rows = source.execute('SELECT * FROM ' + table + ' WHERE ' + column + ' IN ('
                                      + ','.join('?' for _ in values) + ') ORDER BY rowid', values).fetchall()
                target.executemany('INSERT INTO ' + table + '(' + ','.join(columns) + ') VALUES ('
                                   + ','.join('?' for _ in columns) + ')', [tuple(r[c] for c in columns) for r in rows])
        return export_snapshot(small, destination, result['as_of'])


def export_case(result, store, folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    decision = {k: v for k, v in result.items() if k != 'scores'}
    atomic_text(folder / 'decision.json', json.dumps(decision, ensure_ascii=False, indent=2) + '\n')
    atomic_text(folder / 'evidence.json', json.dumps(result['evidence'], ensure_ascii=False, indent=2) + '\n')
    atomic_text(folder / 'score_snapshot.json', json.dumps(result['scores'], ensure_ascii=False, indent=2) + '\n')
    snapshot = _case_snapshot(store, result, folder / 'snapshot.json.gz')
    snapshot['file'] = 'snapshot.json.gz'
    snapshot['case_id'] = CASE_ID
    atomic_text(folder / 'snapshot_manifest.json', json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n')
    graph = payload(store, result['as_of'])
    ids = {e['publication_id'] for e in result['evidence']} | {'ispras', 'real:gitlab', 'real:CVE-2026-110264'}
    for edge in graph['edges']:
        if edge['source'] in ids and edge['type'] == 'PUBLISHED_BY':
            ids.add(edge['target'])
    graph['edges'] = [e for e in graph['edges'] if e['source'] in ids and e['target'] in ids]
    endpoints = {e[k] for e in graph['edges'] for k in ('source', 'target')}
    graph['nodes'] = [n for n in graph['nodes'] if n['id'] in endpoints]
    export_payload(graph, folder)
    atomic_text(folder / 'graph.cypher', '''// Conditional monitoring, not proof of exploitation or an unpatched service.
MATCH use_path=(c:Company {id:'ispras'})-[u:USES_PRODUCT|USED_PRODUCT]->(p:Product {id:'real:gitlab'}),
      notice_path=(p)<-[:SECURITY_NOTICE_FOR]-(n:Publication),
      cve_path=(n)-[:MENTIONS_CVE]->(v:Vulnerability {id:'real:CVE-2026-110264'})
WHERE u.status='confirmed'
RETURN use_path, notice_path, cve_path;
''')
    row = result['queue_entry'] or {}
    evidence_table = '\n'.join('| ' + ' | '.join([e['source_id'], ', '.join(e['roles']),
        e['published_at'] or e['metadata'].get('publication_day') or 'дата публикации неизвестна',
        '[' + e['publication_id'] + '](' + e['url'] + ')']) + ' |' for e in result['evidence'])
    text = f'''# Кейс 04. ИСП РАН / GitLab: положительное основание для условного мониторинга

Срез дополнительного набора: {result['as_of']}. Горизонт наблюдения — до {result['horizon_end']}. Исходный снимок на 374 публикации и корпус человеческой разметки не меняются. Кейс поставляется отдельным snapshot.json.gz и не выдаётся за часть прежнего среза.

## Вопрос и решение

{result['hypothesis']}

Решение текущего среза: {result['decision']}. {result['decision_summary']} Совпадение продукта и свежего бюллетеня даёт конкретную задачу проверки. Уязвимая версия, эксплуатация сервиса и будущая атака не установлены. Решение не означает, что институт следует объявить следующей целью.

## Проверяемая цепочка

Официальная страница лаборатории ИСП РАН перечисляет GitLab и GitLab CI/CD в своём стеке и ссылается на собственный проект Utopia EDA на gitlab.ispras.ru. Дата публикации этого описания неизвестна; сегодняшняя дата ему не присваивается.

Отдельно 24.10.2026 обычный GET публичной страницы списка проектов вернул HTTP 200. В HTML указаны realm=self-managed, deployment_type=self-managed и context_generated_at=2026-10-24T19:09:54.392Z. Это наблюдение текущего сервиса, а не сканирование, запрос версии через служебный endpoint или эксплуатация. Полный исходный HTML не сохранялся; в evidence.json приведены время наблюдения, короткий пересказ и SHA-256 полученного ответа. Хеш краткого сохранённого текста указан отдельно. Он не является хешем всей веб-страницы.

Бюллетень самого GitLab от 21.10.2026 описывает CVE-2026-110264 в CE/EE и срочные исправления для самостоятельно управляемых установок. Использование конкретного сервиса и область бюллетеня проверены раздельно. В этой цепочке нет сообщения об эксплуатации сервиса института.

## Даты, версии и источники

Давность наблюдения сервиса на срезе: {row.get('use_age_days', 'основание не подтверждено')} дней; бюллетеня: {row.get('notice_age_days', 'основание не подтверждено')} дней. Пороги очереди — 180 и 30 дней; они экспертные, прогнозная полезность не измерена. Дата наблюдения хранится как observed_day с основанием public_service_observation. У двух недатированных страниц published_at=null; для бюллетеня известен календарный день, но точное время публикации не выдумано.

| Источник | Роль | Дата публикации | ID и первоисточник |
| --- | --- | --- | --- |
{evidence_table}

Исправленные релизы перечислены по веткам: 18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3, 19.5.1. Точные диапазоны перенесены из первичного бюллетеня в метаданные. Одно общее сравнение «версия меньше 19.5.1» здесь неверно. Состояние GitLab.com и GitLab Dedicated нельзя переносить на отдельный self-managed сервис. Установленная версия остаётся неизвестной.

## Что ограничивает вывод

''' + '\n'.join('- ' + item for item in result['limitations']) + '''

Источник института и его публичный сервис относятся к одной группе ispras. Бюллетень относится к группе gitlab_vendor: это независимый издатель, но он подтверждает область уязвимости продукта, а не состояние установки института. Связь с организацией ограничена описанной лабораторией и конкретным сервисом.

## Следующее действие и условия пересмотра

''' + '\n'.join('- ' + item for item in result['next_actions']) + '''

Подтверждённая исправленная версия исключает соответствующую гипотезу. Отмена подтверждения использования или области CVE снимает доказательное основание кейса. Старое наблюдение или старый бюллетень выводят запись из текущей условной очереди. Новое официальное сообщение о событии рассматривается отдельно, без автоматического приписывания ему этой CVE.

## Воспроизведение

В отдельной базе выполнить python3 scripts/build_monitoring_case.py. Скрипт использует короткие сохранённые первичные материалы из examples/ispras_gitlab_case.json и фиксированный AS_OF. Повторный seed не перезаписывает компании, публикации и существующие проверки, в том числе отменённые. Повторный импорт — не новая ручная проверка источника: сохраняется исходное время проектной проверки и отдельно фиксируется время импорта.

Готовый дополнительный снимок можно восстановить стандартным app.review_snapshot.restore_snapshot и пересчитать app.monitoring_case.analyze на дате из snapshot_manifest.json. decision.json, evidence.json и score_snapshot.json содержат решение, происхождение и отдельные экспертные индексы. graph_view.html показывает подграф, graph.cypher — путь в Neo4j. Подграф не добавляет стрелку атаки на организацию. Контент — ручные краткие пересказы с открытыми ссылками, не автоматическая выгрузка первоисточников.
'''
    atomic_text(folder / 'case.md', text)
    blocks = []
    for block in re.split(r'\n\s*\n', text.strip()):
        escaped = html.escape(block)
        escaped = re.sub(r'\[([^]]+)\]\((https?://[^)]+)\)', r'<a href="\2" rel="noreferrer">\1</a>', escaped)
        if block.startswith('#'):
            level = len(block) - len(block.lstrip('#'))
            blocks.append(f'<h{level}>' + escaped[level:].strip() + f'</h{level}>')
        elif block.startswith('- '):
            blocks.append('<ul>' + ''.join('<li>' + html.escape(l[2:]) + '</li>' for l in block.splitlines()) + '</ul>')
        elif block.startswith('|'):
            rows = block.splitlines()
            def cells(line, tag):
                values = []
                for cell in line.strip('|').split('|'):
                    value = html.escape(cell.strip())
                    value = re.sub(r'\[([^]]+)\]\((https?://[^)]+)\)',
                                   r'<a href="\2" rel="noreferrer">\1</a>', value)
                    values.append(f'<{tag}>' + value + f'</{tag}>')
                return '<tr>' + ''.join(values) + '</tr>'
            blocks.append('<div class="table-wrap"><table>' + cells(rows[0], 'th')
                          + ''.join(cells(line, 'td') for line in rows[2:]) + '</table></div>')
        else:
            blocks.append('<p>' + escaped + '</p>')
    page = '<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ИСП РАН / GitLab — кейс 04</title><style>body{font:16px/1.65 system-ui,sans-serif;color:#20314a;background:#eef2f7;margin:0}main{max-width:1000px;margin:30px auto;background:white;padding:35px;border-radius:12px}a{color:#165e9e}h1{font-size:30px;line-height:1.25}h2{margin-top:1.8em}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7fa;padding:12px}.table-wrap{overflow:auto}table{border-collapse:collapse;font-size:13px;width:100%}td,th{border:1px solid #d6e0eb;padding:10px;vertical-align:top;text-align:left;overflow-wrap:anywhere}th{background:#f1f5fa}nav{display:flex;gap:16px;flex-wrap:wrap}@media(max-width:700px){main{margin:0;padding:20px}}@media print{body{background:white}main{margin:0;padding:0}nav{display:none}}</style><main><nav><a href="graph_view.html">Подграф</a><a href="evidence.json">Доказательства</a><a href="decision.json">Решение</a><a href="snapshot.json.gz">Отдельный снимок</a></nav>' + '\n'.join(blocks) + '</main></html>'
    atomic_text(folder / 'case.html', page)
    return {'directory': str(folder.resolve()), 'decision': result['decision'],
            'evidence_records': len(result['evidence']), 'snapshot_content_sha256': snapshot['content_sha256']}
