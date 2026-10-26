"""Reproducible JSON/CSV and printable Russian report, no external assets."""
import csv
import html
import json
import os
from pathlib import Path
from .models import utcnow
from .scoring import calculate, MODEL_VERSION
from .collectors import source_status
from .config import ROOT


def csv_safe(value):
    text = str(value if value is not None else '')
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else text


def render_graph_scores(result, esc):
    from collections import Counter
    components = {'direct_signal': 'адресные сигналы', 'incident_history': 'история инцидентов',
                  'sector_activity': 'отраслевой контекст', 'product_cve': 'ПО и применимость CVE',
                  'confirmed_incident_exploitation': 'подтверждённая историческая эксплуатация (отдельно от текущей применимости)'}
    reasons = {'historical_fact_not_established': 'заявление или обвинение не устанавливает историческую эксплуатацию',
               'historical_fact_requires_review_metadata': 'неполная разметка исторической цепочки',
               'date_unknown': 'неизвестна дата основания', 'future_evidence': 'дата основания в будущем',
               'historical_context_not_current_signal': 'сообщение о прошлом инциденте или его последствиях',
               'assertion_not_confirmed': 'связь не подтверждена аналитиком',
               'signal_not_reviewed_or_refuted': 'сигнал не проверен либо опровергнут',
               'evidence_changed': 'изменился текст доказательства',
               'evidence_or_review_after_as_of': 'данные или проверка появились после даты расчёта',
               'version_outside_reported_range': 'версия вне указанного диапазона',
               'weaker_path_in_component': 'учтён более сильный путь того же компонента',
               'same_event_already_counted': 'то же событие уже учтено'}
    rows, details = [], []
    def display_score(value):
        if value is None:
            return 'недостаточно данных'
        return '<0,001' if 0 < value < .001 else f'{value:.3f}'
    for row in result['companies']:
        known = sorted(set(row['interest']['observed_components'] + row['technical']['observed_components']))
        rows.append('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in (
            row['company'], 'исследуемая компания' if row['monitor_target'] else 'исторический кейс',
            display_score(row['interest']['score']), display_score(row['technical']['score']),
            ', '.join(components[c] for c in known) or 'недостаточно данных')) + '</tr>')
        parts = []
        if any(row[d]['status'] == 'historical_evidence_only' for d in ('interest', 'technical')):
            parts.append('<p>Для одного или обоих индексов пригодны только давние основания; требуется обновление сведений.</p>')
        for path in row['paths']:
            if not path['selected']:
                continue
            edge_details = []
            for edge in path['edges']:
                metadata_warning = (' Применены значения по умолчанию: ' + ', '.join(edge['defaults_used']) + '.'
                                    if edge.get('defaults_used') else '')
                edge_details.append(f'<li>{esc(edge["subject"])} → {esc(edge["kind"])} → {esc(edge["object"])}: '
                    f'качество {edge["quality"]:.3f}; давность {esc(edge["age_days"])} дней; '
                    f'затухание {edge["decay"]:.5f}; вес {edge["weight"]:.5f}; '
                    f'режим даты: {esc(edge["temporal_policy"])}; основание даты: {esc(edge["date_basis"])}. '
                    f'{esc(metadata_warning)} '
                    f'<a href="{esc(edge["source_url"])}" rel="noreferrer">Доказательство</a>'
                    f'<blockquote>{esc(edge["excerpt"])}</blockquote></li>')
            parts.append(f'<h4>{esc(components[path["component"]])}: {path["contribution"]:.3f} балла</h4>'
                f'<p>{esc(path["context"].get("interpretation"))}</p><ul>{"".join(edge_details)}</ul>'
                f'<p>Вклад = максимум компонента {path["max_points"]} × минимальный вес звена '
                f'{min(e["weight"] for e in path["edges"]):.5f} × множитель применимости '
                f'{path["multiplier"]:.5f} = {path["contribution"]:.3f}. '
                f'Версия ПО: {esc(path["context"].get("installed_version"))}; '
                f'совпадение версии: {esc(path["context"].get("version_match"))}.</p>')
        excluded = Counter(reason for p in row['paths'] for reason in p['excluded_reasons'])
        if excluded:
            parts.append('<p>Не учтены: ' + esc('; '.join(f'{reasons.get(k,k)}: {v}' for k,v in sorted(excluded.items()))) + '.</p>')
        missing = sorted(set(row['interest']['missing_components'] + row['technical']['missing_components']))
        if missing:
            parts.append('<p>Нет пригодных оснований для компонентов: ' + esc(', '.join(components[k] for k in missing)) + '.</p>')
        details.append('<details><summary>' + esc(row['company']) + '</summary>' + ''.join(parts) + '</details>')
    return ''.join(rows), ''.join(details)


def export_report(store, output, demo=False, as_of=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    scores = calculate(store, demo, as_of)
    from .graph_scoring import calculate_graph
    graph_scores = calculate_graph(store, demo, as_of=as_of, include_historical=True)
    pubs = store.publications(demo)
    signals = store.signals(demo)
    from .knowledge import exposure_rows
    assertions = store.assertions(demo)
    exposures = exposure_rows(store, demo, as_of)
    from .threats import shared_products
    entities = store.entities(demo)
    from .attack import status as attack_status
    attack_info = attack_status(store) if not demo else {'dataset':None,'projected_counts':{},'mappings':[]}
    from .company_graph import attack_contexts
    company_context = attack_contexts(store) if not demo else []
    shared = shared_products(store, demo, as_of)
    configs = json.loads((ROOT / 'config/sources.json').read_text(encoding='utf-8'))
    source_states = source_status(store, configs, as_of)
    from .freshness import audit, evidence_day
    freshness = audit(store, configs, demo, as_of)
    cves = sorted({cve for p in pubs for cve in json.loads(p['extraction']).get('cves', [])})
    bdu_ids = sorted({bdu for p in pubs for bdu in json.loads(p['extraction']).get('bdu_ids', [])})
    hashes = {}
    for p in pubs:
        hashes.setdefault(p['content_hash'], []).append(p['id'])
    duplicates = [ids for ids in hashes.values() if len(ids) > 1]
    payload = {'generated_at': utcnow(), 'as_of': graph_scores['calculated_at'],
               'model_version': graph_scores['model_version'], 'legacy_manual_model': MODEL_VERSION,
               'is_demo': demo, 'scores': scores, 'weighted_graph': graph_scores, 'publications': pubs, 'signals': signals,
               'duplicate_clusters': duplicates, 'source_status': source_states, 'freshness': freshness, 'cves': cves,
               'assertions': assertions, 'technical_context': exposures, 'bdu_ids': bdu_ids,
               'knowledge_entities': entities, 'shared_product_context': shared, 'attack': attack_info, 'company_attack_context': company_context}
    from .research_context import build as research_build, export as research_export
    research = research_build(store, as_of) if not demo else {'as_of': graph_scores['calculated_at'], 'programs': [], 'edges': [], 'hypotheses': [], 'interpretation': 'Учебный режим'}
    payload['research_context'] = research
    research_export(research, output)
    (output / 'report.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    (output / 'graph_scores.json').write_text(json.dumps(graph_scores, ensure_ascii=False, indent=2), encoding='utf-8')
    with (output / 'graph_scores.csv').open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['company_id', 'company', 'monitor_target', 'interest_index', 'technical_exposure_index',
                         'model_version', 'weights_sha256', 'calculated_at'])
        for row in graph_scores['companies']:
            writer.writerow([csv_safe(v) for v in (row['company_id'], row['company'], row['monitor_target'],
                row['interest']['score'], row['technical']['score'], graph_scores['model_version'],
                graph_scores['weights_sha256'], graph_scores['calculated_at'])])
    with (output / 'targets.csv').open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        fields = ['company_id', 'company', 'score', 'partial_score', 'coverage', 'confidence', 'category', 'is_demo']
        writer.writerow(fields)
        for row in scores:
            writer.writerow([csv_safe(row[k]) for k in fields])
    esc = lambda s: html.escape(str(s if s is not None else 'нет данных'))
    title = 'Учебная демонстрация — все организации и события вымышлены' if demo else 'Анализ открытых сигналов об интересе к компаниям'
    case_links = []
    if not demo:
        for slug, title_text in [('novabev-2025', 'Novabev Group и ВинЛаб'),
                                 ('equifax-2017', 'Equifax: ПО, CVE и атрибуция'),
                                 ('weight-sensitivity', 'Проверка чувствительности весов')]:
            case_file = ROOT / 'docs/cases' / slug / 'case.html'
            if case_file.exists():
                case_links.append(f'<a href="{esc(os.path.relpath(case_file, output))}">{esc(title_text)}</a>')
    case_link = '<p>Аналитические материалы: ' + ' · '.join(case_links) + '.</p>' if case_links else ''
    rows = ''.join('<tr>' + ''.join('<td>' + esc(r[k]) + '</td>' for k in
                   ('company', 'score', 'coverage', 'confidence', 'category')) + '</tr>' for r in scores)
    graph_rows, graph_details = render_graph_scores(graph_scores, esc)
    viewer_link = '<p><a href="graph_view.html">Открыть общий интерактивный граф</a> · компании, ПО, CVE, бюллетени и программы bug bounty.</p>' if not demo else ''
    cards = []
    for s in signals:
        p = s['publication']
        cards.append(f'<article><h3>{esc(s["company_id"])} · {esc(s["event_type"])}</h3>'
                     f'<p>ID {esc(s["id"])}; сопоставление: {esc(s["entity_status"])}; '
                     f'событие: {esc(s["verification_status"])}.</p><blockquote>{esc(s["excerpt"])}</blockquote>'
                     f'<p><a href="{esc(p["url"])}" rel="noreferrer">Источник</a>; опубликовано '
                     f'{esc(p["published_at"])}; получено {esc(p["collected_at"])}.</p>'
                     f'<p>Проверка: {esc(s.get("review_note", "Требуется ручная проверка"))}</p></article>')
    source_rows = ''.join(f'<li>{esc(r["source_id"])}: {esc(r["status"])}; '
                          f'попытка {esc(r.get("attempted_at"))}; следующая {esc(r.get("next_allowed_at"))}'
                          f'<pre>{esc(json.dumps(r.get("details", {}), ensure_ascii=False, indent=2))}</pre></li>'
                          for r in source_states)
    publication_rows = []
    freshness_rows = ''.join('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in (
        r['name'], r['mode'], r['freshness']['status'], r['freshness']['newest_day'],
        r['freshness']['recent'], r['freshness']['stale'], r['freshness']['unknown'],
        r['freshness']['future'])) + '</tr>' for r in freshness)
    for pub in pubs:
        content = json.loads(pub['data'])
        extraction = json.loads(pub['extraction'])
        day, meaning = evidence_day(content)
        publication_rows.append('<tr>' + f'<td><a href="{esc(pub["url"])}" rel="noreferrer">{esc(content["title"])}</a></td>'
                                f'<td>{esc(pub["source_id"])}</td><td>{esc(extraction.get("event_type"))}</td>'
                                f'<td>{esc(", ".join(extraction.get("cves", []) + extraction.get("bdu_ids", [])))}</td>'
                                f'<td>{esc(content.get("metadata", {}).get("content_scope", "feed_or_import"))}</td>'
                                f'<td>{esc(day)} ({esc(meaning)})</td><td>{esc(pub["collected_at"])}</td></tr>')
    assertion_rows = ''.join('<tr>' + ''.join('<td>' + esc(a[k]) + '</td>' for k in
                              ('subject', 'kind', 'object', 'status')) +
                            f'<td><a href="{esc(a["publication"]["url"])}">Доказательство</a></td></tr>'
                            for a in assertions)
    exposure_rows_html = ''.join('<tr>' + ''.join('<td>' + esc(a[k]) + '</td>' for k in
                                  ('company_id', 'product_id', 'cve', 'installed_version', 'status')) + '</tr>'
                                for a in exposures)
    names = {e['id']: e['name'] for e in [*store.companies(), *store.products(), *entities]}
    attack_mappings = ''.join('<tr>' + ''.join('<td>' + esc(m.get(k)) + '</td>' for k in
                         ('local_name','attack_name','attack_id','effective_status','reviewer')) + '</tr>'
                         for m in attack_info['mappings'])
    attack_summary = (('Enterprise ATT&CK ' + attack_info['dataset']['version'] + '; ' +
                      ', '.join(str(v) + ' ' + k for k,v in attack_info['projected_counts'].items()))
                      if attack_info['dataset'] else 'Справочник ATT&CK ещё не импортирован')
    company_context_rows = ''.join('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in (
        names.get(row['company_id'],row['company_id']), names.get(row['incident_id'],row['incident_id']),
        names.get(row['local_entity_id'],row['local_entity_id']),row['attack_id'],row['interpretation'])) + '</tr>'
        for row in company_context)
    entity_rows = ''.join('<tr>' + ''.join('<td>' + esc(e.get(k)) + '</td>' for k in
                          ('name', 'entity_type', 'start_day', 'date_precision')) + '</tr>' for e in entities)
    from .knowledge import THREAT_KINDS
    threat_kinds = THREAT_KINDS
    threat_rows = ''.join('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in (
        names.get(a['subject'], a['subject']), a['kind'], names.get(a['object'], a['object']),
        a['status'], a['attributes'].get('basis'), a['attributes'].get('confidence'))) +
        f'<td><a href="{esc(a["publication"]["url"])}">Источник</a></td></tr>'
        for a in assertions if a['kind'] in threat_kinds)
    shared_rows = ''.join('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in (
        names.get(a['left'], a['left']), names.get(a['right'], a['right']),
        names.get(a['properties']['product_id'], a['properties']['product_id']),
        ', '.join(a['properties']['age_statuses']))) + '</tr>' for a in shared)
    explanations = ''.join('<h3>' + esc(s['company']) + '</h3><pre>' +
                           esc(json.dumps({'factors': s['factors'], 'missing': s['missing']}, ensure_ascii=False, indent=2)) +
                           '</pre>' for s in scores)
    page = f'''<!doctype html><html lang="ru"><meta charset="utf-8"><title>CTI — отчёт</title>
<style>body{{font:16px/1.5 system-ui;max-width:1100px;margin:36px auto;padding:0 24px;color:#172336}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #bbb;padding:9px;text-align:left}}
article{{border-top:1px solid #bbb;margin-top:24px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}}
blockquote{{border-left:4px solid #ccc;margin-left:0;padding-left:16px}}a{{color:#1649a1}}
@media print{{body{{margin:0;font-size:11pt}}article{{break-inside:avoid}}a{{color:inherit}}}}</style>
<h1>{esc(title)}</h1><p>Создано {esc(payload['generated_at'])}; срез {esc(payload['as_of'])}.</p>
{case_link}
<p>Задача № 1: пассивный сбор, объединение публикаций, очередь проверки и экспертный индекс.
Индекс не является вероятностью атаки. Заявления источников не являются подтверждёнными инцидентами.</p>
<p>Публикаций: {len(pubs)}; кандидатов в сигналы: {len(signals)}; кластеров точных копий: {len(duplicates)}.
Копии сохраняются как самостоятельные публикации и не считаются независимыми подтверждениями.</p>
<h2>Гипотезы для пассивной проверки</h2><p><a href="monitoring.html">Свежий бюллетень → продукт → известное использование компанией</a>. Условия применимости, неизвестные версии и закрытый контур показаны отдельно. Bug bounty служит контекстом исследований и не добавляет баллы угрозы.</p>
{viewer_link}
<h2>Оценка по весам связей графа</h2>
<p>Два экспертных индекса от 0 до 100: интерес атакующих и техническая подверженность.
Они не являются процентами вероятности атаки. Нет данных — неизвестность, а не нулевой риск.
Веса пока не проверены на прогнозной выборке. Компания с большим количеством публикаций не получает автоматическую прибавку.</p>
<p>Модель {esc(graph_scores['model_version'])}; коэффициенты: <a href="graph_scores.json">расчёт JSON</a>;
<a href="graph_scores.csv">таблица CSV</a>. Исторические кейсы обозначены отдельно; таблица не ранжирована.</p>
<table><tr><th>Компания</th><th>Охват</th><th>Интерес / 100</th><th>Техническая подверженность / 100</th>
<th>Компоненты с основаниями</th></tr>{graph_rows}</table>
<h3>Почему получились такие баллы</h3>{graph_details}
<details><summary>Дополнительный ручной индекс — совместимость с ранними данными</summary>
<table><tr><th>Компания</th><th>T / 100</th><th>Покрытие %</th>
<th>Уверенность</th><th>Категория</th></tr>{rows}</table>
<p>Пустой T означает недостаток данных. При разном наборе заполненных факторов частичные индексы не ранжируются.</p>
</details>
<h2>Состояние источников</h2><ul>{source_rows or '<li>Сетевой сбор ещё не выполнялся</li>'}</ul>
<h2>Свежесть данных</h2>
<p>Возраст считается по дате публикации или включения в каталог (catalog_added), отдельно от даты загрузки.
recent означает наличие сведений в заданном для источника окне, а не подтверждение текущего состояния компании.
stale — только старые датированные материалы; unknown — даты неизвестны; future_dates — требуется проверка дат.
Архивные записи сохраняются для исторического анализа. Даты событий и публикаций могут различаться.</p>
<table><tr><th>Источник</th><th>Режим</th><th>Свежесть</th><th>Последняя дата сведений</th>
<th>В пределах окна</th><th>Старые</th><th>Без даты</th><th>Будущие даты</th></tr>{freshness_rows}</table>
<h2>Все публикации и технический контекст</h2><p>Упомянутых CVE: {len(cves)}; BDU: {len(bdu_ids)}.
Упоминание CVE не доказывает использование продукта или уязвимость компании.</p>
<table><tr><th>Публикация</th><th>Источник</th><th>Категория</th><th>CVE / BDU</th><th>Объём сведений</th>
<th>Дата сведений и её смысл</th><th>Первая загрузка</th></tr>
{''.join(publication_rows)}</table>
<h2>Связи компаний, продуктов и уязвимостей</h2>
<table><tr><th>Откуда</th><th>Связь</th><th>Куда</th><th>Статус</th><th>Источник</th></tr>{assertion_rows}</table>
<h2>Инциденты, группировки и вредоносное ПО</h2>
<p>confirmed означает проверенное соответствие источнику. Атрибуция остаётся оценкой указанного источника;
заявление об ответственности не подтверждает взлом. Кампания не приписывает автоматически свои CVE всем пострадавшим.</p>
<table><tr><th>Название</th><th>Тип</th><th>Начало / обнаружение</th><th>Точность даты</th></tr>{entity_rows}</table>
<table><tr><th>Откуда</th><th>Связь</th><th>Куда</th><th>Проверка</th><th>Основание</th><th>Уверенность в пересказе источника</th><th>Источник</th></tr>{threat_rows}</table>
<h2>MITRE ATT&amp;CK</h2><p>{esc(attack_summary)}</p>
<p>Группировки сопоставляются отдельной проверкой. Справочные техники и инструменты не переносятся автоматически
на отдельный инцидент компании. Сохраняются STIX ID, версия набора и исходные ссылки.</p>
<table><tr><th>Локальная сущность</th><th>ATT&amp;CK</th><th>ID</th><th>Проверка</th><th>Проверяющий</th></tr>{attack_mappings}</table>
<h2>Компании и связанный контекст ATT&amp;CK</h2>
<p>Только проверенные связи пострадавшей компании с инцидентом и атрибуцией или вредоносным ПО
отбирают справочный контекст. Совпадение ПО, техники или пересечение кластеров не атрибутирует атаку.</p>
<table><tr><th>Компания</th><th>Инцидент / кампания</th><th>Группировка / вредоносное ПО</th><th>ATT&amp;CK</th><th>Интерпретация</th></tr>{company_context_rows}</table>
<h2>Общее ПО организаций</h2><p>Связи получены из проверенных утверждений об использовании продукта.
Одинаковый продукт не доказывает деловую связь, одинаковую версию или общую атаку.</p>
<table><tr><th>Организация</th><th>Организация</th><th>Общий продукт</th><th>Давность оснований</th></tr>{shared_rows}</table>
<h2>Техническая применимость — отдельно от индекса интереса</h2>
<p>Связь через продукт требует проверки версии, конфигурации и актуальности сведений.
Историческое использование не означает текущее развёртывание. Подтверждённой уязвимости компании эти данные не доказывают.</p>
<table><tr><th>Компания</th><th>Продукт</th><th>CVE / BDU</th><th>Известная версия</th><th>Состояние проверки</th></tr>
{exposure_rows_html}</table>
<h2>Карточки сигналов</h2>{''.join(cards) or '<p>Сигналы не обнаружены в собранной выборке.</p>'}
<h2>Основания оценок и неизвестные параметры</h2>{explanations}
<h2>Методика и ограничения</h2><p>T = 0,50I + 0,30S + 0,20H. Давность учитывается внутри факторов,
период полураспада по умолчанию 90 дней. I — адресные сигналы; S — отраслевой контекст;
H — сходство по географии и бизнес-модели без повторного учёта отрасли. Оценки требуют ручного обоснования.
Покрытие означает заполненность факторов, а не полноту мониторинга дарквеба. Отсутствие публикаций не доказывает безопасность.</p>
<p>Автоматизация использует правила и словарь компаний, без LLM. Возможны пропуски, неоднозначные названия,
ошибки отрицаний и зависимые источники. Используются RSS, краткие описания публичных страниц,
опубликованные JSON-уведомления и разрешённый импорт. Обхода сайтов компаний нет.
Содержимое дампов, доступы и техническая подверженность компаний не проверяются.</p>
<p>Источники и описание обработки: docs/data_sources.md. Проверка: docs/validation.md.
Методологическая основа: <a href="https://www.first.org/global/sigs/cti/curriculum/source-evaluation">FIRST</a>,
<a href="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a">CISA, DLS</a>.</p></html>'''
    (output / 'report.html').write_text(page, encoding='utf-8')
    if not demo:
        from .graph_view import export as export_graph_view
        export_graph_view(store, output, graph_scores['calculated_at'])
    store.save_scores(scores, MODEL_VERSION)
    return {'directory': str(output.resolve()), 'publications': len(pubs), 'signals': len(signals),
            'companies': len(scores), 'is_demo': demo}
