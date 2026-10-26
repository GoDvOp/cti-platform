"""A reproducible analyst decision: a product/CVE path can reject an attack hypothesis."""
from datetime import datetime, timedelta
import html
import json
from pathlib import Path

from .graph_scoring import calculate_graph
from .graph_view import atomic_text, payload, export_payload
from .research_context import build


def analyze(store, as_of, company_id='roszarubezhneft', product_id='trueconf-server'):
    context = build(store, as_of)
    matches = [r for r in context['hypotheses'] if r['company_id'] == company_id and r['product_id'] == product_id]
    if len(matches) != 1:
        raise ValueError('Для кейса требуется одно сопоставление компании, продукта и бюллетеня')
    row = matches[0]
    claim = next(a for a in store.assertions() if a['id'] == row['use_assertion_id'])
    publications = {p['id']: p for p in store.publications()}
    roles = {claim['publication']['id']: {'software_use'}, row['notice_id']: {'selected_security_notice'}}
    for edge in context['edges']:
        if edge['object'] == 'real:' + product_id and edge['relation'] in ('SECURITY_UPDATE_FOR', 'SECURITY_NOTICE_FOR'):
            roles.setdefault(edge['subject'], set()).add(edge['relation'].lower())
    for report in row['related_exploitation_reports']:
        roles.setdefault(report['publication_id'], set()).add('general_exploitation_report')
    evidence = []
    for uid, kinds in sorted(roles.items()):
        p = publications[uid]
        data = json.loads(p['data'])
        evidence.append({'publication_id': uid, 'roles': sorted(kinds), 'url': p['url'],
                         'title': data['title'], 'published_at': p['published_at'], 'collected_at': p['collected_at'],
                         'content_hash': p['content_hash'], 'source_id': p['source_id'],
                         'metadata': data.get('metadata', {})})
    scores = calculate_graph(store, as_of=as_of, include_historical=True)
    scores['companies'] = [c for c in scores['companies'] if c['company_id'] == company_id]
    direct = [a for a in store.assertions() if a['status'] == 'confirmed'
              and a['kind'] == 'incident_affects' and a['object'] == company_id]
    until = (datetime.fromisoformat(as_of) + timedelta(days=row['horizon_days'])).date().isoformat()
    return {'case_id': 'trueconf-php-2026', 'as_of': as_of, 'horizon_end': until,
            'hypothesis': 'Проверить, достаточно ли оснований включить компанию в очередь возможных внешних целей через TrueConf Server/PHP.',
            'queue_entry': row, 'decision': row['status'],
            'named_external_target_supported': row['status'] == 'conditional_monitoring_candidate',
            'attack_established_by_this_chain': False, 'is_probability': False,
            'evidence': evidence, 'use_assertion': {'id': claim['id'], 'status': claim['status'],
                'evidence_hash': claim['evidence_hash'], 'excerpt': claim['excerpt'], 'attributes': claim['attributes']},
            'confirmed_incident_assertions_elsewhere': [a['id'] for a in direct],
            'decision_gates': {'same_product': True, 'recent_use': row['use_age_days'] is not None and row['use_age_days'] <= 180,
                               'recent_notice': row['notice_age_days'] is not None and row['notice_age_days'] <= 30,
                               'affected_installed_version': row['version_match'],
                               'network_exposure': row['network_exposure'],
                               'direct_attack_evidence_in_this_path': False},
            'scores': scores}


def export_case(result, store, folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    row = result['queue_entry']
    atomic_text(folder / 'decision.json', json.dumps({k: v for k, v in result.items() if k != 'scores'}, ensure_ascii=False, indent=2) + '\n')
    atomic_text(folder / 'evidence.json', json.dumps(result['evidence'], ensure_ascii=False, indent=2) + '\n')
    atomic_text(folder / 'score_snapshot.json', json.dumps(result['scores'], ensure_ascii=False, indent=2) + '\n')
    graph = payload(store, result['as_of'])
    evidence_ids = {p['publication_id'] for p in result['evidence']}
    product = 'real:' + row['product_id']
    ids = evidence_ids | {product, row['company_id']}
    for edge in graph['edges']:
        if edge['source'] in evidence_ids and edge['type'] in ('MENTIONS_CVE', 'PUBLISHED_BY'):
            ids.add(edge['target'])
    graph['edges'] = [e for e in graph['edges'] if e['source'] in ids and e['target'] in ids]
    endpoints = {e[k] for e in graph['edges'] for k in ('source', 'target')}
    graph['nodes'] = [n for n in graph['nodes'] if n['id'] in endpoints]
    export_payload(graph, folder)
    p = folder / 'graph_view.html'
    atomic_text(p, p.read_text().replace('<h1>Общий граф CTI</h1>', '<h1>TrueConf/PHP: основания и контраргументы</h1>'))
    atomic_text(folder / 'graph.cypher', '''// Product use, vendor update, shared CVEs and a general exploitation report.
MATCH use_path=(c:Company {id:'roszarubezhneft'})-[u:USES_PRODUCT|USED_PRODUCT]->(p:Product {id:'real:trueconf-server'}),
      update_path=(p)<-[:SECURITY_UPDATE_FOR]-(release:Publication)-[:MENTIONS_CVE]->(v:Vulnerability),
      report_path=(v)<-[:MENTIONS_CVE]-(report:Publication {source_id:'bizone_news'})
WHERE u.status='confirmed' AND report.title CONTAINS 'PHP'
RETURN use_path, update_path, report_path;
// An exploitation report about PHP is not evidence of an attack on this company.
''')
    esc = html.escape
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="340" viewBox="0 0 1000 340"><defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#526b88"/></marker></defs><rect width="1000" height="340" fill="#f7f9fc"/><g fill="#fff" stroke="#b9c9da"><rect x="20" y="75" width="210" height="85" rx="10"/><rect x="290" y="75" width="190" height="85" rx="10"/><rect x="540" y="75" width="190" height="85" rx="10"/><rect x="790" y="75" width="190" height="85" rx="10"/></g><g font-family="sans-serif" font-size="16" fill="#20314a" text-anchor="middle"><text x="125" y="110">{esc(row['company'])}</text><text x="125" y="140" font-size="13">использование по источнику</text><text x="385" y="110">TrueConf Server</text><text x="385" y="140" font-size="13">версия установки неизвестна</text><text x="635" y="110">Обновление / CVE</text><text x="635" y="140" font-size="13">публичный бюллетень</text><text x="885" y="110">Сообщение BI.ZONE</text><text x="885" y="140" font-size="13">попытки эксплуатации PHP</text></g><g stroke="#526b88" stroke-width="2" marker-end="url(#arrow)"><path d="M230,115 H285"/><path d="M540,115 H485"/><path d="M790,115 H735"/></g><g font-family="sans-serif" font-size="15" fill="#75482c"><text x="25" y="215">Контраргумент: источник описывает закрытый контур без внешнего доступа.</text><text x="25" y="250">Вывод текущего среза: внутренняя проверка обновления; внешняя цель не установлена.</text><text x="25" y="295" fill="#60738a" font-size="13">Схема — иллюстрация сохранённых связей. Полные пути, даты, хеши и оговорки доступны в evidence.json.</text></g></svg>'''
    atomic_text(folder / 'graph.svg', svg)
    table = '\n'.join('| ' + ' | '.join([e['source_id'], ', '.join(e['roles']),
                                       e['published_at'] or e['metadata'].get('publication_day') or 'дата неизвестна',
                                       '[' + e['publication_id'] + '](' + e['url'] + ')']) + ' |' for e in result['evidence'])
    text = f'''# Кейс 03. TrueConf/PHP: проверка гипотезы и контраргумент

Срез: {result['as_of']}. Горизонт наблюдения: {row['horizon_days']} дней, до {result['horizon_end']}. Это разбор условной гипотезы на сохранённых публичных данных. Он не устанавливает атаку, неустранённую уязвимость или вероятность будущего события.

## Вопрос аналитика и решение

Можно ли по свежему уведомлению TrueConf и сообщениям об эксплуатации PHP включить Росзарубежнефть в список возможных внешних целей? По текущим основаниям — нет. Очередь возвращает {result['decision']}: проверку обновления внутри организации. Установленная версия неизвестна; источник о внедрении описывает закрытый контур. Такое решение не является утверждением о безопасности компании.

Схема: компания использует продукт ← описание обновления → CVE ← общий исследовательский отчёт.

## Проверяемая цепочка

Официальный кейс TrueConf от 16.08.2026 описывает использование TrueConf Server в собственном ЦОД Росзарубежнефти. В том же источнике указан закрытый контур без внешнего доступа. Это датированное публичное утверждение разработчика о внедрении; установленная версия и современная доступность системы из него не следуют. В сохранённой базе связь проверена отдельно, её ID — {row['use_assertion_id']}.

Автоматически собранное уведомление TrueConf сообщает об исправлении PHP в Server 5.5.8. Для веток 5.4 и 5.3 источник даёт отдельные указания. Область уведомления нужно читать по веткам: из номера исправления нельзя произвольно выводить диапазон всех клиентских установок. Ручной разбор области бюллетеня и автоматическая загрузка его текста отмечены отдельно.

Журнал изменений TrueConf связывает выпуск 5.5.8 с CVE-2026-109618 и CVE-2026-109619. Этот мост между продуктом и CVE добавлен вручную по индексируемому фрагменту первоисточника; полная версия раздела напрямую не архивирована. Ограничение доступа сохранено, ручной шаг не выдаётся за автоматическую обработку.

Автоматическая новость BI.ZONE от 22.10.2026 сообщает о попытках эксплуатации этих CVE в PHP. Совпадение идентификаторов обосновывает справочную связь с обновлением продукта. Оно не устанавливает эксплуатацию TrueConf Server, атаку на Росзарубежнефть или конкретную группировку.

## Реестр оснований

| Источник | Роль | Дата основания | ID и первоисточник |
| --- | --- | --- | --- |
{table}

Полные хеши текстов, время сбора, способ получения и метаданные находятся в evidence.json. Срез совпадает с поставляемым SQLite-снимком; будущие изменения рабочей базы этот кейс не изменяют. [Интерактивный подграф](graph_view.html) раскрывает сохранённые свойства и ссылки.

## Почему гипотеза ограничена

Использование продукта сопоставлено точно: TrueConf Server не подменяется TrueConf Enterprise или клиентским приложением. Давность использования на срезе — {row['use_age_days']} дней, уведомления — {row['notice_age_days']} дней. В правилах очереди они проходят пороги 180 и 30 дней. Эти пороги экспертные, их прогнозная полезность не измерена.

Неизвестная версия не позволяет подтвердить применимость уязвимости к установке. Закрытый контур — контраргумент к гипотезе внешней доступности, а не доказательство отсутствия внутренних угроз. Общий отчёт об эксплуатации PHP не заменяет адресный сигнал о компании. Участие других организаций в bug bounty в эту цепочку угрозы не включается.

Три материала TrueConf относятся к одной группе источников и не считаются тремя независимыми подтверждениями. BI.ZONE даёт отдельное основание об эксплуатации PHP в общем, а не проверку состояния клиента. Общий технический индекс компании может учитывать другие CVE; этот балл не используется вместо условий конкретного бюллетеня и сведений о сетевой доступности.

## Что могло бы изменить решение

- Датированное официальное сообщение об актуальной версии или исправлении изменит оценку применимости. Подтверждённая исправленная версия исключит соответствующую техническую гипотезу.
- Новое официальное описание доступности и конфигурации может заменить прежнее основание о закрытом контуре. Неизвестность сама по себе не доказывает внешний доступ.
- Адресный отчёт самой организации, регулятора или исследователя может дать самостоятельное основание о событии; его нужно проверить отдельно.

Это условия будущей переоценки, а не найденные сведения о компании. Активные проверки, сканирование инфраструктуры и попытки эксплуатации не проводились.

## Как воспроизвести и оценивать полезность

Офлайн-команда scripts/review.py восстанавливает публичный снимок и пересчитывает решение. decision.json содержит исходную гипотезу, прохождение условий и ограничения; score_snapshot.json — отдельные экспертные индексы без вероятностной интерпретации; graph.cypher раскрывает путь в Neo4j. Подграф не содержит связи «атака на компанию», выведенной из соседства CVE и продукта.

Для последующего наблюдения заранее определён горизонт {row['horizon_days']} дней. Регистрируются новые публичные основания и причины изменения решения. Отсутствие сообщения об атаке не означает, что атаки не было; неизвестные исходы должны остаться неизвестными. Один такой разбор не позволяет оценить Precision@K или прогнозную точность.
'''
    atomic_text(folder / 'case.md', text)
    return {'directory': str(folder.resolve()), 'decision': result['decision'],
            'external_target_supported': result['named_external_target_supported'], 'evidence_records': len(result['evidence'])}
