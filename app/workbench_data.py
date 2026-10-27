"""Analyst queue and evidence cards, computed on a consistent read-only backup."""
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile

from .collectors import source_status
from .config import ROOT
from .freshness import evidence_day
from .graph_scoring import calculate_graph
from .models import utcnow
from .research_context import build
from .storage import CTIStore
from .workbench_control import read_json

STATUS_LABELS = {
    'conditional_monitoring_candidate': 'Проверить применимость обновления',
    'internal_patch_review': 'Проверить обновление внутри контура',
    'insufficient_current_evidence': 'Обновить сведения',
    'version_outside_reported_range': 'Версия вне области бюллетеня',
}
MISSING_LABELS = {
    'installed_version_unknown': 'Установленная версия неизвестна',
    'network_exposure_unknown': 'Доступность системы неизвестна',
    'use_date_unknown': 'Неизвестна дата использования ПО',
    'use_evidence_older_than_180_days': 'Сведения об использовании ПО старше 180 дней',
    'notice_date_unknown': 'Неизвестна дата бюллетеня',
    'notice_older_than_30_days': 'Бюллетень старше 30 дней',
}
RELATIONS = {'uses_product': 'использует ПО', 'affects_product': 'затрагивает ПО',
             'incident_affects': 'инцидент затронул', 'incident_exploited': 'в инциденте использовалась CVE',
             'attributed_to': 'атрибуция по источнику', 'part_of': 'входит в состав',
             'subsidiary_of': 'дочерняя организация', 'supplies_to': 'поставляет',
             'partners_with': 'сотрудничает', 'actor_exploits': 'эксплуатация по источнику'}


def _display_paths(row, names):
    return [{'id': p['id'], 'selected': p['selected'], 'dimension': p['dimension'],
             'component': p['component'], 'contribution': p['contribution'],
             'excluded_reasons': p['excluded_reasons'],
             'edges': [{'subject': names.get(e['subject'], e['subject']),
                        'relation': RELATIONS.get(e['kind'], e['kind']),
                        'object': names.get(e['object'], e['object']),
                        'url': e['source_url'], 'excerpt': e['excerpt'],
                        'warnings': e.get('warnings', []), 'date': e.get('date'),
                        'date_basis': e.get('date_basis'), 'age_days': e.get('age_days'),
                        'publication_id': e['publication_id']} for e in p['edges']]}
            for p in sorted(row['paths'], key=lambda p: (not p['selected'], -p['candidate_points'], p['id']))[:15]]


@contextmanager
def snapshot(database, folder):
    database = Path(database)
    if not database.is_file():
        raise ValueError('База ещё не подготовлена. Запустите проверку снимка или сборщик.')
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='read-', dir=folder) as tmp:
        target = Path(tmp) / 'snapshot.sqlite3'
        with closing(sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)) as source, \
                closing(sqlite3.connect(target)) as destination:
            source.backup(destination)
        yield CTIStore(target)


def runtime(root=ROOT, offline=False, now=None):
    folder = Path(root) / 'data/diagnostics/auto_update'
    state = read_json(folder / 'status.json')
    preferences = read_json(folder / 'preferences.json')
    fresh = False
    try:
        age = ((now or datetime.now(timezone.utc)) - datetime.fromisoformat(state['heartbeat_at'])).total_seconds()
        fresh = 0 <= age < 900 and state.get('phase') not in ('stopped', 'stopping')
    except (KeyError, ValueError, TypeError):
        pass
    mode = state.get('runtime') or ('docker' if str(state.get('database', '')).startswith('/app/') else 'desktop')
    if offline:
        mode, fresh = 'offline', False
    return {'mode': mode, 'mode_label': {'docker': 'Docker', 'desktop': 'Настольный сборщик',
                                         'offline': 'Офлайн-демонстрация'}.get(mode, mode),
            'running': fresh, 'phase': 'offline' if offline else state.get('phase', 'unknown'),
            'paused': preferences.get('paused') is True,
            'heartbeat_at': None if offline else state.get('heartbeat_at'),
            'last_graph_success': None if offline else state.get('last_graph_success'),
            'error': None if offline else state.get('last_graph_error') or state.get('last_error'),
            'controls_available': fresh and not offline, 'graph_counts': state.get('graph_counts') if not offline else None}


def _priority(score, hypotheses, signals, as_of):
    statuses = {r['status'] for r in hypotheses}
    if 'conditional_monitoring_candidate' in statuses:
        return 0, 'Проверить применимость обновления', 'Свежий бюллетень связан с подтверждённым использованием ПО.', \
            'Сверить установленную ветку и версию с бюллетенем по внутренней инвентаризации; проверить официальные сообщения об обновлении.'
    if 'internal_patch_review' in statuses:
        return 1, 'Проверить обновление внутри контура', 'Свежий бюллетень; источник описывает закрытый контур.', \
            'Проверить установленную версию и обновление внутри организации; учитывать ограничение сетевой доступности.'
    pending = []
    today = datetime.fromisoformat(as_of).date()
    for signal in signals:
        content = json.loads(signal['publication']['data'])
        day, _ = evidence_day(content)
        scope = content.get('metadata', {}).get('signal_scope')
        if (scope not in ('historical_incident', 'recovery_update', 'business_followup')
                and day is not None and 0 <= (today - day).days <= 30
                and (signal['entity_status'] == 'needs_review' or signal['verification_status'] == 'needs_review')):
            pending.append(signal)
    if pending:
        return 2, 'Проверить адресное сообщение', 'Есть непроверенное сопоставление публикации с организацией.', \
            'Проверить, относится ли сообщение к этой организации, затем сопоставить его с первоисточником и независимыми основаниями.'
    if any(score[d]['status'] == 'evidence_present' for d in ('interest', 'technical')):
        return 3, 'Рассмотреть подтверждённые основания', 'В расчёте есть проверенные пути к источникам.', \
            'Разобрать доказательные пути и ограничения применимости; зафиксировать решение и следующую дату проверки.'
    if hypotheses or any(score[d]['status'] == 'historical_evidence_only' for d in ('interest', 'technical')):
        return 4, 'Обновить сведения', 'Основания требуют проверки актуальности или области применимости.', \
            'Найти новые датированные сведения об использовании ПО и текущих версиях; сохранить неизвестные значения.'
    return 5, 'Недостаточно данных', 'Текущих проверенных оснований для приоритета нет.', \
        'Проверить охват разрешённых источников и каталог организации. Отсутствие данных не означает безопасность.'


def dashboard(store, root=ROOT, as_of=None, offline=False):
    at = as_of or utcnow()
    configs = json.loads((Path(root) / 'config/sources.json').read_text())
    source_meta = read_json(Path(root) / 'config/source_metadata.json')
    for s in configs:
        source_meta[s['id']] = {**source_meta.get(s['id'], {}), **s}
    scores = calculate_graph(store, as_of=at, include_historical=True)
    research = build(store, at)
    companies = {c['id']: c for c in store.companies() if not c.get('is_demo', False)}
    publications = {p['id']: p for p in store.publications(as_of=at)}
    claims = [c for c in store.assertions() if c['publication_id'] in publications]
    signals = store.signals(as_of=at)
    names = {k: c['name'] for k, c in companies.items()}
    names.update({p['id']: p['name'] for p in store.products()})
    names.update({e['id']: e['name'] for e in store.entities()})
    cards = []
    from .shodan import observations, review_available
    service_observations = observations(store, now=at, as_of=at)
    for row in scores['companies']:
        cid = row['company_id']
        hypotheses = [r for r in research['hypotheses'] if r['company_id'] == cid]
        company_signals = [s for s in signals if s['company_id'] == cid]
        company_claims = [c for c in claims if c['subject'] == cid or c['object'] == cid]
        evidence_ids = {c['publication_id'] for c in company_claims} | {s['publication_id'] for s in company_signals}
        for h in hypotheses:
            evidence_ids.add(h['notice_id'])
            evidence_ids.update(r['publication_id'] for r in h['related_exploitation_reports'])
        for path in row['paths']:
            evidence_ids.update(e['publication_id'] for e in path['edges'])
        by_url = {p['url']: p['id'] for p in publications.values()}
        for pid in list(evidence_ids):
            pub = publications.get(pid)
            if pub:
                supporting = json.loads(pub['data']).get('metadata', {}).get('supporting_url')
                if supporting in by_url:
                    evidence_ids.add(by_url[supporting])
        evidence = []
        important = {h['notice_id'] for h in hypotheses}
        important.update(c['publication_id'] for c in company_claims
                         if any(h['use_assertion_id'] == c['id'] for h in hypotheses))
        important.update(e['publication_id'] for p in row['paths'] if p['selected'] for e in p['edges'])
        for pid in sorted(evidence_ids):
            pub = publications.get(pid)
            if pub is None:
                continue
            data = json.loads(pub['data'])
            meta = data.get('metadata', {})
            day, date_basis = evidence_day(data)
            publisher = source_meta.get(pub['source_id'], {})
            evidence.append({'id': pid, 'title': data['title'], 'url': pub['url'],
                'source_id': pub['source_id'], 'publisher': publisher.get('name') or meta.get('source_publisher') or pub['source_id'],
                'independence_group': publisher.get('independence_group') or meta.get('independence_group') or 'unknown',
                'published_at': pub['published_at'], 'evidence_day': day.isoformat() if day else None,
                'publication_day': meta.get('publication_day'),
                'date_basis': date_basis, 'observed_at': meta.get('observed_at'),
                'collected_at': pub['collected_at'], 'content_hash': pub['content_hash'],
                'text': data['text'], 'content_scope': meta.get('content_scope', 'feed_or_import'),
                'collection_method': meta.get('collection_method') or meta.get('import_method') or 'not_recorded'})
        evidence.sort(key=lambda e: (e['id'] not in important, e['id']))
        priority, label, reason, next_action = _priority(row, hypotheses, company_signals, at)
        missing = sorted({MISSING_LABELS.get(m, m) for h in hypotheses for m in h['missing']})
        counter = sorted({h['counterevidence'] for h in hypotheses if h.get('counterevidence')})
        if not row['monitor_target']:
            priority, label = 6, 'Исторический кейс'
            next_action = 'Использовать для разбора методики. В текущую очередь целей этот кейс не включается.'
        example = None
        if cid == 'equifax' and not row['monitor_target']:
            from .historical_example import calculate_example
            reconstruction = calculate_example(store)
            if reconstruction:
                reconstruction['paths'] = _display_paths(reconstruction, names)
            example = {
                'title': 'Исторический пример · Equifax, 2017',
                'case_url': '/cases/equifax-2017/case.html',
                'summary': 'Подтверждённый исторический инцидент даёт основание для индекса интереса. '
                           'Связи с Apache Struts 2 и CVE-2017-5638 показывают технический контекст.',
                'score_note': 'Учебный расчёт на 15.09.2017 — дату публикации подробностей инцидента. '
                              'Источники собраны и проверены позднее: это учебная реконструкция, а не прогноз атаки '
                              'или подтверждённый результат работы системы в 2017 году. '
                              'Технический балл здесь показывает подтверждение исторической цепочки, '
                              'отдельно от текущей применимости CVE.',
                'limitations': 'Точная установленная версия неизвестна. Исторические сведения '
                               'не устанавливают состояние инфраструктуры сегодня.',
                'reconstruction': reconstruction,
            }
            label = 'Исторический пример'
            reason = example['summary']
            next_action = ('Сопоставить оба индекса с учтёнными путями и первоисточниками; '
                           'затем открыть полный исторический разбор.')
        paths = _display_paths(row, names)
        from .review_policy import missing_metadata
        relations = [{'id': c['id'], 'subject': names.get(c['subject'], c['subject']),
                      'relation': RELATIONS.get(c['kind'], c['kind']),
                      'object': names.get(c['object'], c['object']), 'status': c['status'],
                      'reviewer': c.get('reviewer'), 'reviewed_at': c.get('reviewed_at'),
                      'review_warnings': ['default_' + key for key in missing_metadata(c.get('attributes', {}))]
                                         if c['status'] == 'confirmed' else [],
                      'excerpt': c['excerpt'], 'publication_id': c['publication_id'],
                      'url': c['publication']['url']} for c in company_claims]
        cards.append({'id': cid, 'name': row['company'], 'sector': companies[cid].get('sector', 'не указан'),
            'monitor_target': row['monitor_target'], 'example': example, 'priority': priority, 'decision_label': label,
            'priority_reason': reason, 'next_action': next_action, 'interest': row['interest'],
            'technical': row['technical'], 'historical_technical': row['historical_technical'],
            'hypotheses': hypotheses, 'missing': missing,
            'technical_observations': [o for o in service_observations
                                      if review_available(o['association_review'], at)
                                      and o['association_review']['company_id'] == cid
                                      and o['freshness'] != 'future'],
            'counterevidence': counter, 'evidence': evidence, 'relations': relations, 'paths': paths,
            'signals': [{'id': s['id'], 'event_type': s['event_type'], 'entity_status': s['entity_status'],
                         'verification_status': s['verification_status'], 'excerpt': s['excerpt'],
                         'url': s['publication']['url']} for s in company_signals]})
    cards.sort(key=lambda c: (c['priority'], c['name'].casefold()))
    states = source_status(store, configs, as_of=at)
    sources = []
    for s in states:
        # The operational list contains current collectors; historical provenance
        # remains available through publication evidence and the source audit.
        if not s.get('enabled', False):
            continue
        freshness = s.get('freshness', {})
        sources.append({'id': s['source_id'], 'name': source_meta.get(s['source_id'], {}).get('name', s['source_id']),
            'enabled': s.get('enabled', False), 'status': s.get('status'), 'attempted_at': s.get('attempted_at'),
            'next_allowed_at': s.get('next_allowed_at'), 'disabled_reason': s.get('disabled_reason'),
            'error': s.get('details', {}).get('message') if isinstance(s.get('details'), dict) else None,
            'error_code': s.get('details', {}).get('error_code') if isinstance(s.get('details'), dict) else None,
            'freshness': freshness})
    current = runtime(root, offline)
    return {'as_of': at, 'generated_at': utcnow(), 'offline': offline, 'runtime': current,
            'model': scores['model_version'], 'is_probability': False, 'companies': cards, 'sources': sources,
            'counts': {'publications': len(publications), 'companies': sum(c['monitor_target'] for c in cards),
                       'assertions': len(claims), 'review_queue': sum(c['monitor_target'] and c['priority'] <= 2 for c in cards),
                       'sources_enabled': sum(s['enabled'] for s in sources),
                       'sources_error': sum(s['enabled'] and s['status'] in ('error', 'partial') for s in sources)},
            'review': {'url': '/review', 'result_url': '/review-result',
                       'status': read_json(Path(root) / 'data/processed/extraction_evaluation/extraction.json').get('status', 'awaiting_human_labels')}}
