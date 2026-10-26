"""Reproducible coefficient sensitivity on an isolated current database snapshot."""
from copy import deepcopy
from contextlib import closing
import csv
import hashlib
import html
import json
import math
from pathlib import Path
import sqlite3
import tempfile

from .graph_scoring import calculate_graph, load_weights
from .models import date_iso, utcnow
from .storage import CTIStore

SCALAR_GROUPS = ('confidence', 'basis', 'signal_status', 'half_life_days', 'interest_caps')
PAIRED = ('technical_base_multiplier', 'exploitation_bonus_multiplier')


def scenarios(weights, delta=.2):
    if type(delta) not in (float, int) or not math.isfinite(delta) or not 0 < delta <= .5:
        raise ValueError('delta должен быть числом больше 0 и не больше 0.5')
    load_weights(weights)
    keys = [group + '.' + key for group in SCALAR_GROUPS for key in sorted(weights[group])]
    keys += ['unknown_version_multiplier', *PAIRED]
    results = [{'id': 'baseline', 'kind': 'baseline', 'parameter': None, 'factor': 1,
                'weights': deepcopy(weights), 'changes': {}, 'clipped': [], 'normalized': []}]

    def make(selected, factor, name, kind):
        config = deepcopy(weights)
        clipped, normalized = [], []
        for key in selected:
            if '.' in key:
                group, field = key.split('.')
                raw = weights[group][field] * factor
                low, high = (1, 36500) if group == 'half_life_days' else (0, 100) if group == 'interest_caps' else (0, 1)
                value = min(high, max(low, raw))
                config[group][field] = value
            else:
                raw = weights[key] * factor
                value = min(1, max(0, raw))
                config[key] = value
            if not math.isclose(raw, value):
                clipped.append(key)
        if any(k.startswith('interest_caps.') for k in selected):
            total = sum(config['interest_caps'].values())
            config['interest_caps'] = {k: 100 * v / total for k, v in config['interest_caps'].items()}
            normalized.append('interest_caps')
        if any(k in PAIRED for k in selected):
            total = sum(config[k] for k in PAIRED)
            for key in PAIRED:
                config[key] /= total
            normalized.append('technical_context_pair')
        load_weights(config)
        changes = {}
        for key in keys:
            if '.' in key:
                group, field = key.split('.')
                before, after = weights[group][field], config[group][field]
            else:
                before, after = weights[key], config[key]
            if not math.isclose(before, after, rel_tol=1e-12, abs_tol=1e-12):
                changes[key] = {'before': before, 'after': after,
                                'effective_change_percent': 100 * (after / before - 1) if before else None}
        return {'id': name, 'kind': kind, 'parameter': selected[0] if len(selected) == 1 else 'all',
                'factor': factor, 'weights': config, 'changes': changes,
                'clipped': clipped, 'normalized': normalized}
    for key in keys:
        for sign, factor in (('minus', 1 - delta), ('plus', 1 + delta)):
            results.append(make([key], factor, key + ':' + sign, 'one_at_a_time'))
    for sign, factor in (('minus', 1 - delta), ('plus', 1 + delta)):
        results.append(make(keys, factor, 'joint:' + sign, 'joint'))
    return results


def _fingerprint(store):
    checksum = hashlib.sha256()
    with store.connect() as db:
        for table in ('companies', 'products', 'knowledge_entities', 'publications', 'signals', 'assertions'):
            checksum.update(table.encode())
            for row in db.execute('SELECT * FROM ' + table + ' ORDER BY id'):
                checksum.update(json.dumps(dict(row), sort_keys=True, ensure_ascii=False).encode())
    return checksum.hexdigest()


def analyze(store, company_ids=None, delta=.2, as_of=None, weights_path=None, demo=False):
    weights, baseline_hash = load_weights(weights_path)
    variants = scenarios(weights, delta)
    as_of = date_iso(as_of or utcnow())
    requested = list(dict.fromkeys(company_ids or ['novabev', 'winelab', 'equifax']))
    with tempfile.TemporaryDirectory(prefix='cti-sensitivity-') as tmp:
        path = Path(tmp) / 'snapshot.sqlite3'
        with store.connect() as source, closing(sqlite3.connect(path)) as target:
            source.backup(target)
        snapshot = CTIStore(path)
        fingerprint = _fingerprint(snapshot)
        baseline = calculate_graph(snapshot, demo, as_of, weights, include_historical=True)
        available = {r['company_id']: r for r in baseline['companies']}
        if any(cid not in available for cid in requested):
            raise ValueError('Не найдены компании: ' + ', '.join(cid for cid in requested if cid not in available))
        cache = {baseline_hash: baseline}
        outputs = []
        for variant in variants:
            _, sha = load_weights(variant['weights'])
            if sha not in cache:
                cache[sha] = calculate_graph(snapshot, demo, as_of, variant['weights'], include_historical=True)
            scored = {r['company_id']: r for r in cache[sha]['companies']}
            rows = []
            for cid in requested:
                row = {'company_id': cid, 'company': scored[cid]['company'],
                       'monitor_target': scored[cid]['monitor_target']}
                for dimension in ('interest', 'technical'):
                    original, changed = available[cid][dimension], scored[cid][dimension]
                    a, b = original['score'], changed['score']
                    row[dimension] = {'score': b, 'baseline_score': a, 'status': changed['status'],
                        'absolute_change': b - a if a is not None and b is not None else None,
                        'relative_change_percent': 100 * (b / a - 1) if a not in (None, 0) and b is not None else None,
                        'selected_path_ids': changed['selected_path_ids'],
                        'selected_paths_changed': set(changed['selected_path_ids']) != set(original['selected_path_ids'])}
                rows.append(row)
            outputs.append({k: v for k, v in variant.items() if k != 'weights'} |
                           {'weights_sha256': sha, 'effective_weights': variant['weights'], 'companies': rows})
        assert _fingerprint(snapshot) == fingerprint, 'Sensitivity must not mutate its snapshot'
    summaries = []
    for cid in requested:
        row = {'company_id': cid, 'company': available[cid]['company'],
               'monitor_target': available[cid]['monitor_target']}
        for dimension in ('interest', 'technical'):
            baseline_score = available[cid][dimension]['score']
            def summarize_subset(kind):
                selected = [(s['id'], next(c for c in s['companies'] if c['company_id'] == cid)[dimension])
                            for s in outputs if s['kind'] in ('baseline', kind)]
                numeric = [(sid, d) for sid, d in selected if d['score'] is not None]
                low = min(numeric, key=lambda x: x[1]['score']) if numeric else None
                high = max(numeric, key=lambda x: x[1]['score']) if numeric else None
                return {'minimum': low[1]['score'] if low else None, 'minimum_scenario': low[0] if low else None,
                        'maximum': high[1]['score'] if high else None, 'maximum_scenario': high[0] if high else None,
                        'null_count': len(selected) - len(numeric), 'scenario_count': len(selected),
                        'path_switch_count': sum(d['selected_paths_changed'] for _, d in selected)}
            row[dimension] = {'baseline': baseline_score,
                              'one_at_a_time': summarize_subset('one_at_a_time'), 'joint': summarize_subset('joint')}
        summaries.append(row)
    return {'model_version': weights['model_version'], 'baseline_weights_sha256': baseline_hash,
            'snapshot_sha256': fingerprint, 'calculated_at': as_of, 'requested_delta': delta,
            'is_probability': False, 'method': 'one_at_a_time_and_joint', 'companies': summaries,
            'scenario_count': len(outputs), 'scenarios': outputs,
            'interpretation': 'Чувствительность экспертных индексов на одном текущем снимке; не точность прогноза и не доверительный интервал.',
            'normalization': 'Бюджеты компонентов сохраняют сумму 100, пара технических множителей — 1. Качества ограничены 0–1. Фактические изменения записаны отдельно.',
            'snapshot_note': baseline['snapshot_note']}


def export(result, output):
    from .reporting import csv_safe
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'sensitivity.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    with (output / 'sensitivity.csv').open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.writer(stream)
        writer.writerow(['scenario', 'kind', 'parameter', 'company_id', 'dimension', 'score',
                         'baseline_score', 'absolute_change', 'relative_change_percent', 'status', 'weights_sha256'])
        for scenario in result['scenarios']:
            for company in scenario['companies']:
                for dimension in ('interest', 'technical'):
                    d = company[dimension]
                    writer.writerow([csv_safe(v) for v in [scenario['id'], scenario['kind'], scenario['parameter'], company['company_id'],
                        dimension, d['score'], d['baseline_score'], d['absolute_change'], d['relative_change_percent'],
                        d['status'], scenario['weights_sha256']]])
    esc = lambda value: html.escape(str(value))
    fmt = lambda value: 'нет данных' if value is None else f'{value:.6g}'
    rows = []
    for company in result['companies']:
        for dim, label in (('interest', 'Интерес'), ('technical', 'Техническая подверженность')):
            d = company[dim]
            rows.append('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in (company['company'], label,
                fmt(d['baseline']), fmt(d['one_at_a_time']['minimum']), fmt(d['one_at_a_time']['maximum']),
                fmt(d['joint']['minimum']), fmt(d['joint']['maximum']))) + '</tr>')
    details = []
    for scenario in result['scenarios'][1:]:
        details.append('<details><summary>' + esc(scenario['id']) + '</summary><pre>' + esc(json.dumps(
            {k: scenario[k] for k in ('changes', 'clipped', 'normalized', 'companies')}, ensure_ascii=False, indent=2)) + '</pre></details>')
    page = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Проверка чувствительности весов</title>
<style>body{font:16px/1.55 system-ui;max-width:1120px;margin:32px auto;padding:0 24px;color:#1b2c43}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd5df;padding:10px;text-align:left}pre{white-space:pre-wrap;font-size:12px}details{padding:8px 0}img{max-width:100%}</style>
<h1>Проверка чувствительности весов</h1>'''
    page += f'<p>Модель {esc(result["model_version"])}; срез {esc(result["calculated_at"])}; сценариев {result["scenario_count"]}.</p>'
    page += '<p>В каждом отдельном сценарии один исходный коэффициент меняется на ±' + esc(100 * result['requested_delta']) + '%; совместные сценарии меняют все коэффициенты. После нормализации фактические изменения могут отличаться. Подробности приведены ниже.</p>'
    page += '<p>Это диапазон значений при выбранных настройках, не доверительный интервал и не вероятность атаки. Неизвестный индекс остаётся неизвестным. Novabev и ВинЛаб относятся к одному кейсу, не двум независимым наблюдениям.</p>'
    page += '<table><tr><th>Компания</th><th>Индекс</th><th>Исходный</th><th>По одному: минимум</th><th>По одному: максимум</th><th>Совместно: минимум</th><th>Совместно: максимум</th></tr>' + ''.join(rows) + '</table>'
    page += '<p>Проверка численно отделяет абсолютные баллы от относительных изменений. Большое относительное изменение почти нулевого значения не доказывает значимый рост риска. Стабильность категорий исторических кейсов не устанавливает прогнозную точность модели.</p>'
    page += '<p><a href="sensitivity.json">Все расчёты JSON</a> · <a href="sensitivity.csv">CSV</a></p>' + ''.join(details) + '</html>'
    (output / 'sensitivity.html').write_text(page, encoding='utf-8')
    return {'directory': str(output.resolve()), 'scenario_count': result['scenario_count'],
            'snapshot_sha256': result['snapshot_sha256'], 'companies': result['companies']}
