"""Versioned expert index. No guessed facts and no calibrated probabilities."""
from datetime import datetime
from .models import date_iso, utcnow

MODEL_VERSION = 'target-interest-v1.1'
WEIGHTS = {'I': .50, 'S': .30, 'H': .20}


def validate_factor(factor, data):
    if factor not in WEIGHTS:
        raise ValueError('Фактор должен быть I, S или H')
    if type(data.get('score')) not in (int, float) or not 0 <= data['score'] <= 100:
        raise ValueError('score должен быть числом от 0 до 100')
    if not data.get('reason', '').strip() or not data.get('reviewer', '').strip():
        raise ValueError('Нужны reason и reviewer')
    if not isinstance(data.get('evidence_ids'), list) or not data['evidence_ids']:
        raise ValueError('Нужен непустой список evidence_ids публикаций')
    if not isinstance(data.get('evidence_hashes'), dict):
        raise ValueError('Нужен evidence_hashes: publication_id → content_hash')
    if not all(data['evidence_hashes'].get(e) for e in data['evidence_ids']):
        raise ValueError('У каждого доказательства должен быть хеш проверенной версии')
    if data.get('confidence') not in ('low', 'medium', 'high'):
        raise ValueError('confidence: low, medium или high')
    if not date_iso(data.get('observed_at')):
        raise ValueError('Нужен observed_at с часовым поясом')
    if factor == 'I' and data['score'] == 0 and not data.get('search_scope'):
        raise ValueError('Нулевой I требует описания проверенного охвата search_scope')


def calculate(store, demo=False, as_of=None, half_life=90):
    if half_life <= 0:
        raise ValueError('Период полураспада должен быть положительным')
    as_of = date_iso(as_of or utcnow())
    at = datetime.fromisoformat(as_of)
    pubs = {p['id']: p for p in store.publications(demo, as_of)}
    signals = store.signals(demo, as_of)
    results = []
    for company in store.companies():
        if bool(company.get('is_demo', False)) != demo or not company.get('monitor_target', True):
            continue
        factors, missing = {}, {}
        for key, data in store.factors(company['id']).items():
            try:
                validate_factor(key, data)
                observed = datetime.fromisoformat(date_iso(data['observed_at']))
                if observed > at or datetime.fromisoformat(data['assessed_at']) > at:
                    raise ValueError('Оценка или наблюдение появились позже даты расчёта')
                if any(e not in pubs or pubs[e]['content_hash'] != data['evidence_hashes'][e]
                       for e in data['evidence_ids']):
                    raise ValueError('Доказательство отсутствует в срезе или его текст изменился')
                if key == 'I' and data['score'] > 0:
                    reviewed = [s for s in signals if s['company_id'] == company['id']
                                and s['publication_id'] in data['evidence_ids']
                                and s['entity_status'] == 'confirmed'
                                and s['verification_status'] in ('unresolved', 'corroborated', 'confirmed')
                                and s.get('reviewed_at', as_of) <= as_of]
                    if not reviewed:
                        raise ValueError('Нет проверенного сопоставления адресного сигнала с компанией')
                age = (at - observed).total_seconds() / 86400
                # A reviewed absence of signals is not a positive signal needing decay.
                value = data['score'] * 2 ** (-age / half_life)
                factors[key] = dict(data, adjusted_score=round(value, 6), age_days=round(age, 2))
            except (ValueError, KeyError, TypeError) as exc:
                missing[key] = str(exc)
        for key in WEIGHTS:
            if key not in factors:
                missing.setdefault(key, 'Нет ручной оценки с доказательствами')
        coverage = sum(WEIGHTS[k] for k in factors)
        partial = sum(WEIGHTS[k] * f['adjusted_score'] for k, f in factors.items()) / coverage if coverage else None
        eligible = 'I' in factors and coverage >= .8
        # Partial rankings across different factor sets are not comparable.
        score = round(partial, 2) if eligible and len(factors) == 3 else None
        queue = [s['id'] for s in signals if s['company_id'] == company['id']
                 and s['entity_status'] != 'rejected' and s['verification_status'] != 'refuted']
        confidence = min((f['confidence'] for f in factors.values()),
                         key={'low': 0, 'medium': 1, 'high': 2}.get) if factors else 'low'
        results.append({'company_id': company['id'], 'company': company['name'],
                        'score': score, 'partial_score': round(partial, 2) if partial is not None else None,
                        'coverage': round(coverage * 100), 'confidence': confidence,
                        'category': ('приоритетная проверка' if score is not None and score >= 65 else
                                     'наблюдение' if score is not None else 'недостаточно данных'),
                        'factors': factors, 'missing': missing, 'review_queue': queue,
                        'calculated_at': as_of, 'model_version': MODEL_VERSION, 'is_demo': demo,
                        'half_life_days': half_life})
    results.sort(key=lambda r: (r['score'] is None, -(r['score'] or 0), r['company_id']))
    return results
