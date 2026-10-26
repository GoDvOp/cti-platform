"""Explainable expert graph indices. No model training or attack probabilities."""
from collections import defaultdict
from datetime import date, datetime
import hashlib
import json
import math
from pathlib import Path

from .config import ROOT
from .freshness import evidence_day
from .knowledge import version_match, scope_id
from .models import date_iso, utcnow, digest

CONFIG = ROOT / 'config/graph_weights.json'


def load_weights(path=None):
    # Internal sensitivity runs pass an isolated config; the on-disk model stays unchanged.
    data = (json.loads(json.dumps(path, allow_nan=False)) if isinstance(path, dict) else
            json.loads(Path(path or CONFIG).read_text(encoding='utf-8')))
    expected = {
        'confidence': {'high', 'medium', 'low'},
        'basis': {'victim_report', 'research_report', 'vendor_advisory', 'government_advisory',
                  'legal_allegation', 'attacker_claim', 'unspecified'},
        'signal_status': {'unresolved', 'corroborated', 'confirmed'},
        'half_life_days': {'interest', 'technical'},
        'interest_caps': {'direct_signal', 'incident_history', 'sector_activity'},
    }
    def number(value, low, high):
        return type(value) in (int, float) and math.isfinite(value) and low <= value <= high
    for key, fields in expected.items():
        values = data.get(key)
        if not isinstance(values, dict) or set(values) != fields:
            raise ValueError('Неверный набор коэффициентов: ' + key)
        low, high = ((1, 36500) if key == 'half_life_days' else
                     (0, 100) if key == 'interest_caps' else (0, 1))
        if not all(number(v, low, high) for v in values.values()):
            raise ValueError('Неверное значение коэффициента: ' + key)
    if not math.isclose(sum(data['interest_caps'].values()), 100):
        raise ValueError('Сумма interest_caps должна быть 100')
    for key in ('unknown_version_multiplier', 'technical_base_multiplier', 'exploitation_bonus_multiplier'):
        if not number(data.get(key), 0, 1):
            raise ValueError('Неверный коэффициент: ' + key)
    if not math.isclose(data['technical_base_multiplier'] + data['exploitation_bonus_multiplier'], 1):
        raise ValueError('Сумма технических множителей должна быть 1')
    if data.get('technical_cap') != 100 or not isinstance(data.get('model_version'), str) or not data['model_version']:
        raise ValueError('Нужны technical_cap=100 и model_version')
    if data.get('default_confidence') not in data['confidence']:
        raise ValueError('Неверный default_confidence')
    policies = data.get('temporal_policy', {})
    if (not isinstance(policies, dict) or
            set(policies) - {'affects_product', 'actor_exploits', 'incident_exploited', 'known_exploited'} or
            any(v not in ('decay', 'static_reference') for v in policies.values())):
        raise ValueError('Неверная temporal_policy')
    if type(data.get('include_incident_exploitation', False)) is not bool:
        raise ValueError('include_incident_exploitation должен быть boolean')
    fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return data, fingerprint


def _before(value, at):
    return not value or datetime.fromisoformat(date_iso(value)) <= at


def _edge(record, weights, at, dimension, signal=False, event_day=None, event_end_day=None,
          historical=False):
    pub = record['publication']
    content = json.loads(pub['data'])
    attrs = record.get('attributes', {})
    reference_day, published_basis = evidence_day(content)
    published_day = reference_day if published_basis == 'publication' else None
    event_reference = (event_end_day if event_end_day and event_end_day <= at.date().isoformat() else event_day)
    day = event_reference or attrs.get('observed_day')
    date_basis = ('event_end' if event_reference == event_end_day and event_end_day else 'event_start') \
        if event_reference else 'observation'
    if day:
        day = date.fromisoformat(day)
    else:
        day = reference_day
        date_basis = 'publication_proxy' if record.get('kind') == 'uses_product' else published_basis
    confidence = record.get('analyst_confidence') if signal else attrs.get('confidence')
    confidence = confidence or weights['default_confidence']
    basis = attrs.get('basis', 'unspecified')
    temporal_policy = ('static_reference' if historical else
                       weights.get('temporal_policy', {}).get(record.get('kind'), 'decay') if not signal else 'decay')
    from .review_policy import missing_metadata
    defaults = missing_metadata(attrs) if not signal else []
    warnings = ['default_' + key for key in defaults]
    if record.get('kind') == 'uses_product' and not attrs.get('observed_day'):
        warnings.append('observation_date_unknown')
    quality = weights['confidence'].get(confidence, 0)
    quality *= (weights['signal_status'].get(record.get('verification_status'), 0) if signal else
                weights['basis'].get(basis, weights['basis']['unspecified']))
    reason = None
    if (signal and (record.get('entity_status') != 'confirmed' or
                    record.get('verification_status') not in weights['signal_status'])):
        reason = 'signal_not_reviewed_or_refuted'
    elif not signal and record.get('status') != 'confirmed':
        reason = 'assertion_not_confirmed'
    elif record.get('evidence_hash') != pub['content_hash']:
        reason = 'evidence_changed'
    elif not all(_before(v, at) for v in (pub.get('collected_at'), pub.get('published_at'), record.get('reviewed_at'))):
        reason = 'evidence_or_review_after_as_of'
    elif day is None and temporal_policy != 'static_reference':
        reason = 'date_unknown'
    elif day is not None and day > at.date():
        reason = 'future_evidence'
    age = (at.date() - day).days if day else None
    decay = (1 if temporal_policy == 'static_reference' else
             2 ** (-age / weights['half_life_days'][dimension]) if age is not None and age >= 0 else 0)
    return {'id': record['id'], 'kind': record.get('event_type') if signal else record['kind'],
            'subject': record.get('company_id') if signal else record['subject'],
            'object': record.get('event_type') if signal else record['object'],
            'publication_id': pub['id'], 'source_url': pub['url'], 'evidence_hash': pub['content_hash'],
            'excerpt': record['excerpt'], 'status': record.get('verification_status') if signal else record['status'],
            'confidence': confidence, 'basis': 'reviewed_signal' if signal else basis,
            'quality': quality, 'date': day.isoformat() if day else None, 'date_basis': date_basis,
            'age_days': age, 'temporal_policy': temporal_policy,
            'decay': decay, 'weight': quality * decay if reason is None else 0,
            'defaults_used': defaults, 'warnings': warnings,
            'published_day': published_day.isoformat() if published_day else None,
            'catalog_added_day': content.get('metadata', {}).get('catalog_added_day'),
            'observed_day': attrs.get('observed_day'), 'event_start_day': event_day,
            'event_end_day': event_end_day, 'collected_at': pub.get('collected_at'),
            'reviewed_at': record.get('reviewed_at'),
            'excluded_reason': reason}


def _event_groups(claims):
    # A campaign and its explicitly linked incidents share one evidence group.
    parent = {}
    def root(key):
        parent.setdefault(key, key)
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key
    for claim in claims:
        if claim['status'] == 'confirmed' and claim['kind'] == 'incident_part_of':
            a, b = root(claim['subject']), root(claim['object'])
            parent[max(a, b)] = min(a, b)
    return root


def calculate_graph(store, demo=False, as_of=None, weights_path=None, include_historical=False):
    weights, fingerprint = load_weights(weights_path)
    at = datetime.fromisoformat(date_iso(as_of or utcnow()))
    companies = [c for c in store.companies() if bool(c.get('is_demo', False)) == demo]
    by_company = {c['id']: c for c in companies}
    entities = {e['id']: e for e in store.entities(demo)}
    claims = store.assertions(demo)
    signals = store.signals(demo)
    root = _event_groups(claims)
    incident_claims = defaultdict(list)
    publication_events = defaultdict(set)
    for claim in claims:
        if claim['kind'] == 'incident_affects':
            incident_claims[claim['subject']].append(claim)
        if claim['kind'].startswith('incident_') or claim['kind'] in ('attributed_to', 'claimed_by'):
            publication_events[claim['publication_id']].add('event:' + root(claim['subject']))
    paths = defaultdict(list)
    edges = {}

    def edge(claim, dimension, signal=False, incident=None, historical=False):
        entity = entities.get(incident, {})
        event_day = entity.get('start_day')  # Explicit event date only, never a year guessed as January 1.
        result = _edge(claim, weights, at, dimension, signal, event_day,
                       entity.get('end_day'), historical=historical)
        edges[(claim['id'], dimension)] = result
        return result

    def add(cid, dimension, component, path_edges, groups, multiplier=1, context=None, blocked=None):
        errors = [e['excluded_reason'] for e in path_edges if e['excluded_reason']]
        if blocked:
            errors.append(blocked)
        strength = min((e['weight'] for e in path_edges), default=0) * multiplier
        if strength <= 0 and not errors:
            errors.append('zero_weight')
        cap = weights['interest_caps'][component] if dimension == 'interest' else weights['technical_cap']
        item = {'id': digest('|'.join([cid, dimension, component, *[e['id'] for e in path_edges],
                                      json.dumps(context or {}, sort_keys=True)]))[:24],
                'dimension': dimension, 'component': component, 'edges': path_edges,
                'event_groups': sorted(groups), 'multiplier': multiplier,
                'strength': strength if not errors else 0, 'max_points': cap,
                'candidate_points': cap * strength if not errors else 0,
                'contribution': 0, 'selected': False, 'excluded_reasons': sorted(set(errors)),
                'context': context or {}}
        paths[cid].append(item)

    # Direct signals and historical incidents remain distinct, with shared events excluded below.
    direct_kinds = {'access_sale_claim', 'data_leak_claim', 'ransomware_claim', 'availability_claim', 'attack_claim'}
    for signal in signals:
        if signal['event_type'] not in direct_kinds:
            continue
        pub = signal['publication']
        groups = {'hash:' + pub['content_hash'], 'url:' + pub['url']}
        groups.update(publication_events[pub['id']])
        meta = json.loads(pub['data']).get('metadata', {})
        if meta.get('incident_id'):
            groups.add('event:' + root(meta['incident_id']))
        scope = meta.get('signal_scope')
        blocked = ('historical_context_not_current_signal' if scope in
                   ('historical_incident', 'recovery_update', 'business_followup') else None)
        add(signal['company_id'], 'interest', 'direct_signal',
            [edge(signal, 'interest', True, incident=meta.get('incident_id'))], groups,
            context={'signal_scope': scope,
                     'interpretation': 'Адресный сигнал; его статус указан отдельно от факта атаки.'}, blocked=blocked)
    for incident, victims in incident_claims.items():
        for victim in victims:
            group = {'event:' + root(incident), 'hash:' + victim['publication']['content_hash'],
                     'url:' + victim['publication']['url']}
            e = edge(victim, 'interest', incident=incident)
            add(victim['object'], 'interest', 'incident_history', [e], group,
                context={'incident_id': incident, 'interpretation': 'Прошлый инцидент, не прогноз повторения.'})
            sector = by_company.get(victim['object'], {}).get('sector')
            if not sector:
                continue
            # Sector context may include unattributed attacks, but not a company's own incident.
            for company in companies:
                if company.get('sector') != sector or company['id'] == victim['object']:
                    continue
                own = {root(a['subject']) for a in claims if a['kind'] == 'incident_affects'
                       and a['object'] == company['id'] and a['status'] == 'confirmed'}
                if root(incident) in own:
                    continue
                add(company['id'], 'interest', 'sector_activity', [e], group,
                    context={'incident_id': incident, 'peer_company_id': victim['object'], 'sector': sector,
                             'interpretation': 'Инцидент другой компании отрасли; предпочтение группировки не установлено.'})

    uses = [a for a in claims if a['kind'] == 'uses_product']
    affects = [a for a in claims if a['kind'] == 'affects_product']
    exploits = defaultdict(list)
    for claim in claims:
        if claim['kind'] == 'actor_exploits' or (weights.get('include_incident_exploitation', False)
                                                and claim['kind'] == 'incident_exploited'):
            exploits[claim['object']].append(claim)
    # KEV contributes exploitation context only after an explicit product/CVE assertion exists.
    kev = defaultdict(list)
    for row in store.publications(demo):
        content = json.loads(row['data'])
        if content.get('metadata', {}).get('collection_method') == 'cisa_kev_json':
            kev[content.get('external_id')].append((row, content))
    for use in uses:
        for advisory in affects:
            if use['object'] != advisory['object']:
                continue
            installed = use['attributes'].get('version')
            match = version_match(installed, advisory['attributes'])
            applicability = 1 if match is True else weights['unknown_version_multiplier']
            blocked = 'version_outside_reported_range' if match is False else None
            base_edges = [edge(use, 'technical'), edge(advisory, 'technical')]
            context = {'product_id': use['object'], 'cve': advisory['subject'], 'installed_version': installed,
                       'version_match': match,
                       'interpretation': 'Кандидат технической подверженности; конфигурация и текущее состояние не проверены.'}
            groups = {'cve:' + advisory['subject']}
            add(use['subject'], 'technical', 'product_cve', base_edges, groups,
                multiplier=applicability * weights['technical_base_multiplier'], context=context, blocked=blocked)
            for exploit in exploits[advisory['subject']]:
                # Incident exploitation is a historical fact tied to its victim,
                # not a modifier of another company's present installation.
                if exploit['kind'] == 'incident_exploited':
                    continue
                exploit_edge = edge(exploit, 'technical', incident=exploit['subject']
                                    if exploit['kind'] == 'incident_exploited' else None)
                # The exploitation bonus is one modifier, not a second independent CVE score.
                multiplier = applicability * (weights['technical_base_multiplier'] +
                    weights['exploitation_bonus_multiplier'] * exploit_edge['weight'])
                exploitation = ({'exploitation_context': 'reported_incident', 'incident_id': exploit['subject']}
                                if exploit['kind'] == 'incident_exploited' else
                                {'exploitation_context': 'reported_actor', 'actor_id': exploit['subject']})
                add(use['subject'], 'technical', 'product_cve', base_edges + [exploit_edge], groups,
                    multiplier=multiplier, context=dict(context, **exploitation), blocked=blocked)
            for row, content in kev[advisory['subject']]:
                record = {'id': 'kev:' + row['id'], 'kind': 'known_exploited', 'status': 'confirmed',
                          'subject': advisory['subject'], 'object': use['object'],
                          'publication': row, 'evidence_hash': row['content_hash'], 'excerpt': content['text'][:1000],
                          'attributes': {'basis': 'government_advisory', 'confidence': 'high',
                                         'observed_day': content['metadata']['catalog_added_day']}}
                kev_edge = edge(record, 'technical')
                kev_edge['date_basis'] = 'catalog_added'
                multiplier = applicability * (weights['technical_base_multiplier'] +
                    weights['exploitation_bonus_multiplier'] * kev_edge['weight'])
                add(use['subject'], 'technical', 'product_cve', base_edges + [kev_edge], groups,
                    multiplier=multiplier, context=dict(context, exploitation_context='CISA KEV'), blocked=blocked)

    # A separate result for an exact incident/company/product/CVE chain. It does
    # not enter current technical applicability or bypass its version checks.
    incident_products = [a for a in claims if a['kind'] == 'incident_product']
    if weights.get('include_incident_exploitation', False):
        for victim in (a for a in claims if a['kind'] == 'incident_affects'):
            incident = victim['subject']
            for product in (a for a in incident_products if a['subject'] == incident):
                for exploit in (a for a in claims if a['kind'] == 'incident_exploited' and a['subject'] == incident):
                    for advisory in (a for a in affects if a['subject'] == exploit['object'] and a['object'] == product['object']):
                        from .review_policy import missing_metadata
                        exact_chain = (victim, product, exploit, advisory)
                        fact_basis = {'victim_report', 'research_report', 'vendor_advisory', 'government_advisory'}
                        blocked = ('historical_fact_requires_review_metadata'
                                   if any(missing_metadata(a.get('attributes', {})) for a in exact_chain) else
                                   'historical_fact_not_established'
                                   if any(a['attributes']['basis'] not in fact_basis for a in exact_chain) else None)
                        add(victim['object'], 'historical_technical', 'confirmed_incident_exploitation',
                            [edge(a, 'technical', incident=incident if a['kind'].startswith('incident_') else None,
                                  historical=True) for a in exact_chain],
                            {'event:' + root(incident)}, blocked=blocked, context={
                                'incident_id': incident, 'product_id': product['object'], 'cve': exploit['object'],
                                'scope': 'historical_fact', 'current_vulnerability_established': False,
                                'interpretation': 'Подтверждение исторической цепочки эксплуатации; '
                                                  'текущее состояние установки не установлено.'})

    results = []
    for company in companies:
        if not include_historical and not company.get('monitor_target', True):
            continue
        company_paths = paths[company['id']]
        dimensions = {}
        for dimension in ('interest', 'technical', 'historical_technical'):
            candidates = [p for p in company_paths if p['dimension'] == dimension]
            occupied, selected_components = set(), set()
            # Strongest eligible contribution first; one event cannot fill two components.
            for path in sorted(candidates, key=lambda p: (-p['candidate_points'], p['id'])):
                if path['excluded_reasons']:
                    continue
                if path['component'] in selected_components:
                    path['excluded_reasons'].append('weaker_path_in_component')
                elif occupied.intersection(path['event_groups']):
                    path['excluded_reasons'].append('same_event_already_counted')
                else:
                    path['selected'] = True
                    path['contribution'] = path['candidate_points']
                    selected_components.add(path['component'])
                    occupied.update(path['event_groups'])
            selected = [p for p in candidates if p['selected']]
            caps = (weights['interest_caps'] if dimension == 'interest' else
                    {'confirmed_incident_exploitation' if dimension == 'historical_technical' else 'product_cve':
                     weights['technical_cap']})
            old_only = selected and all(any(e['temporal_policy'] == 'decay' and
                                            (e['age_days'] or 0) > 3 * weights['half_life_days'].get(dimension, 180)
                                            for e in p['edges']) for p in selected)
            dimensions[dimension] = {'score': sum(p['contribution'] for p in selected) if selected else None,
                'status': 'historical_evidence_only' if old_only else 'evidence_present' if selected else 'insufficient_data',
                'observed_components': sorted(selected_components),
                'missing_components': sorted(set(caps) - selected_components),
                'component_coverage': sum(caps[k] for k in selected_components),
                'selected_path_ids': [p['id'] for p in selected], 'candidate_paths': len(candidates),
                'interpretation': 'Индекс силы доступных оснований, не вероятность атаки. Пропуски не означают безопасность.'}
            if dimension == 'historical_technical':
                dimensions[dimension].update(
                    status='confirmed_historical_exploitation' if selected else 'insufficient_data',
                    scope='historical_fact', current_vulnerability_established=False,
                    interpretation='Сила подтверждения исторической цепочки эксплуатации. '
                                   'Не оценка текущей уязвимости, тяжести инцидента или вероятности атаки.')
        results.append({'company_id': company['id'], 'company': company['name'], 'is_demo': demo,
                        'monitor_target': company.get('monitor_target', True), **dimensions, 'paths': company_paths})
    return {'model_version': weights['model_version'], 'weights_sha256': fingerprint, 'weights': weights,
            'calculated_at': at.isoformat(), 'is_probability': False, 'aggregation': 'strongest_path_per_component',
            'snapshot_note': 'Расчёт по текущему снимку и текущим проверкам; as_of не восстанавливает прошлые версии.',
            'companies': sorted(results, key=lambda r: r['company_id'])}


def projection_statements(store, demo=False, as_of=None):
    """Expose the same coefficients and company indices in Neo4j."""
    result = calculate_graph(store, demo, as_of=as_of, include_historical=True)
    weights = result['weights']
    at = datetime.fromisoformat(result['calculated_at'])
    entities = {e['id']: e for e in store.entities(demo)}
    weighted = {}
    edge_rows = []
    for claim in store.assertions(demo):
        dimension = 'technical' if claim['kind'] in (
            'uses_product', 'affects_product', 'actor_exploits', 'incident_exploited', 'known_exploited'
        ) else 'interest'
        event_day = entities.get(claim['subject'], {}).get('start_day') if claim['kind'].startswith('incident_') or claim['kind'] in ('attributed_to', 'claimed_by') else None
        info = _edge(claim, weights, at, dimension, event_day=event_day,
                     event_end_day=entities.get(claim['subject'], {}).get('end_day') if event_day else None)
        weighted[claim['id']] = info
        edge_rows.append({'claim_id': scope_id(claim['id'], demo), 'properties': {
            'weight': info['weight'], 'weight_quality': info['quality'], 'weight_decay': info['decay'],
            'weight_age_days': info['age_days'], 'weight_date_basis': info['date_basis'],
            'weight_temporal_policy': info['temporal_policy'],
            'weight_warnings': info['warnings'],
            'weight_excluded_reason': info['excluded_reason'], 'weight_dimension': dimension,
            'weight_model': result['model_version'], 'weight_config_sha256': result['weights_sha256'],
            'weight_as_of': result['calculated_at']}})
    derived = []
    if not demo:
        from .company_overview import overview_rows
        for row in overview_rows(store, as_of):
            if row['existing']:
                continue
            ids = row['properties'].get('assertion_ids', [])
            # Taxonomy has no evidential weight and cannot imply threat interest.
            if row['relation'] == 'INCLUDES_COMPANY':
                strength, role = None, 'taxonomy_only'
            elif row['relation'] == 'OBSERVED_ATTACK_IN_SECTOR':
                strength, role = None, 'aggregate_context_only'
            else:
                strength = min((weighted[i]['weight'] for i in ids if i in weighted), default=0)
                role = 'evidence_path'
            derived.append({'id': row['id'], 'properties': {
                'weight': strength, 'weight_role': role, 'weight_model': result['model_version'],
                'weight_config_sha256': result['weights_sha256'], 'weight_as_of': result['calculated_at']}})
    node_rows = [{'id': row['company_id'], 'properties': {
        'interest_index': row['interest']['score'], 'technical_exposure_index': row['technical']['score'],
        'historical_exploitation_index': row['historical_technical']['score'],
        'interest_evidence_coverage': row['interest']['component_coverage'],
        'technical_evidence_coverage': row['technical']['component_coverage'],
        'graph_score_model': result['model_version'], 'graph_score_config_sha256': result['weights_sha256'],
        'graph_score_as_of': result['calculated_at'], 'graph_score_is_probability': False,
        'graph_score_explanation_json': json.dumps(row, ensure_ascii=False)}} for row in result['companies']]
    return [
        {'statement': 'UNWIND $rows AS row MATCH ()-[r]->() WHERE r.claim_id=row.claim_id '
                      'SET r += row.properties', 'parameters': {'rows': edge_rows}},
        {'statement': 'UNWIND $rows AS row MATCH ()-[r]->() WHERE r.id=row.id '
                      'AND r.cti_managed="company-overview-v1" SET r += row.properties',
         'parameters': {'rows': derived}},
        {'statement': 'UNWIND $rows AS row MATCH (c:Company {id:row.id}) SET c += row.properties',
         'parameters': {'rows': node_rows}},
    ]
