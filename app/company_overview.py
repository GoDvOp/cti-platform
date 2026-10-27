"""Directed analyst overview; every shortcut retains its evidence path."""
from collections import defaultdict
from .knowledge import scope_id, age_status
from .models import digest


def overview_rows(store, as_of=None):
    claims = [a for a in store.assertions() if a['status'] == 'confirmed']
    companies = {c['id']: c for c in store.companies() if not c.get('is_demo', False)}
    entities = {e['id']: e for e in store.entities()}
    affected, attributed = defaultdict(list), defaultdict(list)
    for claim in claims:
        if claim['kind'] == 'incident_affects':
            affected[claim['subject']].append(claim)
        elif claim['kind'] in ('attributed_to', 'claimed_by'):
            attributed[claim['subject']].append(claim)
    rows = []

    def evidence(path):
        levels = {'low': 0, 'medium': 1, 'high': 2}
        confidence = min((a['attributes'].get('confidence', 'low') for a in path), key=levels.get)
        return {'assertion_ids': sorted({a['id'] for a in path}),
                'evidence_urls': sorted({a['publication']['url'] for a in path}),
                'evidence_hashes': sorted({a['evidence_hash'] for a in path}),
                'bases': sorted({a['attributes'].get('basis', 'unspecified') for a in path}),
                'attribution_scopes': sorted({a['attributes']['attribution_scope'] for a in path
                                             if a['attributes'].get('attribution_scope')}),
                'confidence': confidence, 'status': 'source_supported'}

    def add(relation, subject_label, subject, object_label, obj, properties, existing=False,
            match_property='claim_id', match_value=None):
        rows.append({'id': 'overview:' + digest('|'.join([relation, subject, obj,
                        properties.get('incident_id', ''), properties.get('claim_id', '')]))[:24],
                     'relation': relation, 'subject_label': subject_label, 'subject': subject,
                     'object_label': object_label, 'object': obj, 'existing': existing,
                     'properties': dict(properties, company_view=True, is_demo=False),
                     'match_property': match_property,
                     'match_value': match_value if match_value is not None else properties.get('claim_id')})

    sectors = {}
    for cid, company in companies.items():
        sector = company.get('sector')
        if not sector:
            continue
        sid = scope_id('sector:' + digest(sector)[:16])
        sectors[cid] = sid
        add('INCLUDES_COMPANY', 'Sector', sid, 'Company', cid,
            {'caption': 'Включает компанию', 'status': 'catalog_context',
             'basis': 'company_catalog', 'interpretation': 'Отрасль из исследуемого каталога компаний.'})

    sector_paths = defaultdict(list)
    sector_incidents = defaultdict(set)
    sector_companies = defaultdict(set)
    participating_actors = {a['object'] for links in attributed.values() for a in links}
    for incident, victims in affected.items():
        for actor in attributed[incident]:
            if entities.get(actor['object'], {}).get('entity_type') != 'ThreatActor':
                continue
            participating_actors.add(actor['object'])
            for victim in victims:
                if victim['object'] not in companies:
                    continue
                path = [victim, actor]
                is_claim = actor['kind'] == 'claimed_by'
                relation = 'CLAIMED_ATTACK_ON' if is_claim else 'ATTRIBUTED_ATTACK_ON'
                add(relation, 'ThreatActor', scope_id(actor['object']), 'Company', victim['object'],
                    {**evidence(path), 'incident_id': incident,
                     'incident_type': entities.get(incident, {}).get('incident_type', 'unknown'),
                     'caption': 'Заявила об атаке' if is_claim else 'Атака приписана группировке',
                     'interpretation': ('Заявление об ответственности; факт участия не установлен.' if is_claim else
                         'Прямая проекция через инцидент; атрибуция остаётся оценкой или обвинением указанного источника.')})
                # Claims of responsibility do not establish observed sector targeting.
                if not is_claim and victim['object'] in sectors:
                    key = actor['object'], sectors[victim['object']]
                    sector_paths[key].extend(path)
                    sector_incidents[key].add(incident)
                    sector_companies[key].add(victim['object'])
    for (actor, sector), path in sector_paths.items():
        key = actor, sector
        add('OBSERVED_ATTACK_IN_SECTOR', 'ThreatActor', scope_id(actor), 'Sector', sector,
            {**evidence(path), 'incident_ids': sorted(sector_incidents[key]),
             'company_ids': sorted(sector_companies[key]),
             'incident_count': len(sector_incidents[key]), 'company_count': len(sector_companies[key]),
             'caption': 'Атрибуции в отрасли',
             'interpretation': 'Агрегация нашей выборки, не частота атак и не доказательство предпочтения отрасли. '
                               'Одна кампания с несколькими жертвами считается одной кампанией.'})

    for claim in claims:
        kind = claim['kind']
        if kind == 'uses_product' and claim['subject'] in companies:
            age = age_status(claim, as_of)
            if age == 'future':
                continue
            relation = {'recent': 'USES_PRODUCT', 'historical': 'USED_PRODUCT'}.get(age, 'REPORTED_USES_PRODUCT')
            add(relation, 'Company', claim['subject'], 'Product', scope_id(claim['object']),
                {'claim_id': scope_id(claim['id']), 'caption': {
                    'recent': 'Использует ПО по источнику', 'historical': 'Использовала ПО'
                }.get(age, 'Использование ПО: дата неизвестна')}, existing=True)
        elif kind == 'actor_exploits' and claim['subject'] in participating_actors:
            # Never infer exploitation from attribution to a campaign: attribution
            # can refer only to its extortion stage, not initial exploitation.
            add('REPORTED_EXPLOITS', 'ThreatActor', scope_id(claim['subject']),
                'Vulnerability', scope_id(claim['object']),
                {'claim_id': scope_id(claim['id']), 'caption': 'Эксплуатирует CVE по источнику'}, existing=True)
    # Include the original context edges instead of duplicating them as inferred
    # attacks. Only CVEs explicitly joined through a product update are expanded.
    from .research_context import build
    context = build(store, as_of)
    publication_ids = set()
    references = defaultdict(set)
    for row in context['edges']:
        properties = dict(row['properties'], view_layer='research_context')
        properties.setdefault('caption', {
            'DESCRIBES_PROGRAM': 'Описывает программу',
            'HAS_PUBLIC_BUG_BOUNTY': 'Публичная программа bug bounty',
        }.get(row['relation'], row['relation']))
        add(row['relation'], row['subject_label'], row['subject'], row['object_label'], row['object'],
            properties, existing=True, match_property='id', match_value=row['id'])
        for side in ('subject', 'object'):
            if row[side + '_label'] == 'Publication':
                publication_ids.add(row[side])
        if row['relation'] == 'SECURITY_UPDATE_FOR':
            references[row['subject']].update(row['properties'].get('reference_cves', []))
    for hypothesis in context['hypotheses']:
        for report in hypothesis.get('related_exploitation_reports', []):
            publication_ids.add(report['publication_id'])
            references[report['publication_id']].update(report['cves'])
    publications = {p['id']: p for p in store.publications()}
    from .shodan import observations, review_available
    for observation in observations(store, now=as_of, as_of=as_of):
        review = observation['association_review']
        if (not review_available(review, as_of) or review['company_id'] not in companies
                or observation['freshness'] == 'future'):
            continue
        add('HAS_TECHNICAL_OBSERVATION', 'Company', review['company_id'], 'Publication', observation['id'],
            {'caption': 'Сервис: принадлежность проверена', 'status': 'reviewed_service_association',
             'view_layer': 'technical_observation', 'weight_role': 'context_only',
             'observed_at': observation['observed_at'], 'reported_version': observation['reported_version'],
             'evidence_url': review['evidence_url'], 'reviewer': review['reviewer'],
             'reviewed_at': review['reviewed_at'], 'current_vulnerability_established': False,
             'interpretation': 'Проверена принадлежность сервиса; версия и CVE остаются сообщением Shodan.'})
        publication_ids.add(observation['id'])
    for pid, identifiers in sorted(references.items()):
        if pid not in publications:
            continue
        for cve in sorted(identifiers):
            add('MENTIONS_CVE', 'Publication', pid, 'Vulnerability', scope_id(cve),
                {'caption': 'Упоминает CVE', 'status': 'reported_reference',
                 'view_layer': 'research_context', 'weight_role': 'reference_only'},
                existing=True, match_property=None)
    for pid in sorted(publication_ids):
        if pid not in publications:
            continue
        add('PUBLISHED_BY', 'Publication', pid, 'Source', scope_id(publications[pid]['source_id']),
            {'caption': 'Опубликовано у', 'status': 'provenance_reference',
             'view_layer': 'source_context', 'weight_role': 'reference_only'},
            existing=True, match_property=None)
    return rows


def statements(store, demo=False, as_of=None):
    if demo:
        return []
    queries = [
        {'statement': 'MATCH ()-[r]->() WHERE r.cti_managed="company-overview-v1" DELETE r'},
        {'statement': 'MATCH ()-[r]->() WHERE r.company_view=true REMOVE r.company_view,r.view_layer'},
        {'statement': 'MATCH (n:CompanyGraph {is_demo:false}) REMOVE n:CompanyGraph'},
    ]
    grouped = defaultdict(list)
    for row in overview_rows(store, as_of):
        grouped[(row['subject_label'], row['relation'], row['object_label'], row['existing'], row['match_property'])].append(row)
    for (subject_label, relation, object_label, existing, match_property), rows in grouped.items():
        query = ('UNWIND $rows AS row '
                 f'MATCH (s:{subject_label} {{id:row.subject,is_demo:false}}), '
                 f'(o:{object_label} {{id:row.object,is_demo:false}}) ')
        if existing:
            query += f'MATCH (s)-[r:{relation}]->(o) '
            if match_property:
                if match_property not in ('id', 'claim_id'):
                    raise ValueError('Unsupported overview edge identity')
                query += f'WHERE r.{match_property}=row.match_value '
        else:
            query += f'MERGE (s)-[r:{relation} {{id:row.id}}]->(o) SET r.cti_managed="company-overview-v1" '
        query += 'SET r += row.properties, s:CompanyGraph, o:CompanyGraph'
        queries.append({'statement': query, 'parameters': {'rows': rows}})
    return queries
