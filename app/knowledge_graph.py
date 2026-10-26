"""Projection of assertions and products. All semantic edges keep provenance."""
import json
from collections import defaultdict
from .knowledge import age_status, exposure_rows, scope_id, THREAT_KINDS
from .models import digest


def statements(store, demo=False, as_of=None):
    assertions = store.assertions(demo)
    companies = [c for c in store.companies() if bool(c.get('is_demo', False)) == demo]
    pubs = store.publications(demo)
    product_ids = {pid for p in pubs for pid in json.loads(p['extraction']).get('products', [])}
    product_ids.update(a['object'] for a in assertions if a['kind'] in ('uses_product', 'affects_product', 'incident_product'))
    products = [dict(p, id=scope_id(p['id'], demo), catalog_id=p['id'], is_demo=demo) for p in store.products()
                if p['id'] in product_ids and bool(p.get('is_demo', False)) == demo]
    product_mentions = [{'publication_id': p['id'], 'product_id': scope_id(pid, demo)}
                        for p in pubs for pid in json.loads(p['extraction']).get('products', [])]
    sectors, domains, sector_links, domain_links = {}, {}, [], []
    for c in companies:
        if c.get('sector'):
            key = scope_id('sector:' + digest(c['sector'])[:16], demo)
            sectors[key] = {'id': key, 'name': c['sector'], 'is_demo': demo}
            sector_links.append({'company_id': c['id'], 'id': key})
        for domain in c.get('domains', []):
            key = scope_id('domain:' + domain, demo)
            domains[key] = {'id': key, 'name': domain, 'is_demo': demo}
            domain_links.append({'company_id': c['id'], 'id': key})
    queries = [
        {'statement': 'MATCH ()-[r]->() WHERE r.cti_managed="knowledge-v1" AND r.is_demo=$demo DELETE r',
         'parameters': {'demo': demo}},
        {'statement': 'MATCH (a:Assertion {is_demo:$demo}) DETACH DELETE a', 'parameters': {'demo': demo}},
        {'statement': 'UNWIND $rows AS row MERGE (p:Product {id:row.id}) '
                      'SET p.name=row.name,p.vendor=row.vendor,p.catalog_id=row.catalog_id,p.is_demo=row.is_demo',
         'parameters': {'rows': [dict(p, vendor=p.get('vendor', 'unknown')) for p in products]}},
        {'statement': 'UNWIND $rows AS row MATCH (p:Publication {id:row.publication_id}), '
                      '(prod:Product {id:row.product_id}) MERGE (p)-[r:MENTIONS_PRODUCT]->(prod) '
                      'SET r.cti_managed="knowledge-v1",r.is_demo=$demo,r.status="mention_only"',
         'parameters': {'rows': product_mentions, 'demo': demo}},
    ]
    from .threats import entity_statements, shared_product_statements
    queries.extend(entity_statements(store, demo))
    queries.extend(shared_product_statements(store, demo, as_of))
    for label, relation, nodes, links in [('Sector', 'IN_SECTOR', sectors, sector_links),
                                         ('Domain', 'HAS_DOMAIN', domains, domain_links)]:
        queries.extend([
            {'statement': f'UNWIND $rows AS row MERGE (n:{label} {{id:row.id}}) '
                          'SET n.name=row.name,n.is_demo=row.is_demo', 'parameters': {'rows': list(nodes.values())}},
            {'statement': f'UNWIND $rows AS row MATCH (c:Company {{id:row.company_id}}), '
                          f'(n:{label} {{id:row.id}}) MERGE (c)-[r:{relation}]->(n) '
                          'SET r.status="catalog_context",r.cti_managed="knowledge-v1",r.is_demo=$demo',
             'parameters': {'rows': links, 'demo': demo}},
        ])
    assertion_nodes, semantic_edges, endpoints = [], defaultdict(list), defaultdict(list)
    company_relations = {'part_of': 'PART_OF', 'subsidiary_of': 'SUBSIDIARY_OF',
                         'supplies_to': 'SUPPLIES_TO', 'partners_with': 'PARTNERS_WITH'}
    for assertion in assertions:
        aid = scope_id(assertion['id'], demo)
        kind = assertion['kind']
        subject_label = 'Vulnerability' if kind == 'affects_product' else 'Company'
        target_label = 'Product' if kind in ('uses_product', 'affects_product') else 'Company'
        if kind in THREAT_KINDS:
            subject_label, target_label, _ = THREAT_KINDS[kind]
        subject = scope_id(assertion['subject'], demo) if subject_label != 'Company' else assertion['subject']
        obj = scope_id(assertion['object'], demo) if target_label != 'Company' else assertion['object']
        props = {'status': assertion['status'], 'evidence_url': assertion['publication']['url'],
                 'evidence_hash': assertion['evidence_hash'], 'excerpt': assertion['excerpt'],
                 'reviewer': assertion.get('reviewer'), 'review_note': assertion.get('review_note'),
                 'age_status': age_status(assertion, as_of), 'cti_managed': 'knowledge-v1', 'is_demo': demo,
                 'observed_day': assertion.get('attributes', {}).get('observed_day'),
                 'installed_version': assertion.get('attributes', {}).get('version'),
                 'confidence': assertion.get('attributes', {}).get('confidence'),
                 'basis': assertion.get('attributes', {}).get('basis'),
                 'attribution_scope': assertion.get('attributes', {}).get('attribution_scope'),
                 'network_exposure': assertion.get('attributes', {}).get('network_exposure'),
                 'network_exposure_note': assertion.get('attributes', {}).get('network_exposure_note'),
                 'interpretation': ('Проверено соответствие источнику; атрибуция остаётся оценкой источника'
                                    if kind in THREAT_KINDS else None)}
        assertion_nodes.append({'id': aid, 'kind': kind, 'publication_id': assertion['publication_id'],
                                'attributes_json': json.dumps(assertion['attributes'], ensure_ascii=False),
                                'properties': {k: v for k, v in props.items() if v is not None}})
        endpoints[(subject_label, target_label)].append({'id': aid, 'subject': subject, 'object': obj})
        if assertion['status'] == 'refuted':
            continue
        if kind == 'uses_product':
            relation = ('USES_PRODUCT' if assertion['status'] == 'confirmed' and age_status(assertion, as_of) == 'recent' else
                        'USED_PRODUCT' if assertion['status'] == 'confirmed' and age_status(assertion, as_of) == 'historical' else
                        'REPORTED_USES_PRODUCT')
        elif kind == 'affects_product':
            relation = 'AFFECTS' if assertion['status'] == 'confirmed' else 'REPORTED_AFFECTS'
        elif kind in THREAT_KINDS:
            relation = THREAT_KINDS[kind][2]
            if assertion['status'] != 'confirmed' and not relation.startswith('REPORTED_'):
                relation = 'REPORTED_' + relation
        else:
            relation = company_relations[kind]
            if assertion['status'] != 'confirmed':
                relation = 'REPORTED_' + relation
        semantic_edges[(subject_label, relation, target_label)].append(
            {'claim_id': aid, 'subject': subject, 'object': obj, 'properties': props})
    queries.append({'statement': 'UNWIND $rows AS row MATCH (p:Publication {id:row.publication_id}) '
                                'MERGE (a:Assertion {id:row.id}) SET a += row.properties, '
                                'a.kind=row.kind,a.attributes_json=row.attributes_json MERGE (p)-[:SUPPORTS]->(a)',
                    'parameters': {'rows': assertion_nodes}})
    for (subject_label, target_label), rows in endpoints.items():
        queries.append({'statement': f'UNWIND $rows AS row MATCH (a:Assertion {{id:row.id}}), '
                                     f'(s:{subject_label} {{id:row.subject}}),(o:{target_label} {{id:row.object}}) '
                                     'MERGE (a)-[:SUBJECT]->(s) MERGE (a)-[:OBJECT]->(o)',
                        'parameters': {'rows': rows}})
    for (subject_label, relation, target_label), rows in semantic_edges.items():
        queries.append({'statement': f'UNWIND $rows AS row MATCH (s:{subject_label} {{id:row.subject}}), '
                                     f'(o:{target_label} {{id:row.object}}) '
                                     f'MERGE (s)-[r:{relation} {{claim_id:row.claim_id}}]->(o) SET r += row.properties',
                        'parameters': {'rows': rows}})
    exposures = defaultdict(list)
    for row in exposure_rows(store, demo, as_of):
        if row['status'] in ('version_outside_reported_range', 'future_evidence'):
            continue
        relation = ('POTENTIALLY_AFFECTED_BY' if row['status'] == 'version_match_requires_configuration_check' else
                    'REQUIRES_VERSION_CHECK' if row['status'] in ('version_unknown', 'affected_range_unknown') else
                    'TECHNICAL_CONTEXT')
        props = {**row, 'cti_managed': 'knowledge-v1', 'is_demo': demo}
        exposures[relation].append({'company_id': row['company_id'], 'cve_id': scope_id(row['cve'], demo),
                                   'id': row['id'], 'properties': props})
    for relation, rows in exposures.items():
        queries.append({'statement': 'UNWIND $rows AS row MATCH (c:Company {id:row.company_id}), '
                                     '(v:Vulnerability {id:row.cve_id}) '
                                     f'MERGE (c)-[r:{relation} {{id:row.id}}]->(v) SET r += row.properties',
                        'parameters': {'rows': rows}})
    return queries
