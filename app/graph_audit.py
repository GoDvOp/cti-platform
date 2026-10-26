"""Compare Neo4j's projection to a fixed SQLite snapshot, including evidence and weights."""
from collections import Counter, defaultdict
import hashlib
import json
import math
import re

from .graph import statements, connection, execute_requests
from .models import utcnow

NODE_MERGE = re.compile(r'MERGE \(\w+:(\w+) \{id:row\.id\}\)')
SEMANTIC_MERGE = re.compile(r'MERGE \(s\)-\[r:(\w+) \{claim_id:row\.claim_id\}\]->\(o\)')
CONTEXT_MERGE = re.compile(r'MERGE \(s\)-\[r:(\w+) \{id:row\.id\}\]->\(o\)')


def prepare(store, as_of=None):
    at = as_of or utcnow()
    queries = statements(store, as_of=at)
    nodes, semantic, endpoints, views = defaultdict(dict), {}, set(), {}
    context = {}
    claim_weights, derived_weights, company_scores = {}, {}, {}
    for query in queries:
        code = query['statement']
        rows = query.get('parameters', {}).get('rows', [])
        match = NODE_MERGE.search(code)
        if match:
            label = match[1]
            for row in rows:
                props = {'id': row['id']}
                if label == 'Publication':
                    props.update({k: row.get(k) for k in ('content_hash', 'source_id', 'published_at')})
                elif label == 'Assertion':
                    props.update(row['properties'])
                    props.update(kind=row['kind'], attributes_json=row['attributes_json'])
                    endpoints.add((row['publication_id'], 'SUPPORTS', row['id']))
                elif label == 'BugBountyProgram':
                    props.update(row['properties'])
                nodes[label].update({row['id']: props})
        match = SEMANTIC_MERGE.search(code)
        if match:
            for row in rows:
                key = (row['subject'], match[1], row['object'], row['claim_id'])
                semantic[key] = dict(row['properties'], claim_id=row['claim_id'])
        match = CONTEXT_MERGE.search(code)
        if match:
            for row in rows:
                if row.get('properties', {}).get('cti_managed') == 'research-context-v1':
                    context[row['subject'], match[1], row['object'], row['id']] = dict(row['properties'], id=row['id'])
        if 'MERGE (a)-[:SUBJECT]->(s)' in code:
            for row in rows:
                endpoints.add((row['id'], 'SUBJECT', row['subject']))
                endpoints.add((row['id'], 'OBJECT', row['object']))
        if 'row.properties' in code and 'CompanyGraph' in code:
            for row in rows:
                key = (row['subject'], row['relation'], row['object'],
                       row.get('match_value', row['properties'].get('claim_id')) if row['existing'] else row['id'])
                views[key] = row
        if 'WHERE r.claim_id=row.claim_id' in code:
            claim_weights.update({r['claim_id']: r['properties'] for r in rows})
        elif 'r.cti_managed="company-overview-v1" SET r += row.properties' in code:
            derived_weights.update({r['id']: r['properties'] for r in rows})
        elif 'MATCH (c:Company {id:row.id}) SET c += row.properties' in code:
            company_scores.update({r['id']: r['properties'] for r in rows})
    for key, props in semantic.items():
        props.update(claim_weights.get(key[3], {}))
    for key, row in views.items():
        row['expected_properties'] = dict(row['properties'])
        if not row['existing']:
            row['expected_properties'].update(derived_weights.get(row['id'], {}))
    return {'as_of': at, 'statement_count': len(queries), 'nodes': dict(nodes), 'semantic': semantic,
            'endpoints': endpoints, 'views': views, 'company_scores': company_scores, 'context': context}


def read_live():
    base, auth = connection()
    queries = [
        {'statement': 'MATCH (n {is_demo:false}) RETURN n.id AS id,labels(n) AS labels,properties(n) AS properties'},
        {'statement': 'MATCH (s)-[r]->(o) WHERE s.is_demo=false OR o.is_demo=false '
                      'RETURN s.id AS subject,labels(s) AS subject_labels,s.is_demo AS subject_demo,'
                      'type(r) AS relation,o.id AS object,labels(o) AS object_labels,o.is_demo AS object_demo,'
                      'properties(r) AS properties'},
    ]
    response = execute_requests(base, auth, queries, 'сверка графа с SQLite')
    if len(response.get('results', [])) != 2:
        raise ValueError('Neo4j вернул неполный результат аудита')
    decoded = []
    for result in response['results']:
        columns = result.get('columns', [])
        decoded.append([dict(zip(columns, row['row'])) for row in result.get('data', [])])
    return {'nodes': decoded[0], 'relationships': decoded[1]}


def same_value(expected, actual):
    if type(expected) is bool:
        return type(actual) is bool and expected == actual
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        return type(actual) in (int, float) and math.isclose(expected, actual, rel_tol=1e-10, abs_tol=1e-12)
    return expected == actual


def audit(expected, live):
    checks, warnings = [], []

    def check(name, problems, expected_count=None, actual_count=None):
        checks.append({'name': name, 'status': 'failed' if problems else 'passed',
                       'problem_count': len(problems), 'examples': problems[:12],
                       'expected_count': expected_count, 'actual_count': actual_count})

    def differences(wanted, actual):
        return [key for key, value in wanted.items() if not same_value(value, actual.get(key))]

    nodes, edges = defaultdict(list), defaultdict(list)
    for node in live['nodes']:
        for label in node['labels']:
            nodes[label, node['id']].append(node)
    for edge in live['relationships']:
        p = edge['properties']
        identifier = p.get('claim_id') or p.get('id')
        edges[edge['subject'], edge['relation'], edge['object'], identifier].append(edge)
    problems = []
    for label, records in expected['nodes'].items():
        for uid, props in records.items():
            found = nodes.get((label, uid), [])
            if len(found) != 1:
                problems.append({'label': label, 'id': uid, 'matches': len(found)})
            elif keys := differences(props, found[0]['properties']):
                problems.append({'label': label, 'id': uid, 'mismatched_properties': keys})
        extra = sorted({uid for (actual_label, uid) in nodes if actual_label == label and uid not in records}, key=str)
        if extra:
            warnings.append({'name': 'nodes_outside_current_snapshot', 'label': label, 'count': len(extra), 'ids': extra[:12]})
    check('expected_nodes_and_evidence', problems, sum(map(len, expected['nodes'].values())), len(live['nodes']))
    problems = []
    for key, props in expected['semantic'].items():
        found = edges.get(key, [])
        if len(found) != 1:
            problems.append({'path': key, 'matches': len(found)})
        elif keys := differences(props, found[0]['properties']):
            problems.append({'path': key, 'mismatched_properties': keys})
    actual_semantic = {key: value for key, value in edges.items()
                       if any(e['properties'].get('cti_managed') == 'knowledge-v1'
                              and e['properties'].get('claim_id') for e in value)}
    for key in actual_semantic.keys() - expected['semantic'].keys():
        problems.append({'unexpected_semantic_path': key})
    check('semantic_directions_provenance_and_weights', problems, len(expected['semantic']), sum(map(len, actual_semantic.values())))
    actual_endpoints = Counter((e['subject'], e['relation'], e['object']) for e in live['relationships']
                              if e['relation'] in ('SUPPORTS', 'SUBJECT', 'OBJECT'))
    problems = [{'path': key, 'matches': actual_endpoints[key]} for key in sorted(expected['endpoints'])
                if actual_endpoints[key] != 1]
    check('assertion_source_and_endpoints', problems, len(expected['endpoints']))
    problems, actual_views = [], {}
    for key, values in edges.items():
        selected = [e for e in values if e['properties'].get('company_view') is True]
        if selected:
            actual_views[key] = selected
    for key, row in expected['views'].items():
        found = actual_views.get(key, [])
        if len(found) != 1:
            problems.append({'path': key, 'matches': len(found)})
        else:
            if keys := differences(row['expected_properties'], found[0]['properties']):
                problems.append({'path': key, 'mismatched_properties': keys})
            if row['subject_label'] not in found[0]['subject_labels'] or row['object_label'] not in found[0]['object_labels']:
                problems.append({'path': key, 'wrong_endpoint_labels': True})
    problems.extend({'unexpected_view_path': key} for key in actual_views.keys() - expected['views'].keys())
    check('company_view_exact_paths_and_qualifications', problems, len(expected['views']), sum(map(len, actual_views.values())))
    expected_view_nodes = {r[k] for r in expected['views'].values() for k in ('subject', 'object')}
    actual_view_nodes = {uid for (label, uid) in nodes if label == 'CompanyGraph'}
    check('company_view_labels', [{'missing': sorted(expected_view_nodes - actual_view_nodes)},
                                 {'unexpected': sorted(actual_view_nodes - expected_view_nodes)}]
          if actual_view_nodes != expected_view_nodes else [], len(expected_view_nodes), len(actual_view_nodes))
    problems = []
    for uid, props in expected['company_scores'].items():
        found = nodes.get(('Company', uid), [])
        if len(found) != 1:
            problems.append({'company': uid, 'matches': len(found)})
        elif keys := differences(props, found[0]['properties']):
            problems.append({'company': uid, 'mismatched_properties': keys})
    check('company_indices_match_sqlite', problems, len(expected['company_scores']))
    # Duplicate managed edges are invalid even when they are outside the overview.
    duplicate = [{'path': key, 'matches': len(values)} for key, values in edges.items()
                 if len(values) > 1 and key[3] and any(e['properties'].get('cti_managed') for e in values)]
    check('no_duplicate_managed_evidence_edges', duplicate)
    problems = []
    for key, props in expected.get('context', {}).items():
        found = edges.get(key, [])
        if len(found) != 1:
            problems.append({'path': key, 'matches': len(found)})
        elif keys := differences(props, found[0]['properties']):
            problems.append({'path': key, 'mismatched_properties': keys})
    for key, values in edges.items():
        if any(e['properties'].get('cti_managed') == 'research-context-v1' for e in values) and key not in expected.get('context', {}):
            problems.append({'unexpected_context_path': key})
    check('research_context_and_conditional_hypotheses', problems, len(expected.get('context', {})))
    cross = [{'path': (e['subject'], e['relation'], e['object'])} for e in live['relationships']
             if e['subject_demo'] is True or e['object_demo'] is True]
    check('real_demo_separation', cross)
    return {'status': 'failed' if any(c['status'] == 'failed' for c in checks) else 'passed',
            'as_of': expected['as_of'], 'checks': checks, 'warnings': warnings,
            'counts': {'nodes': len(live['nodes']), 'relationships': len(live['relationships']),
                       'overview_relationships': sum(map(len, actual_views.values()))}}


def fingerprint(live):
    normalized = {'nodes': [], 'relationships': []}
    for key, rows in live.items():
        for row in rows:
            normalized[key].append({k: sorted(v) if k.endswith('labels') else v for k, v in row.items()})
        normalized[key].sort(key=lambda r: json.dumps(r, sort_keys=True, ensure_ascii=False))
    return hashlib.sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
