"""Incident attribution, source-scoped actor links and shared product context."""
from collections import defaultdict
from itertools import combinations
import json
from .models import Publication, digest
from .knowledge import age_status, scope_id

LABELS = ('ThreatActor', 'Incident', 'Malware')


def seed_threats(store, root, filename="threat_library.json"):
    """Reviewed source summaries, never a claim of fresh/live discovery."""
    from .collectors import ingest
    library = json.loads((root / 'examples' / filename).read_text(encoding='utf-8'))
    existing = {c['id'] for c in store.companies()}
    store.load_companies([c for c in library['companies'] if c['id'] not in existing])
    existing = {p['id'] for p in store.products()}
    store.load_products([p for p in library['products'] if p['id'] not in existing])
    existing = {e['id'] for e in store.entities()}
    store.load_entities([e for e in library['entities'] if e['id'] not in existing])
    pubs = {}
    for row in library['publications']:
        row = dict(row)
        key = row.pop('key')
        pubs[key] = Publication(**row)
    counts = ingest(store, list(pubs.values()))
    hashes = {p.id: p.content_hash for p in pubs.values()}
    previous = {a['id']: a for a in store.assertions()}
    reviewed = preserved = 0
    for row in library['claims']:
        row = dict(row)
        row['publication_id'] = pubs[row.pop('publication_key')].id
        note = row.pop('review_note')
        from .knowledge import claim_id
        identifier = claim_id(row['publication_id'], row['kind'], row['subject'], row['object'])
        old = previous.get(identifier)
        if old and old['status'] in ('confirmed', 'refuted') and old['evidence_hash'] == hashes[row['publication_id']]:
            preserved += 1
            continue
        identifier = store.add_assertion(row)
        if (old and old['status'] in ('confirmed', 'refuted') and not old.get('superseded')
                and old['attributes'] == row.get('attributes', {}) and old['excerpt'] == row['excerpt']
                and old['evidence_hash'] == hashes[row['publication_id']]):
            preserved += 1
        else:
            store.review_assertion(identifier, 'confirmed', 'assistant_source_review', note)
            reviewed += 1
    return {'counts': counts, 'library_claims': len(library['claims']), 'reviewed': reviewed,
            'existing_reviews_preserved': preserved, 'entities': len(store.entities()),
            'interpretation': 'Проверено соответствие пересказа источнику; атрибуция и заявления не становятся установленным фактом'}


def entity_statements(store, demo=False):
    queries = []
    entities = store.entities(demo)
    for label in LABELS:
        rows = []
        for entity in entities:
            if entity['entity_type'] != label:
                continue
            properties = {k: v for k, v in entity.items() if k in (
                'name', 'aliases', 'start_day', 'end_day', 'incident_type', 'date_precision', 'note')}
            rows.append({'id': scope_id(entity['id'], demo), 'catalog_id': entity['id'],
                         'properties': dict(properties, is_demo=demo)})
        queries.append({'statement': f'UNWIND $rows AS row MERGE (n:{label} {{id:row.id}}) '
                                     'SET n += row.properties,n.catalog_id=row.catalog_id',
                        'parameters': {'rows': rows}})
    # Mentions remain distinct from any causal or attribution relationship.
    queries.append({'statement': 'MATCH (:Publication {is_demo:$demo})-[r]->() '
                                 'WHERE r.cti_managed="threat-mentions-v1" DELETE r',
                    'parameters': {'demo': demo}})
    valid = {(e['entity_type'], e['id']) for e in entities}
    for label in LABELS:
        rows = [{'publication_id': p['id'], 'entity_id': scope_id(e['id'], demo)}
                for p in store.publications(demo) for e in json.loads(p['extraction']).get('entity_mentions', [])
                if (label, e['id']) in valid and e['entity_type'] == label]
        queries.append({'statement': 'UNWIND $rows AS row MATCH (p:Publication {id:row.publication_id}), '
                                     f'(n:{label} {{id:row.entity_id}}) MERGE (p)-[r:MENTIONS_ENTITY]->(n) '
                                     'SET r.status="mention_only",r.cti_managed="threat-mentions-v1",r.is_demo=$demo',
                        'parameters': {'rows': rows, 'demo': demo}})
    return queries


def shared_products(store, demo=False, as_of=None):
    groups = defaultdict(lambda: defaultdict(list))
    for a in store.assertions(demo):
        if a['kind'] == 'uses_product' and a['status'] == 'confirmed' and age_status(a, as_of) != 'future':
            groups[a['object']][a['subject']].append(a)
    rows = []
    for product, companies in sorted(groups.items()):
        for left, right in combinations(sorted(companies), 2):
            claims = companies[left] + companies[right]
            rows.append({'id': scope_id('shared:' + digest('|'.join([left, right, product]))[:24], demo),
                         'left': left, 'right': right, 'properties': {
                             'product_id': product,
                             'assertion_ids': [scope_id(a['id'], demo) for a in claims],
                             'evidence_urls': sorted({a['publication']['url'] for a in claims}),
                             'age_statuses': sorted({age_status(a, as_of) for a in claims}),
                             'status': 'shared_product_context', 'is_demo': demo,
                             'interpretation': 'Общий продукт по публикациям разных дат; версии и одновременность не установлены',
                             'cti_managed': 'knowledge-v1'}})
    return rows


def shared_product_statements(store, demo=False, as_of=None):
    return [{'statement': 'UNWIND $rows AS row MATCH (a:Company {id:row.left}),(b:Company {id:row.right}) '
                           'MERGE (a)-[r:SHARES_PRODUCT_CONTEXT {id:row.id}]->(b) SET r += row.properties',
             'parameters': {'rows': shared_products(store, demo, as_of)}}]
