"""An offline interactive view of exactly the analyst overview projected to Neo4j."""
import hashlib
import json
from pathlib import Path
import tempfile

from .config import ROOT
from .graph_scoring import calculate_graph
from .knowledge import scope_id
from .models import digest, utcnow
from .research_context import build


def atomic_text(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(value)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def payload(store, as_of=None, status=None):
    from .graph_audit import prepare
    at = as_of or utcnow()
    nodes = {}
    def node(uid, label, name, **properties):
        nodes[uid] = {'id': uid, 'type': label, 'name': name, 'properties': properties}
    scores = {r['company_id']: r for r in calculate_graph(store, as_of=at, include_historical=True)['companies']}
    for c in store.companies():
        if c.get('is_demo', False):
            continue
        score = scores[c['id']]
        node(c['id'], 'Company', c['name'], sector=c.get('sector'),
             interest_index=score['interest']['score'], technical_index=score['technical']['score'],
             interest_status=score['interest']['status'], technical_status=score['technical']['status'])
        if c.get('sector'):
            node(scope_id('sector:' + digest(c['sector'])[:16]), 'Sector', c['sector'])
    for p in store.products():
        if not p.get('is_demo', False):
            node(scope_id(p['id']), 'Product', p['name'], vendor=p.get('vendor'))
    for e in store.entities():
        node(scope_id(e['id']), e['entity_type'], e['name'])
    configs = json.loads((ROOT / 'config/source_metadata.json').read_text())
    configs.update({s['id']: s for s in json.loads((ROOT / 'config/sources.json').read_text())})
    for p in store.publications():
        data = json.loads(p['data'])
        node(p['id'], 'Publication', data['title'], url=p['url'], published_at=p['published_at'],
             collected_at=p['collected_at'], content_hash=p['content_hash'],
             collection_method=data.get('metadata', {}).get('collection_method'),
             verification_method=data.get('metadata', {}).get('verification_method'))
        config = configs.get(p['source_id'], {})
        node(scope_id(p['source_id']), 'Source', config.get('name', p['source_id']),
             url=config.get('reference_url') or config.get('url'), source_id=p['source_id'])
        extraction = json.loads(p['extraction'])
        for identifier in extraction.get('cves', []) + extraction.get('bdu_ids', []):
            node(scope_id(identifier), 'Vulnerability', identifier)
    for p in build(store, at)['programs']:
        properties = dict(p['properties'])
        name = properties.pop('name')
        node(p['id'], 'BugBountyProgram', name, **properties)
    edges = []
    projection = prepare(store, at)
    for key, r in projection['views'].items():
        if r['subject'] not in nodes or r['object'] not in nodes:
            raise ValueError('Не найден конец обзорной связи: ' + r['relation'])
        identity = r['match_value'] if r['existing'] else r['id']
        uid = hashlib.sha256(json.dumps([r['subject'], r['relation'], r['object'], identity]).encode()).hexdigest()[:24]
        properties = dict(projection['semantic'].get(key, projection['context'].get(key, {})))
        properties.update(r['expected_properties'])
        edges.append({'id': uid, 'source': r['subject'], 'target': r['object'],
                      'type': r['relation'], 'caption': r['properties'].get('caption', r['relation']),
                      'properties': properties})
    included = {e[k] for e in edges for k in ('source', 'target')}
    return {'as_of': at, 'data_origin': 'SQLite snapshot; same directed overview as Neo4j',
            'nodes': [nodes[uid] for uid in sorted(included)], 'edges': edges, 'status': status or {}}


def export(store, output, as_of=None, status=None):
    data = payload(store, as_of, status)
    return export_payload(data, output)


def export_payload(data, output):
    output = Path(output)
    encoded = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    atomic_text(output / 'graph_view.json', encoded + '\n')
    safe = encoded.replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    template = (ROOT / 'app/assets/graph_view.html').read_text(encoding='utf-8')
    script = (ROOT / 'app/assets/graph_view.js').read_text(encoding='utf-8')
    atomic_text(output / 'graph_view.html', template.replace('__SCRIPT__', script, 1).replace('__DATA__', safe, 1))
    return {'file': str((output / 'graph_view.html').resolve()), 'nodes': len(data['nodes']), 'edges': len(data['edges'])}
