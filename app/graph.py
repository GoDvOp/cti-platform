"""Optional Neo4j projection. No APOC and no Python driver required."""
import base64
import json
import os
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from .models import redact


def statements(store, demo=False, as_of=None):
    from .config import ROOT
    pubs = store.publications(demo)
    signals = store.signals(demo)
    companies = [c for c in store.companies() if bool(c.get('is_demo', False)) == demo]
    from .knowledge_graph import statements as knowledge_statements
    from .attack import statements as attack_statements
    from .company_graph import statements as company_graph_statements
    from .company_overview import statements as overview_statements
    from .graph_scoring import projection_statements as scoring_statements
    from .research_context import statements as research_statements
    configs = json.loads((ROOT / 'config/sources.json').read_text(encoding='utf-8'))
    source_config = {s['id']: s for s in configs}
    registry = ROOT / 'config/source_metadata.json'
    if registry.exists():
        source_config = {**json.loads(registry.read_text(encoding='utf-8')), **source_config}
    scope = 'demo:' if demo else 'real:'
    sources = {}
    publication_rows, cve_rows, bdu_rows = [], [], []
    for pub in pubs:
        content = json.loads(pub['data'])
        extraction = json.loads(pub['extraction'])
        source = source_config.get(pub['source_id'], {})
        source_key = scope + pub['source_id']
        sources[source_key] = {'id': source_key, 'source_id': pub['source_id'],
                              'name': source.get('name', pub['source_id']),
                              'url': source.get('reference_url', ''),
                              'independence_group': source.get('independence_group', 'unknown'),
                              'is_demo': demo}
        publication_rows.append({**{k: pub[k] for k in ('id', 'url', 'source_id', 'published_at',
                                                        'collected_at', 'content_hash')},
                                 'title': content['title'], 'is_demo': demo, 'source_key': source_key,
                                 'event_type': extraction.get('event_type', 'unknown'),
                                 'content_scope': content.get('metadata', {}).get('content_scope', 'feed_or_import')})
        for cve in extraction.get('cves', []):
            cve_rows.append({'id': scope + cve, 'cve': cve, 'publication_id': pub['id'], 'is_demo': demo})
        for bdu in extraction.get('bdu_ids', []):
            bdu_rows.append({'id': scope + bdu, 'bdu_id': bdu, 'publication_id': pub['id'], 'is_demo': demo})
    return [
        *[{'statement': f'CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS '
                        f'FOR (n:{label}) REQUIRE n.id IS UNIQUE'}
          for label in ('Company', 'Publication', 'Signal', 'Source', 'Vulnerability', 'Product', 'Sector', 'Domain', 'Assertion', 'ThreatActor', 'Incident', 'Malware', 'Technique', 'Tactic', 'Tool', 'AttackCampaign', 'BugBountyProgram')],
        {'statement': 'UNWIND $rows AS row MERGE (c:Company {id:row.id}) '
                      'SET c.name=row.name, c.sector=row.sector, c.is_demo=row.is_demo, '
                      'c.entity_type=row.entity_type,c.monitor_target=row.monitor_target',
         'parameters': {'rows': [dict(c, is_demo=demo, sector=c.get('sector', 'unknown'),
                                      entity_type=c.get('entity_type','company'), monitor_target=c.get('monitor_target',True))
                                 for c in companies]}},
        {'statement': 'UNWIND $rows AS row MERGE (src:Source {id:row.id}) '
                      'SET src.name=row.name, src.source_id=row.source_id, src.url=row.url, '
                      'src.independence_group=row.independence_group, src.is_demo=row.is_demo',
         'parameters': {'rows': list(sources.values())}},
        {'statement': 'UNWIND $rows AS row MERGE (p:Publication {id:row.id}) '
                      'SET p.url=row.url, p.title=row.title, p.name=row.title, p.source_id=row.source_id, '
                      'p.published_at=row.published_at, p.collected_at=row.collected_at, '
                      'p.content_hash=row.content_hash, p.is_demo=row.is_demo, '
                      'p.event_type=row.event_type, p.content_scope=row.content_scope '
                      'WITH p,row MATCH (src:Source {id:row.source_key}) MERGE (p)-[:PUBLISHED_BY]->(src)',
         'parameters': {'rows': publication_rows}},
        {'statement': 'UNWIND $rows AS row MATCH (p:Publication {id:row.id}) '
                      'OPTIONAL MATCH (p)-[r]->() WHERE type(r) IN ["MENTIONS_CVE","MENTIONS_BDU"] DELETE r',
         'parameters': {'rows': [{'id': p['id']} for p in pubs]}},
        {'statement': 'UNWIND $rows AS row MATCH (p:Publication {id:row.publication_id}) '
                      'MERGE (v:Vulnerability {id:row.id}) SET v.cve=row.cve, v.name=row.cve, v.is_demo=row.is_demo '
                      'MERGE (p)-[r:MENTIONS_CVE]->(v) SET r.status="reported_reference"',
         'parameters': {'rows': cve_rows}},
        {'statement': 'UNWIND $rows AS row MATCH (p:Publication {id:row.publication_id}) '
                      'MERGE (v:Vulnerability {id:row.id}) SET v.bdu_id=row.bdu_id,v.name=row.bdu_id,v.is_demo=row.is_demo '
                      'MERGE (p)-[r:MENTIONS_BDU]->(v) SET r.status="reported_reference"',
         'parameters': {'rows': bdu_rows}},
        {'statement': 'MATCH (s:Signal)-[:MENTIONS]->(c:Company {is_demo:$demo}) DETACH DELETE s',
         'parameters': {'demo': demo}},
        *knowledge_statements(store, demo, as_of),
        *(research_statements(store, as_of) if not demo else []),
        *attack_statements(store, demo),
        *company_graph_statements(store, demo),
        *overview_statements(store, demo, as_of),
        *scoring_statements(store, demo, as_of),
        {'statement': 'UNWIND $rows AS row MATCH (c:Company {id:row.company_id}), '
                      '(p:Publication {id:row.publication_id}) MERGE (s:Signal {id:row.id}) '
                      'SET s.event_type=row.event_type, s.entity_status=row.entity_status, '
                      's.verification_status=row.verification_status, s.excerpt=row.excerpt, s.is_demo=$demo '
                      'MERGE (p)-[:REPORTS]->(s) MERGE (s)-[:MENTIONS]->(c)',
         'parameters': {'rows': [{k: row[k] for k in ('id', 'company_id', 'publication_id', 'event_type',
                                                   'entity_status', 'verification_status', 'excerpt')}
                                 for row in signals], 'demo': demo}},
    ]


def export_graph(store, output, demo=False, as_of=None):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {'statements': statements(store, demo, as_of)}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'file': str(path.resolve()), 'statements': len(data['statements'])}


def connection():
    base = os.getenv('NEO4J_HTTP_URL', 'http://127.0.0.1:7474').rstrip('/')
    p = urlsplit(base)
    if (p.scheme not in ('http', 'https') or p.hostname not in ('localhost', '127.0.0.1', 'neo4j')
            or p.username or p.password or p.query or p.fragment):
        raise ValueError('Neo4j: допускается только локальная БД')
    password = os.getenv('NEO4J_PASSWORD', '')
    if len(password) < 8:
        raise ValueError('Задайте NEO4J_PASSWORD длиной не менее 8 символов')
    auth = base64.b64encode(('neo4j:' + password).encode()).decode()
    return base, auth


def execute_requests(base, auth, statements, stage):
    req = Request(base + '/db/neo4j/tx/commit',
                  data=json.dumps({'statements': statements}).encode(),
                  headers={'Content-Type': 'application/json', 'Authorization': 'Basic ' + auth})
    try:
        with urlopen(req, timeout=30) as response:
            result = json.load(response)
    except HTTPError as exc:
        if exc.code == 401:
            raise ValueError('Neo4j: пароль из .env отклонён. Проверьте совпадение с паролем контейнера.') from exc
        raise ValueError('Neo4j HTTP ' + str(exc.code) + '; этап: ' + stage) from exc
    except (URLError, TimeoutError, ConnectionError, PermissionError) as exc:
        reason = exc.reason if isinstance(exc, URLError) else exc
        if isinstance(reason, PermissionError):
            detail = 'Среда запрещает соединение; выполните команду в обычном терминале пользователя.'
        elif isinstance(reason, ConnectionRefusedError):
            detail = 'Соединение отклонено. Проверьте запуск контейнера Neo4j и публикацию HTTP-порта.'
        elif isinstance(reason, (TimeoutError, socket.timeout)):
            detail = 'Истекло время ожидания ответа. Проверьте состояние Neo4j и журнал контейнера.'
        elif isinstance(reason, socket.gaierror):
            detail = 'Не удалось разрешить имя сервера. Проверьте NEO4J_HTTP_URL в .env.'
        elif isinstance(reason, ssl.SSLError):
            detail = 'Ошибка TLS. Проверьте протокол и сертификат Neo4j.'
        else:
            detail = 'Сетевая ошибка. Проверьте состояние Neo4j и NEO4J_HTTP_URL в .env.'
        raise ValueError('Не удалось подключиться к Neo4j (' + base + '); этап: ' + stage + '. ' + detail) from exc
    if result.get('errors'):
        error = result['errors'][0]
        code = error.get('code', 'unknown')
        message = redact(error.get('message', ''))[:1000]
        raise ValueError('Neo4j; этап: ' + stage + '; ' + code + ': ' + message)
    return result


def graph_status(demo=False):
    base, auth = connection()
    queries = [
        {'statement': 'MATCH (n) WHERE n.is_demo=$demo RETURN labels(n) AS labels,count(n) AS count',
         'parameters': {'demo': demo}},
        {'statement': 'MATCH (a)-[r]->(b) WHERE a.is_demo=$demo AND b.is_demo=$demo '
                      'RETURN type(r) AS type,count(r) AS count', 'parameters': {'demo': demo}},
    ]
    result = execute_requests(base, auth, queries, 'проверка загруженного графа')
    rows = []
    for entry in result.get('results', []):
        columns = entry.get('columns', [])
        rows.append([dict(zip(columns, d.get('row', []))) for d in entry.get('data', [])])
    return {'database': 'neo4j', 'endpoint': base, 'is_demo': demo,
            'nodes': rows[0] if rows else [], 'relationships': rows[1] if len(rows) > 1 else []}


def sync_graph(store, demo=False, as_of=None):
    base, auth = connection()
    all_statements = statements(store, demo, as_of)
    # Schema constraints must be committed separately from graph data updates.
    schema = [q for q in all_statements if q['statement'].startswith('CREATE CONSTRAINT')]
    data = [q for q in all_statements if not q['statement'].startswith('CREATE CONSTRAINT')]
    for batch, stage in ((schema, 'создание схемы'), (data, 'загрузка данных')):
        execute_requests(base, auth, batch, stage)
    verification = graph_status(demo)
    for label, marker in [('Product', 'MERGE (p:Product'), ('Incident', 'MERGE (n:Incident'),
                          ('ThreatActor', 'MERGE (n:ThreatActor'), ('Malware', 'MERGE (n:Malware'),
                          ('Technique', 'MERGE (n:Technique'), ('Tactic', 'MERGE (n:Tactic'),
                          ('Tool', 'MERGE (n:Tool'), ('AttackCampaign', 'MERGE (n:AttackCampaign')]:
        expected = len({row['id'] for q in data if marker in q['statement']
                        for row in q.get('parameters', {}).get('rows', [])})
        actual = sum(n['count'] for n in verification['nodes'] if label in n.get('labels', []))
        if expected and actual < expected:
            message = 'не найдены узлы ' if not actual else 'недостаточно узлов '
            raise ValueError('После загрузки в базе neo4j ' + message + label +
                             '; синхронизация не подтверждена.')
    return {'status': 'ok', 'statements': len(all_statements), 'verification': verification}
