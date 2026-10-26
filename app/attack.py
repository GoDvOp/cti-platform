"""Versioned Enterprise ATT&CK STIX import and reviewed identity mappings.

The catalogue is separate from observed incidents. ATT&CK uses relationships
never imply that a technique was observed in a company's individual incident.
"""
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
from .models import normalized, utcnow

INDEX_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json'
REFERENCE_URL = 'https://attack.mitre.org/resources/attack-data-and-tools/'
MAX_BYTES = 60_000_000
TYPES = {'intrusion-set':'ThreatActor','malware':'Malware','tool':'Tool',
         'attack-pattern':'Technique','x-mitre-tactic':'Tactic','campaign':'AttackCampaign'}
ID_RE = re.compile(r'^[a-z][a-z0-9-]*--[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def attack_reference(obj):
    return next((r for r in obj.get('external_references', [])
                 if r.get('source_name') == 'mitre-attack' and r.get('external_id')), {})


def active(obj):
    return not obj.get('revoked', False) and not obj.get('x_mitre_deprecated', False)


def identity_hash(obj):
    fields = {k: obj.get(k) for k in ('type', 'name', 'aliases')}
    fields['attack_id'] = attack_reference(obj).get('external_id')
    return hashlib.sha256(encode(fields).encode()).hexdigest()


def parse_bundle(payload):
    if len(payload) > MAX_BYTES:
        raise ValueError('STIX-файл превышает 60 МБ')
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeError) as exc:
        raise ValueError('Не удалось прочитать STIX JSON') from exc
    if not isinstance(data, dict) or data.get('type') != 'bundle' or not isinstance(data.get('objects'), list):
        raise ValueError('Ожидается STIX bundle с массивом objects')
    if not 1 <= len(data['objects']) <= 100000:
        raise ValueError('Недопустимое количество STIX objects')
    objects, collections = {}, []
    for obj in data['objects']:
        if not isinstance(obj, dict) or not isinstance(obj.get('id'), str) or not ID_RE.fullmatch(obj['id']):
            raise ValueError('Некорректный STIX object id')
        if not isinstance(obj.get('type'),str) or not obj['id'].startswith(str(obj.get('type')) + '--') or obj['id'] in objects:
            raise ValueError('Тип и STIX id не совпадают или id повторяется')
        for flag in ('revoked', 'x_mitre_deprecated'):
            if flag in obj and type(obj[flag]) is not bool:
                raise ValueError('Некорректный флаг ' + flag)
        for key in ('created', 'modified'):
            if obj.get(key):
                stamp = datetime.fromisoformat(obj[key].replace('Z', '+00:00'))
                if stamp.tzinfo is None:
                    raise ValueError('Дата STIX должна иметь часовой пояс')
        if not isinstance(obj.get('external_references', []), list) or not all(
                isinstance(x, dict) for x in obj.get('external_references', [])):
            raise ValueError('Некорректные external_references')
        if 'description' in obj and not isinstance(obj['description'], str):
            raise ValueError('description должен быть строкой')
        if obj['type'] in TYPES:
            if not isinstance(obj.get('name'), str) or not obj['name'].strip():
                raise ValueError('Нет названия STIX объекта')
            for field in ('aliases', 'x_mitre_domains', 'x_mitre_platforms'):
                if not isinstance(obj.get(field, []), list) or not all(isinstance(x, str) for x in obj.get(field, [])):
                    raise ValueError('Некорректный ' + field)
            if not isinstance(obj.get('kill_chain_phases', []),list):
                raise ValueError('kill_chain_phases должен быть списком')
            for phase in obj.get('kill_chain_phases', []):
                if not isinstance(phase,dict) or not all(isinstance(phase.get(k),str)
                        for k in ('kill_chain_name','phase_name')):
                    raise ValueError('Некорректная тактика kill_chain_phases')
            if not isinstance(obj.get('kill_chain_phases', []),list):
                raise ValueError('kill_chain_phases должен быть списком')
            if 'x_mitre_is_subtechnique' in obj and type(obj['x_mitre_is_subtechnique']) is not bool:
                raise ValueError('Некорректный флаг подтехники')
            ref=attack_reference(obj)
            patterns={'intrusion-set':r'G\d{4,}','malware':r'S\d{4,}','tool':r'S\d{4,}',
                      'attack-pattern':r'T\d{4,}(?:\.\d{3})?','x-mitre-tactic':r'TA\d{4,}','campaign':r'C\d{4,}'}
            if not isinstance(ref.get('external_id'),str) or not re.fullmatch(patterns[obj['type']],ref['external_id']):
                raise ValueError('У объекта нет допустимого внешнего идентификатора MITRE ATT&CK')
            if ref.get('url') and (not isinstance(ref['url'],str) or urlsplit(ref['url']).scheme not in ('https','http')):
                raise ValueError('Некорректная ссылка ATT&CK')
        if obj['type'] == 'relationship':
            if not all(isinstance(obj.get(k), str) and ID_RE.fullmatch(obj[k])
                       for k in ('source_ref', 'target_ref')):
                raise ValueError('Некорректные концы STIX relationship')
        if obj['type'] == 'x-mitre-collection':
            collections.append(obj)
        objects[obj['id']] = obj
    enterprise = next((c for c in collections if c.get('name') == 'Enterprise ATT&CK'), None)
    if not enterprise:
        raise ValueError('Не найдена коллекция Enterprise ATT&CK; нужен полный официальный STIX 2.1 bundle')
    contents=enterprise.get('x_mitre_contents')
    if not isinstance(contents,list) or not contents:
        raise ValueError('Нет манифеста содержимого коллекции')
    for entry in contents:
        if (not isinstance(entry,dict) or entry.get('object_ref') not in objects or
                objects[entry['object_ref']].get('modified') != entry.get('object_modified')):
            raise ValueError('Bundle неполон или не соответствует манифесту коллекции')
    version = enterprise.get('x_mitre_version')
    if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+', version):
        raise ValueError('Неизвестная версия коллекции ATT&CK')
    usable = {k: o for k,o in objects.items() if o['type'] in TYPES and active(o)
              and 'enterprise-attack' in o.get('x_mitre_domains', ['enterprise-attack'])}
    if not any(o['type']=='intrusion-set' for o in usable.values()) or not any(
            o['type']=='attack-pattern' for o in usable.values()):
        raise ValueError('В наборе отсутствуют активные группировки или техники')
    attack_ids = [attack_reference(o)['external_id'] for o in usable.values()]
    if len(set(attack_ids)) != len(attack_ids):
        raise ValueError('Повтор внешнего идентификатора ATT&CK')
    return data, usable, {'version': version, 'collection_id': enterprise['id'],
                          'collection_modified': enterprise.get('modified'),
                          'bundle_id': data.get('id'), 'total_objects':len(objects)}


def import_bundle(store, payload, source_url=None, expected_version=None):
    data, usable, metadata = parse_bundle(payload)
    if expected_version and metadata['version'] != expected_version:
        raise ValueError('Версия STIX не соответствует выбранной версии индекса')
    checksum = hashlib.sha256(payload).hexdigest()
    metadata.update(sha256=checksum, imported_at=utcnow(), source_url=source_url or 'local_file',
                    reference_url=REFERENCE_URL, dataset='enterprise-attack',
                    active_counts=dict(Counter(o['type'] for o in usable.values())))
    # Validate before touching the active snapshot. Failed imports leave it intact.
    with store.connect() as db:
        previous = db.execute('SELECT sha256 FROM attack_snapshots WHERE active=1').fetchone()
        db.execute('UPDATE attack_snapshots SET active=0')
        db.execute('INSERT INTO attack_snapshots VALUES(?,?,1) ON CONFLICT(sha256) DO UPDATE SET active=1',
                   (checksum,encode(metadata)))
        db.executemany('INSERT OR IGNORE INTO attack_objects VALUES(?,?,?)',
                       [(checksum,o['id'],encode(o)) for o in data['objects']])
    return dict(status='unchanged' if previous and previous['sha256']==checksum else 'imported', **metadata)


def catalogue(store):
    with store.connect() as db:
        snapshot = db.execute('SELECT * FROM attack_snapshots WHERE active=1').fetchone()
        if not snapshot:
            return {}, {}
        meta = json.loads(snapshot['data'])
        objects = {r['id']:json.loads(r['data']) for r in db.execute(
            'SELECT id,data FROM attack_objects WHERE snapshot_sha256=?',(snapshot['sha256'],))}
    return meta, objects


def supported_relationship(obj, objects):
    if obj.get('type') != 'relationship' or not active(obj):
        return None
    source, target = objects.get(obj['source_ref']), objects.get(obj['target_ref'])
    if not source or not target or not active(source) or not active(target):
        return None
    if source['type'] not in TYPES or target['type'] not in TYPES:
        return None
    pair = source['type'], target['type']
    kind = obj.get('relationship_type')
    if kind == 'uses':
        if pair[0] in ('intrusion-set','campaign') and pair[1] in ('tool','malware'):
            return 'ATTACK_USES_SOFTWARE'
        if pair[0] in ('intrusion-set','campaign','tool','malware') and pair[1]=='attack-pattern':
            return 'ATTACK_USES_TECHNIQUE'
    if kind == 'subtechnique-of' and pair==('attack-pattern','attack-pattern'):
        return 'SUBTECHNIQUE_OF'
    if kind == 'attributed-to' and pair==('campaign','intrusion-set'):
        return 'ATTACK_ATTRIBUTED_TO'
    return None


def mapping_rows(store):
    meta, objects = catalogue(store)
    local = {e['id']:e for e in store.entities()}
    with store.connect() as db:
        rows = [json.loads(r['data']) for r in db.execute('SELECT data FROM attack_mappings ORDER BY local_id,stix_id')]
    for row in rows:
        target = objects.get(row['stix_id'])
        row['effective_status'] = row['status']
        if row['local_id'] not in local or not target or not active(target):
            row['effective_status'] = 'inactive'
        elif row['identity_hash'] != identity_hash(target):
            row['effective_status'] = 'needs_review'
        row['local_name'] = local.get(row['local_id'],{}).get('name')
        row['attack_name'] = target.get('name') if target else None
        row['attack_id'] = attack_reference(target or {}).get('external_id')
    return rows


def candidates(store):
    meta, objects = catalogue(store)
    targets = [o for o in objects.values() if o['type'] in ('intrusion-set','malware','tool') and active(o)]
    rows=[]
    decisions={(m['local_id'],m['stix_id']):m['effective_status'] for m in mapping_rows(store)}
    for entity in store.entities():
        expected={'ThreatActor':'intrusion-set','Malware':'malware'}.get(entity['entity_type'])
        if not expected: continue
        names={normalized(x) for x in [entity['name'],*entity.get('aliases',[])]}
        for obj in targets:
            hits=names & {normalized(x) for x in [obj['name'],*obj.get('aliases',[])]}
            if obj['type']==expected and hits and decisions.get((entity['id'],obj['id'])) not in ('confirmed','refuted'):
                rows.append({'local_id':entity['id'],'local_name':entity['name'],
                             'stix_id':obj['id'],'attack_id':attack_reference(obj)['external_id'],
                             'attack_name':obj['name'],'matched_names':sorted(hits),'status':'needs_review'})
    return rows


def review_mapping(store, local_id, target_id, status, reviewer, note):
    if status not in ('confirmed','refuted','needs_review') or not reviewer.strip() or not note.strip():
        raise ValueError('Нужны статус, проверяющий и обоснование сопоставления')
    meta, objects=catalogue(store)
    target=objects.get(target_id) or next((o for o in objects.values()
        if o['type'] in TYPES and attack_reference(o).get('external_id')==target_id),None)
    entity=next((e for e in store.entities() if e['id']==local_id),None)
    if not target or not active(target) or not entity:
        raise ValueError('Нет активного объекта ATT&CK или локальной сущности')
    if {'ThreatActor':'intrusion-set','Malware':'malware'}.get(entity['entity_type']) != target['type']:
        raise ValueError('Нельзя сопоставить группировку с вредоносным ПО или несовместимые типы')
    row={'local_id':local_id,'stix_id':target['id'],'status':status,'reviewer':reviewer,'note':note,
         'reviewed_at':utcnow(),'identity_hash':identity_hash(target),'snapshot_sha256':meta['sha256'],
         'evidence_url':attack_reference(target).get('url',REFERENCE_URL)}
    with store.connect() as db:
        db.execute('INSERT INTO attack_mappings VALUES(?,?,?) ON CONFLICT(local_id,stix_id) DO UPDATE SET data=excluded.data',
                   (local_id,target['id'],encode(row)))
        db.execute('INSERT INTO attack_mapping_reviews(local_id,stix_id,data) VALUES(?,?,?)',
                   (local_id,target['id'],encode(row)))
    return row


def projection(store):
    meta, objects=catalogue(store)
    if not meta:return meta,{},[],[]
    valid = {k:o for k,o in objects.items() if o['type'] in TYPES and active(o)
             and 'enterprise-attack' in o.get('x_mitre_domains',['enterprise-attack'])}
    mappings=[m for m in mapping_rows(store) if m['effective_status']=='confirmed' and m['stix_id'] in valid]
    chosen={m['stix_id'] for m in mappings}
    relationships=[o for o in objects.values() if supported_relationship(o,valid)]
    # Include campaigns attributed to mapped actors, then their reported tools and techniques.
    chosen.update(o['source_ref'] for o in relationships if o.get('relationship_type')=='attributed-to'
                  and o['target_ref'] in chosen)
    changed=True
    while changed:
        before=len(chosen)
        chosen.update(o['target_ref'] for o in relationships if o['source_ref'] in chosen)
        changed=len(chosen)!=before
    selected={k:valid[k] for k in chosen}
    # Techniques encode their tactics as kill_chain_phases, not STIX relationships.
    phases={p['phase_name'] for o in selected.values() if o['type']=='attack-pattern'
            for p in o.get('kill_chain_phases',[]) if p.get('kill_chain_name')=='mitre-attack'}
    selected.update((k,o) for k,o in valid.items() if o['type']=='x-mitre-tactic' and o.get('x_mitre_shortname') in phases)
    relationships=[o for o in relationships if o['source_ref'] in selected and o['target_ref'] in selected]
    return meta, selected, relationships, mappings


def graph_id(stix_id):return 'real:attack:'+stix_id


def statements(store, demo=False):
    if demo:return []
    meta,objects,relationships,mappings=projection(store)
    if not meta:return []
    queries=[{'statement':'MATCH ()-[r]->() WHERE r.cti_managed="attack-mapping-v1" DELETE r'},
             {'statement':'MATCH (n {knowledge_origin:"mitre-attack",is_demo:false}) DETACH DELETE n'}]
    for label in TYPES.values():
        rows=[]
        for obj in objects.values():
            if TYPES[obj['type']]!=label:continue
            ref=attack_reference(obj)
            props={'name':obj['name'],'stix_id':obj['id'],'attack_id':ref['external_id'],
                   'aliases':obj.get('aliases',[]),'description':obj.get('description',''),
                   'url':ref.get('url',REFERENCE_URL),'external_references_json':encode(obj.get('external_references',[])),
                   'platforms':obj.get('x_mitre_platforms',[]),'modified':obj.get('modified'),
                   'object_version':obj.get('x_mitre_version'),'dataset_version':meta['version'],
                   'snapshot_sha256':meta['sha256'],'is_demo':False,'knowledge_origin':'mitre-attack',
                   'is_subtechnique':obj.get('x_mitre_is_subtechnique',False)}
            rows.append({'id':graph_id(obj['id']),'properties':props})
        queries.append({'statement':f'UNWIND $rows AS row MERGE (n:{label} {{id:row.id}}) SET n += row.properties',
                        'parameters':{'rows':rows}})
    grouped=defaultdict(list)
    for obj in relationships:
        source,target=objects[obj['source_ref']],objects[obj['target_ref']]
        key=TYPES[source['type']],supported_relationship(obj,objects),TYPES[target['type']]
        grouped[key].append({'source':graph_id(source['id']),'target':graph_id(target['id']),'id':obj['id'],
                            'properties':{'description':obj.get('description',''), 'stix_id':obj['id'],
                                          'external_references_json':encode(obj.get('external_references',[])),
                                          'modified':obj.get('modified'),'dataset_version':meta['version'],
                                          'status':'reported_by_attack','cti_managed':'attack-v1','is_demo':False,
                                          'interpretation':'Справочная связь ATT&CK; применение в отдельном инциденте не установлено'}})
    for (left,relation,right),rows in grouped.items():
        queries.append({'statement':f'UNWIND $rows AS row MATCH (a:{left} {{id:row.source}}),(b:{right} {{id:row.target}}) '
                                     f'MERGE (a)-[r:{relation} {{stix_id:row.id}}]->(b) SET r += row.properties',
                        'parameters':{'rows':rows}})
    tactics={o.get('x_mitre_shortname'):o for o in objects.values() if o['type']=='x-mitre-tactic'}
    rows=[{'source':graph_id(o['id']),'target':graph_id(tactics[p['phase_name']]['id'])}
          for o in objects.values() if o['type']=='attack-pattern' for p in o.get('kill_chain_phases',[])
          if p.get('kill_chain_name')=='mitre-attack' and p.get('phase_name') in tactics]
    queries.append({'statement':'UNWIND $rows AS row MATCH (a:Technique {id:row.source}),(b:Tactic {id:row.target}) '
                                 'MERGE (a)-[r:IN_TACTIC]->(b) SET r.status="stix_kill_chain_phase",r.is_demo=false,r.cti_managed="attack-v1"',
                    'parameters':{'rows':rows}})
    for label in ('ThreatActor','Malware'):
        local={e['id']:e for e in store.entities()}
        rows=[{'local_id':'real:'+m['local_id'],'target':graph_id(m['stix_id']),
               'properties':dict({k:m[k] for k in ('reviewer','reviewed_at','note','evidence_url','status','snapshot_sha256')},
                                 current_snapshot_sha256=meta['sha256'],dataset_version=meta['version'])}
              for m in mappings if local[m['local_id']]['entity_type']==label]
        queries.append({'statement':f'UNWIND $rows AS row MATCH (a:{label} {{id:row.local_id}}),(b:{label} {{id:row.target}}) '
                                     'MERGE (a)-[r:ATTACK_MAPPING]->(b) SET r += row.properties,r.is_demo=false,r.cti_managed="attack-mapping-v1"',
                        'parameters':{'rows':rows}})
    return queries


def status(store):
    meta,objects,relationships,mappings=projection(store)
    return {'dataset':meta or None,'projected_counts':dict(Counter(TYPES[o['type']] for o in objects.values())),
            'projected_relationships':len(relationships),'confirmed_mappings':len(mappings),
            'mappings':mapping_rows(store),'candidates':candidates(store)}


def fetch_official(url, limit=MAX_BYTES):
    p=urlsplit(url)
    if (p.scheme!='https' or p.hostname!='raw.githubusercontent.com' or p.username or p.password or
            p.query or p.fragment or not p.path.startswith('/mitre-attack/attack-stix-data/')):
        raise ValueError('Допускается только официальный репозиторий MITRE ATT&CK STIX')
    try:
        with urlopen(Request(url,headers={'User-Agent':'CTI-Intern-Research/1.6'}),timeout=40) as response:
            if urlsplit(response.geturl()).hostname!='raw.githubusercontent.com':
                raise ValueError('Неожиданный хост загрузки ATT&CK')
            payload=response.read(limit+1)
    except OSError as exc:
        raise ValueError('Не удалось скачать ATT&CK. Повторите attack-update в обычном терминале с интернетом; локальный набор сохранён.') from exc
    if len(payload)>limit:raise ValueError('Ответ ATT&CK превышает допустимый размер')
    return payload


def update(store, cache_dir, version=None):
    index_payload=fetch_official(INDEX_URL,2_000_000)
    try:
        index=json.loads(index_payload)
        collection=next(c for c in index['collections'] if c['name']=='Enterprise ATT&CK')
        versions=[v for v in collection['versions'] if re.fullmatch(r'\d+\.\d+',v['version'])]
        selected=next(v for v in versions if v['version']==version) if version else max(
            versions,key=lambda v:tuple(map(int,v['version'].split('.'))))
    except (KeyError,StopIteration,TypeError,ValueError) as exc:
        raise ValueError('Не удалось выбрать версию Enterprise ATT&CK в официальном индексе') from exc
    payload=fetch_official(selected['url'])
    # Check before caching or replacing the active catalogue.
    _,_,meta=parse_bundle(payload)
    if meta['version']!=selected['version']:raise ValueError('Версия bundle не совпадает с индексом')
    checksum=hashlib.sha256(payload).hexdigest()
    folder=Path(cache_dir);folder.mkdir(parents=True,exist_ok=True)
    path=folder/(checksum+'.json')
    temporary=path.with_suffix('.tmp');temporary.write_bytes(payload);temporary.replace(path)
    return dict(import_bundle(store,payload,selected['url'],selected['version']),cache_file=str(path))


def search(store, text, kind=None, limit=20):
    if not text.strip() or not 1<=limit<=100:
        raise ValueError('Нужны поисковая строка и limit от 1 до 100')
    meta,objects=catalogue(store)
    query=normalized(text)
    result=[]
    for obj in objects.values():
        if obj['type'] not in TYPES or not active(obj) or (kind and TYPES[obj['type']]!=kind):continue
        ref=attack_reference(obj)
        names=[obj['name'],ref.get('external_id',''),*obj.get('aliases',[])]
        if any(query in normalized(name) for name in names):
            result.append({'name':obj['name'],'type':TYPES[obj['type']],'attack_id':ref['external_id'],
                           'stix_id':obj['id'],'aliases':obj.get('aliases',[]),'url':ref.get('url'),
                           'dataset_version':meta['version']})
    return sorted(result,key=lambda r:(normalized(r['name'])!=query,r['name']))[:limit]


def restore_cached(store, folder):
    """Restore the shipped verified snapshot and explicitly reviewed seed mappings."""
    folder=Path(folder)
    manifest=json.loads((folder/'import_manifest.json').read_text(encoding='utf-8'))
    checksum=manifest.get('sha256','')
    if not re.fullmatch(r'[0-9a-f]{64}',checksum):raise ValueError('Некорректный SHA256 кеша ATT&CK')
    with (folder/'cache'/(checksum+'.json')).open('rb') as stream:payload=stream.read(MAX_BYTES+1)
    if hashlib.sha256(payload).hexdigest()!=checksum:raise ValueError('Кеш ATT&CK изменился: SHA256 не совпадает')
    result=import_bundle(store,payload,manifest['source_url'],manifest['version'])
    reviewed=folder/'reviewed_mappings.json'
    existing={(m['local_id'],m['stix_id']) for m in mapping_rows(store)}
    local={e['id'] for e in store.entities()}
    _,objects=catalogue(store)
    restored=0
    for m in json.loads(reviewed.read_text(encoding='utf-8')) if reviewed.exists() else []:
        obj=objects.get(m['stix_id'])
        if ((m['local_id'],m['stix_id']) in existing or m['local_id'] not in local or not obj
                or m['status']!='confirmed' or m['identity_hash']!=identity_hash(obj)):continue
        review_mapping(store,m['local_id'],m['stix_id'],'confirmed',m['reviewer'],
                       m['note']+' Восстановлено из проверенного сопоставления '+m['reviewed_at']+'.')
        restored+=1
    return dict(result,restored_mappings=restored)
