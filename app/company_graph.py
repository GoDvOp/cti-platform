"""A company-centred view over the existing graph, without inferred attack edges."""
from collections import defaultdict


def attack_contexts(store):
    """Only reviewed, directed incident paths can select ATT&CK context.

    Shared products, actor overlaps and reused tools never attribute an incident.
    The selected ATT&CK objects remain reference knowledge, not observations.
    """
    from .attack import mapping_rows
    claims=[a for a in store.assertions() if a['status']=='confirmed']
    affected=defaultdict(list)
    for a in claims:
        if a['kind']=='incident_affects':affected[a['subject']].append(a)
    mapped=defaultdict(list)
    for mapping in mapping_rows(store):
        if mapping['effective_status']=='confirmed':mapped[mapping['local_id']].append(mapping)
    actors=defaultdict(list);malware=defaultdict(list);tools=defaultdict(list)
    for a in claims:
        if a['kind']=='attributed_to':actors[a['subject']].append(a)
        elif a['kind']=='incident_malware':malware[a['subject']].append(a)
        elif a['kind']=='actor_uses_malware':tools[a['subject']].append(a)
    rows=[]
    def append(affected_claim, local_id, path):
        if local_id not in mapped:return
        for mapping in mapped[local_id]:
            rows.append({'company_id':affected_claim['object'],'incident_id':affected_claim['subject'],
                     'local_entity_id':local_id,'stix_id':mapping['stix_id'],'attack_id':mapping['attack_id'],
                     'assertion_ids':[a['id'] for a in path],
                     'source_urls':sorted({a['publication']['url'] for a in path}),
                     'status':'reference_context',
                     'interpretation':'Цепочка основана на источниках; справочные техники не подтверждены для каждого отдельного вторжения'})
    for incident,links in affected.items():
        for link in links:
            for actor in actors[incident]:
                append(link,actor['object'],[link,actor])
                for tool in tools[actor['object']]:
                    append(link,tool['object'],[link,actor,tool])
            for tool in malware[incident]:append(link,tool['object'],[link,tool])
    # Several evidence paths can reach the same object; keep all proofs in one row.
    merged={}
    for row in rows:
        key=row['company_id'],row['incident_id'],row['local_entity_id'],row['stix_id']
        if key not in merged:merged[key]=dict(row)
        else:
            for field in ('assertion_ids','source_urls'):
                merged[key][field]=sorted(set(merged[key][field]+row[field]))
    return list(merged.values())


def incident_entities(store):
    """Select direct incident participants, never an actor's complete repertoire."""
    claims = [a for a in store.assertions() if a['status']=='confirmed']
    incidents = {e['id'] for e in store.entities() if e['entity_type']=='Incident'}
    kinds = {'attributed_to':'ThreatActor', 'claimed_by':'ThreatActor', 'incident_malware':'Malware'}
    entities = {e['id']:e for e in store.entities()}
    selected = {}
    for claim in claims:
        if claim['kind'] not in kinds or claim['subject'] not in incidents:
            continue
        entity = entities.get(claim['object'])
        if entity and entity['entity_type']==kinds[claim['kind']]:
            selected[entity['id']] = entity
    return list(selected.values())


def statements(store,demo=False):
    if demo:return []
    # Keep catalogue metadata on selected local entities without displaying a
    # duplicate ATT&CK profile or expanding all of its software and techniques.
    from .attack import mapping_rows
    selected = incident_entities(store)
    mappings = defaultdict(list)
    for mapping in mapping_rows(store):
        if mapping['effective_status']=='confirmed':mappings[mapping['local_id']].append(mapping)
    rows = [{'id':'real:'+entity['id'],
             'attack_ids':sorted({m['attack_id'] for m in mappings[entity['id']]}),
             'attack_urls':sorted({m['evidence_url'] for m in mappings[entity['id']]})}
            for entity in selected]
    return [
        {'statement':'MATCH (n:CompanyGraph {is_demo:false}) REMOVE n:CompanyGraph'},
        {'statement':'MATCH (n) WHERE n.is_demo=false AND coalesce(n.knowledge_origin,"")<>"mitre-attack" '
                     'AND (n:Company OR n:Product OR n:Vulnerability OR n:Incident '
                     'OR n:Sector OR n:Domain) SET n:CompanyGraph'},
        {'statement':'UNWIND $rows AS row MATCH (n {id:row.id,is_demo:false}) '
                     'SET n:CompanyGraph,n.attack_ids=row.attack_ids,n.attack_urls=row.attack_urls',
         'parameters':{'rows':rows}},
    ]
