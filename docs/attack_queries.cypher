// Сопоставленные сущности и справочные связи ATT&CK
MATCH path=(local)-[m]->(a)-[r]->(b)
WHERE type(m) = 'ATTACK_MAPPING'
  AND type(r) IN ['ATTACK_USES_TECHNIQUE', 'ATTACK_USES_SOFTWARE']
RETURN path LIMIT 100;

// Техники TA505 и относящиеся к ним тактики
MATCH path=(g:ThreatActor)-[u]->(t:Technique)-[r]->(tactic:Tactic)
WHERE g.attack_id='G0092' AND type(u)='ATTACK_USES_TECHNIQUE' AND type(r)='IN_TACTIC'
RETURN path LIMIT 100;

// Доказательства справочной связи, без вывода об отдельном инциденте
MATCH (g:ThreatActor)-[r]->(x)
WHERE g.attack_id='G0092' AND type(r) IN ['ATTACK_USES_TECHNIQUE','ATTACK_USES_SOFTWARE']
RETURN g.name, x.name, x.attack_id, r.description, r.external_references_json, r.dataset_version;
