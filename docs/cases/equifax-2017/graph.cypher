// Кейс 02. После graph-sync: историческая цепочка, без утверждения о текущем ПО.
MATCH path=(i:Incident {id:'real:equifax-2017'})-[r]->(n)
WHERE i.is_demo=false AND n.is_demo=false AND r.status='confirmed'
  AND type(r) IN ['AFFECTED_ORGANIZATION','INVOLVED_PRODUCT','EXPLOITED','ATTRIBUTED_TO']
RETURN path
UNION
MATCH path=(c:Company {id:'equifax'})-[r:USED_PRODUCT]->(p:Product {id:'real:apache-struts2'})
WHERE r.status='confirmed' AND c.is_demo=false AND p.is_demo=false
RETURN path
UNION
MATCH path=(v:Vulnerability {id:'real:CVE-2017-5638'})-[r:AFFECTS]->(p:Product {id:'real:apache-struts2'})
WHERE r.claim_id='real:b6e835ece705a0f2b39de37b' AND r.status='confirmed'
RETURN path;

// Направленная обзорная атрибуция. basis = legal_allegation остаётся на связи.
MATCH path=(a:ThreatActor {id:'real:pla54'})-[r:ATTRIBUTED_ATTACK_ON]->(c:Company {id:'equifax'})
RETURN path;
