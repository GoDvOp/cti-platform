// Conditional monitoring, not proof of exploitation or an unpatched service.
MATCH use_path=(c:Company {id:'ispras'})-[u:USES_PRODUCT|USED_PRODUCT]->(p:Product {id:'real:gitlab'}),
      notice_path=(p)<-[:SECURITY_NOTICE_FOR]-(n:Publication),
      cve_path=(n)-[:MENTIONS_CVE]->(v:Vulnerability {id:'real:CVE-2026-110264'})
WHERE u.status='confirmed'
RETURN use_path, notice_path, cve_path;
