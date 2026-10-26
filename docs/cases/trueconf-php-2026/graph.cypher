// Product use, vendor update, shared CVEs and a general exploitation report.
MATCH use_path=(c:Company {id:'roszarubezhneft'})-[u:USES_PRODUCT|USED_PRODUCT]->(p:Product {id:'real:trueconf-server'}),
      update_path=(p)<-[:SECURITY_UPDATE_FOR]-(release:Publication)-[:MENTIONS_CVE]->(v:Vulnerability),
      report_path=(v)<-[:MENTIONS_CVE]-(report:Publication {source_id:'bizone_news'})
WHERE u.status='confirmed' AND report.title CONTAINS 'PHP'
RETURN use_path, update_path, report_path;
// An exploitation report about PHP is not evidence of an attack on this company.
