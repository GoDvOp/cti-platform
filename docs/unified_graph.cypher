// Направленный обзор компаний, группировок, отраслей и ПО.
// Требуется новый graph-sync; исходные связи инцидентов сохранены отдельно.
MATCH path=(a:CompanyGraph)-[r]->(b:CompanyGraph)
WHERE a.is_demo = false AND b.is_demo = false
  AND r.company_view = true
RETURN path LIMIT 1000;
