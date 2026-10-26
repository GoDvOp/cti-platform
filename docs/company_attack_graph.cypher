// Только пути от компаний через атрибуцию к справочному контексту ATT&CK.
MATCH path=(c:Company)<-[affected]-(i:Incident)-[attribution]->(actor:ThreatActor)-[mapping]->(profile)-[use]->(detail)
WHERE c.is_demo=false
  AND type(affected)='AFFECTED_ORGANIZATION' AND affected.status='confirmed'
  AND type(attribution)='ATTRIBUTED_TO' AND attribution.status='confirmed'
  AND type(mapping)='ATTACK_MAPPING' AND mapping.status='confirmed'
  AND type(use) IN ['ATTACK_USES_TECHNIQUE','ATTACK_USES_SOFTWARE']
RETURN path LIMIT 150;
