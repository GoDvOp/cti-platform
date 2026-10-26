// 1. Обзор: 22 компании каталога, исторические примеры включены.
// В Browser запускать один запрос за раз.
MATCH path=(s:CompanyGraph)-[r]->(o:CompanyGraph)
WHERE s.is_demo=false AND o.is_demo=false AND r.company_view=true
RETURN path LIMIT 200;

// 2. Только связи вокруг Equifax в обзоре: атрибуция из обвинения, отрасль и ПО.
MATCH path=(c:Company {id:'equifax'})-[r]-(n:CompanyGraph)
WHERE r.company_view=true
RETURN path;

// 3. Техническая цепочка Equifax. Версия установки неизвестна, факт эксплуатации исторический.
MATCH path=(c:Company {id:'equifax'})-[use:USED_PRODUCT]->(p:Product)
              <-[affects:AFFECTS]-(v:Vulnerability {cve:'CVE-2017-5638'})
WHERE use.status='confirmed' AND affects.status='confirmed'
RETURN path;

// 4. Novabev / ВинЛаб: один инцидент с двумя организациями; группировка не придумана.
MATCH path=(i:Incident {id:'real:novabev-2025'})-[r:AFFECTED_ORGANIZATION]->(c:Company)
WHERE r.status='confirmed'
RETURN path;

// 5. Индексы, покрытие компонентов и дата. null — нет достаточных оснований.
MATCH (c:Company {is_demo:false})
RETURN c.name AS company,c.monitor_target AS current_monitoring,
       c.interest_index AS interest,c.technical_exposure_index AS technical,
       c.interest_evidence_coverage AS component_coverage,
       c.graph_score_model AS model,c.graph_score_as_of AS as_of
ORDER BY company;

// 6. Атрибуция: основания и доказательства прямо у стрелки.
MATCH (a:ThreatActor)-[r:ATTRIBUTED_ATTACK_ON]->(c:Company)
WHERE r.company_view=true
RETURN a.name,c.name,r.incident_id,r.bases,r.attribution_scopes,r.evidence_urls,r.weight;

// 7. Прямая связь группы с CVE: только проверенное прямое утверждение источника.
MATCH path=(a:ThreatActor)-[r:REPORTED_EXPLOITS]->(v:Vulnerability)
WHERE r.company_view=true AND r.status='confirmed'
RETURN path;

// 8. Известная эксплуатация инцидентом: назначение веса technical, политика static_reference.
MATCH (i:Incident)-[r:EXPLOITED]->(v:Vulnerability)
WHERE r.status='confirmed'
RETURN i.name,v.cve,r.weight_dimension,r.weight_temporal_policy,r.weight_quality,r.weight_decay;

// 9. Отрасль — наблюдения в нашей выборке, не частота всех атак.
MATCH (a:ThreatActor)-[r:OBSERVED_ATTACK_IN_SECTOR]->(s:Sector)
WHERE r.company_view=true
RETURN a.name,s.name,r.incident_count,r.company_count,r.interpretation;
