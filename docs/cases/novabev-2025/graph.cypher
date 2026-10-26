// Кейс 01: в обычном терминале сначала выполните graph-sync.
// Один инцидент затронул две организации; две организации не означают две атаки.
MATCH path=(i:Incident {id:'real:novabev-2025'})-[r:AFFECTED_ORGANIZATION]->(c:Company)
WHERE i.is_demo=false AND c.is_demo=false AND r.status='confirmed'
RETURN path
UNION
MATCH path=(c:Company {id:'winelab'})-[r:PART_OF]->(g:Company {id:'novabev'})
WHERE c.is_demo=false AND g.is_demo=false AND r.status='confirmed'
RETURN path;

// Проверка основания отдельной связи с инцидентом.
MATCH path=(p:Publication)-[:SUPPORTS]->(a:Assertion)-[:SUBJECT]->(i:Incident {id:'real:novabev-2025'})
WHERE p.is_demo=false AND a.status='confirmed'
RETURN path;

// Индексы и сохранённое объяснение текущего расчёта, после нового graph-sync.
MATCH (c:Company)
WHERE c.id IN ['novabev','winelab'] AND c.is_demo=false
RETURN c.name, c.interest_index, c.technical_exposure_index,
       c.graph_score_as_of, c.graph_score_explanation_json;
