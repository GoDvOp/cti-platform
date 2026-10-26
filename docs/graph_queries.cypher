// 1. Все источники и публикации, включая бюллетени без названия компании.
MATCH path=(p:Publication)-[:PUBLISHED_BY]->(src:Source)
WHERE p.is_demo = false
RETURN path LIMIT 100;

// 2. Публикации с CVE. Упоминание не означает уязвимость компании.
MATCH path=(src:Source)<-[:PUBLISHED_BY]-(p:Publication)-[:MENTIONS_CVE]->(v:Vulnerability)
WHERE p.is_demo = false
RETURN path LIMIT 100;

// 3. Кандидаты в адресные сигналы, а не подтверждённые атаки.
MATCH path=(src:Source)<-[:PUBLISHED_BY]-(p:Publication)-[:REPORTS]->(s:Signal)-[:MENTIONS]->(c:Company)
WHERE c.is_demo = false
RETURN path LIMIT 100;

// 4. Источники в порядке количества публикаций. Считать источник независимым автоматически нельзя.
MATCH (p:Publication)-[:PUBLISHED_BY]->(src:Source)
WHERE p.is_demo = false
RETURN src.name AS source, src.independence_group AS publisher,
       count(p) AS publications ORDER BY publications DESC;

// 5. Полная техническая цепочка. USED_PRODUCT — исторические сведения.
MATCH path=(c:Company)-[:USES_PRODUCT|USED_PRODUCT|REPORTED_USES_PRODUCT]->(p:Product)
           <-[:AFFECTS|REPORTED_AFFECTS]-(v:Vulnerability)
WHERE c.is_demo = false
RETURN path LIMIT 100;

// 6. Связи компаний. Поставка и партнёрство не доказывают технический доступ.
MATCH path=(a:Company)-[:PART_OF|SUBSIDIARY_OF|SUPPLIES_TO|PARTNERS_WITH]->(b:Company)
WHERE a.is_demo = false
RETURN path LIMIT 100;

// 7. Две компании с общим продуктом. Не означает общую уязвимость.
MATCH path=(a:Company)-[:USES_PRODUCT|USED_PRODUCT|REPORTED_USES_PRODUCT]->(p:Product)
           <-[:USES_PRODUCT|USED_PRODUCT|REPORTED_USES_PRODUCT]-(b:Company)
WHERE a.is_demo = false AND b.is_demo = false AND a.id < b.id
RETURN path LIMIT 100;

// 8. Источник утверждения и его участники, включая кандидатов и опровержения.
MATCH path=(p:Publication)-[:SUPPORTS]->(a:Assertion)-[:SUBJECT|OBJECT]->(n)
WHERE a.is_demo = false
RETURN path LIMIT 100;

// 9. Технические проверки; это отдельный контекст, не вероятность атаки.
MATCH path=(c:Company)-[:TECHNICAL_CONTEXT|REQUIRES_VERSION_CHECK|POTENTIALLY_AFFECTED_BY]->(v:Vulnerability)
WHERE c.is_demo = false
RETURN path LIMIT 100;

// Версия 1.5: весь предметный граф
MATCH path=(a)-[r]->(b)
WHERE a.is_demo = false AND b.is_demo = false
  AND none(n IN nodes(path) WHERE n:Publication OR n:Assertion OR n:Source OR n:Signal)
RETURN path LIMIT 300;
