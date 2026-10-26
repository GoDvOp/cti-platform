// 1. Рабочая условная цепочка: компания использует продукт, по продукту есть свежий бюллетень.
// Это очередь проверки применимости. MONITORING_HYPOTHESIS не означает факт атаки.
MATCH p=(c:Company)-[h:MONITORING_HYPOTHESIS]->(n:Publication)-[:SECURITY_NOTICE_FOR]->(product:Product)
RETURN p;

// 2. Добавить известное использование ПО к цепочке. Для Росзарубежнефти показать закрытый контур.
MATCH p=(c:Company {id:'roszarubezhneft'})-[use:USES_PRODUCT|USED_PRODUCT]->(product:Product),
      q=(c)-[h:MONITORING_HYPOTHESIS]->(n:Publication)-[:SECURITY_NOTICE_FOR]->(product)
RETURN p,q;

// 3. Условия и контраргументы: неизвестная версия не становится подтверждённой уязвимостью.
MATCH (c:Company)-[h:MONITORING_HYPOTHESIS]->(n:Publication)
RETURN c.name,h.status,h.network_exposure,h.counterevidence,h.missing,h.interpretation,n.url;

// 4. Bug bounty — исследовательский контекст. У этих связей нет вклада в индекс угрозы.
MATCH p=(c:Company)-[r:HAS_PUBLIC_BUG_BOUNTY]->(b:BugBountyProgram)
RETURN p;

// 5. Происхождение публичного описания программы.
MATCH p=(pub:Publication)-[:DESCRIBES_PROGRAM]->(program:BugBountyProgram)
RETURN p;

// 6. Новая цепочка из нескольких источников: продукт, описание исправления и текущая новость.
// Журнал изменений проверен по индексируемому фрагменту первоисточника (ограничение на связи).
// Новость сообщает о попытках эксплуатации PHP в общем, не об атаке на эту компанию.
MATCH usage_path=(c:Company {id:'roszarubezhneft'})-[u:USES_PRODUCT|USED_PRODUCT]->(product:Product),
      patch_path=(product)<-[:SECURITY_UPDATE_FOR]-(release:Publication)-[:MENTIONS_CVE]->(v:Vulnerability),
      activity_path=(v)<-[:MENTIONS_CVE]-(report:Publication {source_id:'bizone_news'})
WHERE u.status='confirmed' AND report.title CONTAINS 'PHP'
RETURN usage_path,patch_path,activity_path;
