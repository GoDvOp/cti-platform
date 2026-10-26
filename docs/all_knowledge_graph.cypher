// Общий исследовательский граф без служебных публикаций и утверждений.
MATCH path=(a)-[r]->(b)
WHERE a.is_demo = false AND b.is_demo = false
  AND none(n IN nodes(path) WHERE n:Publication OR n:Assertion OR n:Source OR n:Signal)
RETURN path LIMIT 300;
