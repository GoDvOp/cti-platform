#!/bin/sh
# Invoked only by the explicit repair-neo4j action, after the normal stack stops.
set -eu
umask 077

fail() {
  printf 'Восстановление Neo4j: %s\n' "$1" >&2
  exit 1
}

[ "${NEO4J_AUTH:-}" = none ] || fail 'Контейнер восстановления неправильно настроен.'
[ "${#CTI_GRAPH_PASSWORD}" -ge 8 ] || fail 'Задайте NEO4J_PASSWORD в .env длиной не менее восьми символов.'

backup=$(mktemp -d /backup/recovery.XXXXXXXX)
server_pid=''
finish() {
  if [ -n "$server_pid" ]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  chown -R "${CTI_UID:-1000}:${CTI_GID:-1000}" "$backup"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

printf '%s\n' 'Создаю полную резервную копию тома Neo4j…'
tar -czf "$backup/neo4j-data.tar.gz" -C /data . || fail 'Не удалось создать резервную копию. Пароль не изменён.'
printf 'Резервная копия: data/diagnostics/neo4j-recovery/%s/neo4j-data.tar.gz\n' "${backup##*/}"

sh /cti/neo4j-start.sh neo4j > "$backup/server.log" 2>&1 &
server_pid=$!
query() {
  database=$1
  shift
  cypher-shell -a bolt://127.0.0.1:7687 -u neo4j -p recovery \
    -d "$database" --format plain "$@" </dev/null
}

attempt=0
until query system 'SHOW DATABASES' >/dev/null 2>&1; do
  kill -0 "$server_pid" 2>/dev/null || fail 'Изолированный сервер не запустился; см. server.log рядом с резервной копией.'
  attempt=$((attempt + 1))
  [ "$attempt" -lt 60 ] || fail 'Изолированный сервер не стал готов за отведённое время; см. server.log.'
  sleep 2
done

before=$(query neo4j 'MATCH (n) RETURN count(n) AS nodes')
# jq escapes quotes, backslashes and dollar signs without constructing Cypher code.
password_json=$(printf '%s' "$CTI_GRAPH_PASSWORD" | jq -Rs .)
if ! query system --param "newPassword => $password_json" \
     'ALTER USER neo4j SET PASSWORD $newPassword CHANGE NOT REQUIRED' >/tmp/cti-password-change.log 2>&1; then
  if grep -Fq 'Old password and new password cannot be the same' /tmp/cti-password-change.log; then
    query system 'ALTER USER neo4j SET PASSWORD CHANGE NOT REQUIRED' >/dev/null 2>&1 || \
      fail 'Не удалось снять требование смены пароля.'
  else
    fail 'Не удалось установить пароль из .env. Пароль и параметры запроса не выводятся.'
  fi
fi
rm -f /tmp/cti-password-change.log
after=$(query neo4j 'MATCH (n) RETURN count(n) AS nodes')
[ "$before" = "$after" ] || fail 'Количество узлов изменилось; сохранена резервная копия.'
printf '%s\n' 'Пароль Neo4j приведён в соответствие с .env. Количество узлов графа не изменилось.'
