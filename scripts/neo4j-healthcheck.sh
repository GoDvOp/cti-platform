#!/bin/bash
set -eu

if ! cypher-shell -u neo4j -p "${CTI_GRAPH_PASSWORD:?}" 'RETURN 1' >/dev/null 2>&1; then
  printf '%s\n' 'Cypher-проверка не прошла. При Unauthorized / authentication failure в логах выполните ./start-cti.sh repair-neo4j.' >&2
  exit 1
fi

# Bolt can already accept queries while the HTTP API used by the worker is starting.
# Use Bash builtins because the official image has neither curl nor Python.
exec 3<>/dev/tcp/127.0.0.1/7474
printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3
IFS= read -r -t 3 response <&3
[[ "$response" == HTTP/1.*' 200 '* ]]
