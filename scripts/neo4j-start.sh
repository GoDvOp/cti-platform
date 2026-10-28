#!/bin/sh
# Only the single Community instance and /data layout in docker-compose.yml.
set -eu

fail() {
  printf 'Neo4j: %s\n' "$1" >&2
  exit 1
}

if [ "${1:-}" = neo4j ]; then
  # Check the Docker volume, not the host checkout: they may use different disks.
  available=$(df -Pk /data | awk 'END {print $4}')
  case "$available" in
    ''|*[!0-9]*) fail 'Не удалось определить свободное место в томе /data.' ;;
  esac
  [ "$available" -ge 262144 ] || fail 'В томе /data осталось меньше 256 MiB. Освободите место на диске Docker; данные не изменены.'
  probe=$(mktemp /data/.cti-write-check.XXXXXXXX) || fail 'Том /data недоступен для записи: проверьте права, свободные inode и файловую систему.'
  rm "$probe"

  # Keep two instances of this wrapper from repairing the same volume at once.
  exec 9>/data/.cti-neo4j.lock
  flock -n 9 || fail 'Том /data уже используется другим экземпляром Neo4j.'

  identity=/data/server_id
  if [ -L "$identity" ] || { [ -e "$identity" ] && [ ! -f "$identity" ]; }; then
    fail '/data/server_id должен быть обычным файлом. Автоматическое восстановление отменено.'
  fi
  if [ -f "$identity" ]; then
    size=$(wc -c < "$identity")
    # The pinned Neo4j serializes one marker byte and two 64-bit UUID halves.
    # A shorter file produces ServerIdMarshal/EOFException during startup.
    if [ "$size" -lt 17 ]; then
      backup=$(mktemp -d /data/cti-server-id-backup.XXXXXXXX)
      if [ "$(id -u)" = 0 ]; then
        chown neo4j:neo4j "$backup"
      fi
      mv "$identity" "$backup/server_id"
      printf 'Neo4j: обрезанный server_id (%s байт) сохранён в %s/server_id; при запуске будет создан новый идентификатор.\n' "$size" "$backup" >&2
    fi
  fi
fi

# Preserve the official image's permission setup, authentication and signal handling.
exec tini -g -- /startup/docker-entrypoint.sh "$@"
