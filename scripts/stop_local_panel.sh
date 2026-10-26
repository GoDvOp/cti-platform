#!/bin/sh
# Retire Linux desktop panels belonging to this exact project directory.
# Uses /proc so Docker-only installations do not need host Python.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ -d /proc/self ] || exit 0
for process in /proc/[0-9]*; do
  [ "$(readlink "$process/cwd" 2>/dev/null || true)" = "$root" ] || continue
  command=$(tr '\000' ' ' < "$process/cmdline" 2>/dev/null || true)
  case "$command" in
    *' -m app.workbench '*) ;;
    *) continue ;;
  esac
  pid=${process##*/}
  printf 'Останавливаю настольную панель этой папки (PID %s)…\n' "$pid"
  kill -TERM "$pid" 2>/dev/null || continue
  attempts=0
  while kill -0 "$pid" 2>/dev/null; do
    # A zombie no longer owns listening sockets and is waiting to be reaped.
    if [ ! -r "$process/stat" ] || \
       [ "$(awk '{print $3}' "$process/stat" 2>/dev/null || true)" = Z ]; then
      break
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 50 ]; then
      printf 'Не удалось завершить настольную панель (PID %s).\n' "$pid" >&2
      exit 1
    fi
    sleep 0.1
  done
done
