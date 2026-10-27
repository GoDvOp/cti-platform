#!/bin/sh
# Linux/macOS/WSL: no Python installation is required on the host.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export CTI_UID="${CTI_UID:-$(id -u)}" CTI_GID="${CTI_GID:-$(id -g)}"
export CTI_IMAGE="${CTI_IMAGE:-cti-platform:3.1.0}"
action=${1:-help}
if [ "$#" -gt 0 ]; then shift; fi

usage() {
  printf '%s\n' 'Usage: ./start-cti.sh [up|review|cli [args...]|status|logs|stop]' \
    'Без аргументов ./start-cti.sh запускает весь проект.' \
    'Также доступно: sh scripts/docker.sh up|review|cli [args...]|status|logs|stop'
}
case "$action" in
  up|review|cli|status|logs|stop) ;;
  help|-h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'Docker не найден. Установите Docker Engine или Docker Desktop и Docker Compose 2.24+.' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'Docker недоступен. Запустите Docker и проверьте доступ командой docker ps в обычном терминале.' >&2
  exit 1
fi
docker compose version >/dev/null
mkdir -p data

case "$action" in
  up)
    desktop_active=0
    desktop_enabled=''
    if command -v systemctl >/dev/null 2>&1 && \
       [ "$(systemctl --user show --property=WorkingDirectory --value cti-platform-update.service 2>/dev/null)" = "$(pwd -P)" ]; then
      if systemctl --user is-active --quiet cti-platform-update.service 2>/dev/null; then
        desktop_active=1
      fi
      desktop_enabled=$(systemctl --user is-enabled cti-platform-update.service 2>/dev/null || true)
    fi
    docker compose build cli
    if [ ! -f .env ]; then
      env_tmp=".env.tmp.$$"
      trap 'rm -f "$env_tmp"' EXIT HUP INT TERM
      (umask 077; docker run --rm --network none --entrypoint python "$CTI_IMAGE" -c \
        'from pathlib import Path; import secrets; print(Path("/app/.env.example").read_text().replace("NEO4J_PASSWORD=\n", "NEO4J_PASSWORD=" + secrets.token_urlsafe(24) + "\n"), end="")' > "$env_tmp")
      mv "$env_tmp" .env
      trap - EXIT HUP INT TERM
      printf '%s\n' 'Создана локальная .env со случайным паролем Neo4j.'
    fi
    docker compose run --rm --no-deps -T cli python -c \
      'from app.graph import connection; connection(); print("Настройки Neo4j корректны.")'
    if [ "$desktop_active" = 1 ]; then
      printf '%s\n' 'Переключаю сборщик этой папки с настольной службы на Docker…'
      systemctl --user stop cti-platform-update.service
    fi
    sh scripts/stop_local_panel.sh
    if docker compose up -d --no-build --wait --wait-timeout 360 neo4j worker workbench; then
      case "$desktop_enabled" in
        enabled|enabled-runtime)
          if [ "$desktop_enabled" = enabled-runtime ]; then
            systemctl --user disable --runtime cti-platform-update.service
          else
            systemctl --user disable cti-platform-update.service
          fi
          printf '%s\n' 'Автозапуск настольного сборщика отключён; сбор выполняется в Docker.'
          ;;
      esac
      address=$(docker compose port workbench 8765)
      printf '\nПанель аналитика: http://%s/\n' "$address"
      printf '%s\n' 'Состояние: ./start-cti.sh status' 'Остановить: ./start-cti.sh stop (данные сохраняются)'
    else
      if [ "$desktop_active" = 1 ]; then
        if docker compose stop worker; then
          systemctl --user start cti-platform-update.service || \
            printf '%s\n' 'Не удалось восстановить настольный сборщик. Выполните: systemctl --user start cti-platform-update.service' >&2
        else
          printf '%s\n' 'Не удалось остановить контейнер сборщика; настольная служба оставлена остановленной.' >&2
        fi
      fi
      printf '%s\n' 'Запуск не завершён. Диагностика: ./start-cti.sh logs' >&2
      exit 1
    fi
    ;;
  review)
    docker compose build review
    docker compose run --rm --no-deps -T review "$@" ;;
  cli)
    docker compose build cli
    docker compose run --rm --no-deps -T cli "$@" ;;
  status) docker compose ps --all ;;
  logs) docker compose logs --tail 100 "$@" ;;
  stop)
    docker compose stop "$@"
    sh scripts/stop_local_panel.sh
    ;;
esac
