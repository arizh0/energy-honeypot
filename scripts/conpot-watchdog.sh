#!/bin/sh
# Restart Conpot when Docker marks it unhealthy.
#
# Docker's restart policy does not act on healthcheck failures, so this small
# host-side watchdog handles the live-but-wedged Conpot failure mode.

set -eu

CONTAINER="${CONPOT_CONTAINER:-conpot}"
COMPOSE_DIR="${HONEYPOT_COMPOSE_DIR:-/opt/honeypot}"
LOG_TAG="${CONPOT_WATCHDOG_TAG:-conpot-watchdog}"

log() {
  message="$1"
  if command -v systemd-cat >/dev/null 2>&1; then
    printf '%s\n' "$message" | systemd-cat -t "$LOG_TAG" -p info
  else
    printf '%s %s\n' "$(date -Is)" "$message"
  fi
}

status="$(
  docker inspect \
    --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
    "$CONTAINER" 2>/dev/null || true
)"

case "$status" in
  healthy | starting | running)
    exit 0
    ;;
  unhealthy)
    log "$CONTAINER is unhealthy; restarting it"
    docker restart "$CONTAINER" >/dev/null
    ;;
  exited | dead | created | paused | restarting | removing)
    log "$CONTAINER status is $status; recreating it through docker compose"
    cd "$COMPOSE_DIR"
    docker compose up -d "$CONTAINER" >/dev/null
    ;;
  "")
    log "$CONTAINER is missing; creating it through docker compose"
    cd "$COMPOSE_DIR"
    docker compose up -d "$CONTAINER" >/dev/null
    ;;
  *)
    log "$CONTAINER status is '$status'; leaving it unchanged"
    ;;
esac
