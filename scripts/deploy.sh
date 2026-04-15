#!/bin/bash
# Push local project changes to the VPS and restart affected containers.
# Works with scp + ssh (no rsync required — runs in Windows Git Bash).
# Run from the project root:
#   bash scripts/deploy.sh
# To rebuild images and restart all containers (after Dockerfile changes):
#   bash scripts/deploy.sh --rebuild

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$PROJECT_ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_ROOT/.env"
  set +a
fi

: "${HONEYPOT_VPS:?Set HONEYPOT_VPS in .env, e.g. admin@203.0.113.10}"

SSH_PORT="${HONEYPOT_SSH_PORT:-2222}"
SSH_KEY="${HONEYPOT_SSH_KEY:-$HOME/.ssh/honeypot_ed25519}"
SSH_OPTS=(-i "$SSH_KEY" -p "$SSH_PORT")
SCP_OPTS=(-i "$SSH_KEY" -P "$SSH_PORT")

REBUILD=false
if [[ "${1:-}" == "--rebuild" ]]; then
  REBUILD=true
fi

ARCHIVE=/tmp/honeypot-deploy.tar.gz

echo "==> Building archive..."
tar czf "$ARCHIVE" \
  -C "$PROJECT_ROOT" \
  --exclude='.git' \
  --exclude='.env' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='logs' \
  --exclude='data' \
  --exclude='geoip/*.mmdb' \
  --exclude='draft_info' \
  --exclude='.venv' \
  --exclude='.terraform' \
  --exclude='*.tfstate' \
  --exclude='*.tfstate.*' \
  .
echo "   Archive: $(du -sh "$ARCHIVE" | cut -f1)"

echo "==> Uploading to $HONEYPOT_VPS ..."
scp "${SCP_OPTS[@]}" "$ARCHIVE" "$HONEYPOT_VPS:/tmp/honeypot-deploy.tar.gz"

echo "==> Extracting on VPS ..."
ssh "${SSH_OPTS[@]}" "$HONEYPOT_VPS" "
  find /opt/honeypot -type d -not -name 'exports' -not -name 'pcap' | xargs chmod 755 2>/dev/null || true
  cd /opt/honeypot
  tar xzf /tmp/honeypot-deploy.tar.gz --overwrite
  rm /tmp/honeypot-deploy.tar.gz
  chmod +x scripts/deploy.sh scripts/sync-logs.sh scripts/conpot-watchdog.sh firewall/iptables-rules.sh 2>/dev/null || true
  echo 'Extraction OK'
"

echo "==> Installing Conpot watchdog timer ..."
ssh "${SSH_OPTS[@]}" "$HONEYPOT_VPS" '
  sudo install -m 0755 /opt/honeypot/scripts/conpot-watchdog.sh /usr/local/sbin/conpot-watchdog.sh
  sudo install -m 0644 /opt/honeypot/scripts/conpot-watchdog.service /etc/systemd/system/conpot-watchdog.service
  sudo install -m 0644 /opt/honeypot/scripts/conpot-watchdog.timer /etc/systemd/system/conpot-watchdog.timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now conpot-watchdog.timer
'

echo "==> Checking secrets on VPS ..."
ssh "${SSH_OPTS[@]}" "$HONEYPOT_VPS" '
  if [[ ! -f /opt/honeypot/.env ]]; then
    echo ""
    echo "WARNING: /opt/honeypot/.env does not exist on the VPS."
    echo "         docker compose will fail without it."
    echo "         Create it before starting containers, e.g.:"
    echo "           echo GRAFANA_ADMIN_PASSWORD=<yourpassword> > /opt/honeypot/.env"
    echo ""
  fi
'

rm -f "$ARCHIVE"

if $REBUILD; then
  echo ""
  echo "==> Pulling updated base images, rebuilding, and restarting all containers ..."
  ssh "${SSH_OPTS[@]}" "$HONEYPOT_VPS" \
    "cd /opt/honeypot && docker compose pull && docker compose build --pull && docker compose up -d"
else
  echo ""
  echo "==> Restarting config-driven containers (no rebuild) ..."
  # These containers pick up bind-mounted config changes immediately on restart.
  # Containers using pre-built images (loki, grafana, promtail, mosquitto, conpot)
  # don't need a restart for config-only changes.
  ssh "${SSH_OPTS[@]}" "$HONEYPOT_VPS" \
    "cd /opt/honeypot && docker compose up -d --no-build flask-honeypot nginx-proxy mqtt-honeypot cowrie"
fi

echo ""
echo "==> Container status:"
ssh "${SSH_OPTS[@]}" "$HONEYPOT_VPS" \
  "docker compose -f /opt/honeypot/docker-compose.yml ps --format 'table {{.Name}}\t{{.Status}}'"

echo ""
echo "==> Watchdog status:"
ssh "${SSH_OPTS[@]}" "$HONEYPOT_VPS" \
  "systemctl --no-pager --plain status conpot-watchdog.timer | sed -n '1,8p'"

echo ""
echo "Deploy complete."
