#!/bin/bash
# Pull VPS log exports to this machine.
# Run from the project root, WSL, or Git Bash:
#   HONEYPOT_VPS=admin@example.com bash scripts/sync-logs.sh
# If you only have scp, run:
#   HONEYPOT_VPS=admin@example.com bash scripts/sync-logs.sh --scp

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$PROJECT_ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_ROOT/.env"
  set +a
fi

: "${HONEYPOT_VPS:?Set HONEYPOT_VPS, for example admin@203.0.113.10}"

SSH_PORT="${HONEYPOT_SSH_PORT:-2222}"
SSH_KEY="${HONEYPOT_SSH_KEY:-$HOME/.ssh/honeypot_ed25519}"

SSH_OPTS=(-i "$SSH_KEY" -p "$SSH_PORT")
SCP_OPTS=(-i "$SSH_KEY" -P "$SSH_PORT")
LOCAL_LOGS="$PROJECT_ROOT/logs"

mkdir -p "$LOCAL_LOGS/exports" "$LOCAL_LOGS/pcap"

USE_SCP=false
if [[ "${1:-}" == "--scp" ]]; then
  USE_SCP=true
fi

if $USE_SCP; then
  echo "Syncing exports (scp)..."
  scp "${SCP_OPTS[@]}" -r "$HONEYPOT_VPS:/opt/honeypot/exports/." "$LOCAL_LOGS/exports/"

  echo "Syncing PCAP files (scp)..."
  scp "${SCP_OPTS[@]}" -r "$HONEYPOT_VPS:/opt/honeypot/pcap/." "$LOCAL_LOGS/pcap/"
else
  echo "Syncing exports..."
  rsync -avz --progress \
    -e "ssh ${SSH_OPTS[*]}" \
    "$HONEYPOT_VPS:/opt/honeypot/exports/" \
    "$LOCAL_LOGS/exports/"

  echo "Syncing PCAP files (skip files already present)..."
  rsync -avz --progress --ignore-existing \
    -e "ssh ${SSH_OPTS[*]}" \
    "$HONEYPOT_VPS:/opt/honeypot/pcap/" \
    "$LOCAL_LOGS/pcap/"
fi

echo ""
echo "Local log store: $LOCAL_LOGS"
echo "Exports:"
ls -lh "$LOCAL_LOGS/exports/" 2>/dev/null | tail -20
echo "PCAP disk usage: $(du -sh "$LOCAL_LOGS/pcap" 2>/dev/null | cut -f1)"
