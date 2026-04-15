#!/bin/bash
# Block outbound internet access from honeypot containers.
# Run as root on the VPS host after Docker has started.

set -euo pipefail

DOCKER_SUBNET="${DOCKER_SUBNET:-172.30.0.0/24}"

echo "Configuring iptables outbound restrictions for $DOCKER_SUBNET..."

iptables -N DOCKER-USER 2>/dev/null || true

ensure_insert_rule() {
  local position="$1"
  shift
  if ! iptables -C DOCKER-USER "$@" 2>/dev/null; then
    iptables -I DOCKER-USER "$position" "$@"
  fi
}

ensure_append_rule() {
  if ! iptables -C DOCKER-USER "$@" 2>/dev/null; then
    iptables -A DOCKER-USER "$@"
  fi
}

# Allow replies to inbound connections.
ensure_insert_rule 1 -s "$DOCKER_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

# Allow inter-container communication on the deterministic Compose subnet.
ensure_insert_rule 2 -s "$DOCKER_SUBNET" -d "$DOCKER_SUBNET" -j RETURN

# Block all other outbound traffic from honeypot containers.
ensure_append_rule -s "$DOCKER_SUBNET" -j DROP

echo "Outbound restrictions applied."
iptables -L DOCKER-USER -n --line-numbers
