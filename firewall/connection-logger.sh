#!/bin/bash
# Log TCP connection lifecycle events to honeypot ports as structured JSON.
# Captures SYN (session start), FIN (clean close), RST (abrupt close).
# Output file: /var/log/honeypot-connections.log (watched by Promtail → Loki).
# Correlate SYN + FIN/RST with the same src IP:port to calculate session duration.
LOG_FILE="/var/log/honeypot-connections.log"
PIDFILE="/var/run/connection-logger.pid"

# Prevent two instances running simultaneously (would double every log entry)
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "connection-logger already running as PID $(cat "$PIDFILE"), exiting." >&2
  exit 1
fi
echo $$ > "$PIDFILE"
trap 'rm -f "$PIDFILE"' EXIT

# Resolve the primary interface dynamically; Contabo VPSes often use ens3/ens18, not eth0.
IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
if [[ -z "$IFACE" ]]; then
  echo "connection-logger: could not detect default interface, aborting" >&2
  exit 1
fi

tcpdump -i "$IFACE" -l -n \
  'tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0 and (port 22 or port 23 or port 80 or port 443 or port 1883 or port 502 or port 102)' \
  2>/dev/null | while read line; do
    # Classify event from TCP Flags field
    if echo "$line" | grep -q 'Flags \[S\]'; then
      event="syn"
    elif echo "$line" | grep -q 'Flags \[F\]\|Flags \[F\.\]'; then
      event="fin"
    elif echo "$line" | grep -q 'Flags \[R\]\|Flags \[R\.\]'; then
      event="rst"
    else
      event="other"
    fi

    src_ip=""
    src_port=0
    dst_ip=""
    dst_port=0

    # Parse IPv4: "IP a.b.c.d.sport > e.f.g.h.dport:"
    # awk field 3 = src_addr.port, field 5 = dst_addr.port (with trailing colon)
    if echo "$line" | grep -q ' IP '; then
      src_full=$(echo "$line" | awk '{print $3}')
      src_ip="${src_full%.*}"
      src_port="${src_full##*.}"
      dst_full=$(echo "$line" | awk '{print $5}' | tr -d ':')
      dst_ip="${dst_full%.*}"
      dst_port="${dst_full##*.}"
    fi

    # Ensure ports are numeric (default 0 if parse failed)
    src_port=$((src_port + 0))
    dst_port=$((dst_port + 0))

    echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"event\":\"$event\",\"src_ip\":\"$src_ip\",\"src_port\":$src_port,\"dst_ip\":\"$dst_ip\",\"dst_port\":$dst_port,\"raw\":$(printf '%s' "$line" | jq -Rs .)}" >> "$LOG_FILE"
done
