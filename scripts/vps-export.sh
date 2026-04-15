#!/bin/bash
# vps-export.sh — export previous day's Loki logs to compressed NDJSON files.
# Each entry: {"ts":"<nanoseconds>","line":"<raw log line>","labels":{...}}
#
# Cron (runs at 02:00 UTC daily):
#   0 2 * * * /opt/honeypot/scripts/vps-export.sh >> /opt/honeypot/exports/export.log 2>&1

set -euo pipefail

DATE="${EXPORT_DATE:-$(date -u -d "yesterday" +%Y-%m-%d)}"
EXPORT_DIR="/opt/honeypot/exports/$DATE"
LOKI_URL="${LOKI_URL:-http://172.30.1.2:3100}"
LIMIT=5000   # max entries per Loki page

mkdir -p "$EXPORT_DIR"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting export for $DATE"

# Nanosecond boundaries for the full previous day (UTC)
START_NS=$(date -u -d "$DATE 00:00:00" +%s)000000000
END_NS=$(date -u -d "$DATE 23:59:59" +%s)999000000

# Query one Loki stream, paginate until exhausted, write NDJSON to $outfile.
export_stream() {
  local selector="$1"   # e.g. {job="honeypot"}
  local outfile="$2"
  local total=0
  local page_start="$START_NS"

  > "$outfile"

  while true; do
    local response
    response=$(curl -sf \
      --data-urlencode "query=$selector" \
      --data-urlencode "start=$page_start" \
      --data-urlencode "end=$END_NS" \
      --data-urlencode "limit=$LIMIT" \
      --data-urlencode "direction=forward" \
      "$LOKI_URL/loki/api/v1/query_range")

    local count
    count=$(echo "$response" | jq '[.data.result[].values | length] | add // 0')

    if [ "$count" -eq 0 ]; then
      break
    fi

    # Flatten each stream's values into individual NDJSON records
    echo "$response" | jq -c '
      .data.result[] as $stream |
      $stream.values[] |
      {ts: .[0], line: .[1], labels: $stream.stream}
    ' >> "$outfile"

    total=$((total + count))

    # If we got fewer than the limit, we've seen everything
    if [ "$count" -lt "$LIMIT" ]; then
      break
    fi

    # Paginate: advance start past the last timestamp we received
    local last_ts
    last_ts=$(echo "$response" | jq -r '[.data.result[].values[-1][0]] | max')
    page_start=$((last_ts + 1))
  done

  echo "  $selector → $total entries"
}

export_stream '{job="honeypot"}' "$EXPORT_DIR/honeypot.ndjson"
export_stream '{job="tcpdump"}' "$EXPORT_DIR/tcpdump.ndjson"

# Snapshot the raw connection log (Promtail source file, not yet in Loki retention)
if cp /var/log/honeypot-connections.log "$EXPORT_DIR/connections.log" 2>/dev/null; then
  echo "  Snapshot: connections.log"
fi

# Compress everything in-place
gzip -f "$EXPORT_DIR"/*.ndjson "$EXPORT_DIR"/*.log 2>/dev/null || true

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Export complete → $EXPORT_DIR ($(du -sh "$EXPORT_DIR" | cut -f1))"

# Prune exports older than 90 days (Loki keeps 60 days; local exports are the long-term archive)
find /opt/honeypot/exports -maxdepth 1 -type d -name "20*" -mtime +90 | while read -r old; do
  echo "  Pruning old export: $old"
  rm -rf "$old"
done
