#!/usr/bin/env python3
"""
enrich_ips.py — aggregate enriched NDJSON logs into a per-IP attacker profile database.

Usage:
    python analysis/enrich_ips.py                        # yesterday
    python analysis/enrich_ips.py 2026-04-15             # specific date
    python analysis/enrich_ips.py 2026-04-10 2026-04-19  # date range

Input:  logs/enriched/YYYY-MM-DD/honeypot_enriched.ndjson  (from scripts/enrich.py)
Output: logs/analysis/LABEL/ip_profiles.json

Each profile:
    {
        "ip": "1.2.3.4",
        "geo": {"country_code": "CN", "asn": 4134, "asn_org": "CHINANET", ...},
        "protocols": ["modbus", "ssh"],
        "event_count": 42,
        "first_seen": "2026-04-15T00:00:00Z",
        "last_seen":  "2026-04-19T23:59:59Z",
        "ssh_credentials":  [{"cred": "root:admin", "count": 7}, ...],
        "http_paths":       [{"path": "/login",     "count": 3}, ...],
        "cowrie_commands":  [{"cmd":  "uname -a",   "count": 2}, ...],
        "modbus_events":    [{"event": "modbus_fc43_intercepted", "count": 1}, ...],
        "mqtt_credentials": [{"cred": "admin:admin", "count": 1}, ...]
    }
"""

import gzip
import json
import sys
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
ENRICHED_DIR = PROJECT_DIR / "logs" / "enriched"
ANALYSIS_DIR = PROJECT_DIR / "logs" / "analysis"

_PRIVATE_PREFIXES = (
    "10.", "127.", "::1",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
)


def _is_private(ip: str) -> bool:
    return not ip or any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _ns_to_iso(ts_ns: str) -> str:
    try:
        return datetime.fromtimestamp(int(ts_ns) / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return ""


def _open(path: Path):
    return gzip.open(path, "rt", encoding="utf-8") if path.suffix == ".gz" else open(path, encoding="utf-8")


def _find_enriched(export_date: str):
    for name in ("honeypot_enriched.ndjson", "honeypot_enriched.ndjson.gz"):
        p = ENRICHED_DIR / export_date / name
        if p.exists():
            return p
    return None


def process_dates(dates: list) -> dict:
    profiles: dict = {}

    for d in dates:
        src = _find_enriched(d)
        if src is None:
            print(f"  [{d}] enriched file not found — run scripts/enrich.py first", file=sys.stderr)
            continue

        with _open(src) as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                try:
                    line = json.loads(rec.get("line", "{}"))
                except (json.JSONDecodeError, AttributeError):
                    line = {}

                ip = line.get("src_ip") or line.get("src") or ""
                if not ip or _is_private(ip):
                    continue

                if ip not in profiles:
                    profiles[ip] = {
                        "geo": {},
                        "protocols": set(),
                        "event_count": 0,
                        "first_seen": "",
                        "last_seen": "",
                        "_ssh_creds": defaultdict(int),
                        "_http_paths": defaultdict(int),
                        "_commands": defaultdict(int),
                        "_modbus_events": defaultdict(int),
                        "_mqtt_creds": defaultdict(int),
                    }

                p = profiles[ip]
                p["event_count"] += 1

                if not p["geo"] and rec.get("geo"):
                    p["geo"] = rec["geo"]

                ts = rec.get("ts", "")
                if ts:
                    if not p["first_seen"] or ts < p["first_seen"]:
                        p["first_seen"] = ts
                    if ts > p["last_seen"]:
                        p["last_seen"] = ts

                labels = rec.get("labels", {})
                container = labels.get("container", "")
                event = line.get("event", "") or labels.get("event", "")

                if container in ("cowrie", "cowrie-honeypot") or event.startswith("cowrie."):
                    p["protocols"].add("ssh")
                elif container == "flask-honeypot" or event.startswith("http_"):
                    p["protocols"].add("http")
                elif container in ("modbus-proxy", "conpot") or "modbus" in event:
                    p["protocols"].add("modbus")
                elif container == "mqtt-honeypot" or "mqtt" in event:
                    p["protocols"].add("mqtt")

                if event in ("cowrie.login.failed", "cowrie.login.success"):
                    user = line.get("username", "")
                    pw = line.get("password", "")
                    if user or pw:
                        p["_ssh_creds"][f"{user}:{pw}"] += 1

                elif event == "cowrie.command.input":
                    cmd = line.get("input", "")
                    if cmd:
                        p["_commands"][cmd] += 1

                elif event in ("http_request", "http_login"):
                    path = line.get("path", "")
                    if path:
                        p["_http_paths"][path] += 1

                elif "modbus" in event:
                    p["_modbus_events"][event] += 1

                elif event in ("mqtt_connect", "mqtt_connect_attempt", "mqtt_publish", "mqtt_subscribe"):
                    user = line.get("username", "")
                    pw = line.get("password", "")
                    if user or pw:
                        p["_mqtt_creds"][f"{user}:{pw}"] += 1

    result = {}
    for ip, p in profiles.items():
        result[ip] = {
            "ip": ip,
            "geo": p["geo"],
            "protocols": sorted(p["protocols"]),
            "event_count": p["event_count"],
            "first_seen": _ns_to_iso(p["first_seen"]),
            "last_seen": _ns_to_iso(p["last_seen"]),
            "ssh_credentials": sorted(
                [{"cred": k, "count": v} for k, v in p["_ssh_creds"].items()],
                key=lambda x: -x["count"],
            ),
            "http_paths": sorted(
                [{"path": k, "count": v} for k, v in p["_http_paths"].items()],
                key=lambda x: -x["count"],
            ),
            "cowrie_commands": sorted(
                [{"cmd": k, "count": v} for k, v in p["_commands"].items()],
                key=lambda x: -x["count"],
            ),
            "modbus_events": sorted(
                [{"event": k, "count": v} for k, v in p["_modbus_events"].items()],
                key=lambda x: -x["count"],
            ),
            "mqtt_credentials": sorted(
                [{"cred": k, "count": v} for k, v in p["_mqtt_creds"].items()],
                key=lambda x: -x["count"],
            ),
        }
    return result


def date_range(start: str, end: str):
    current = date.fromisoformat(start)
    stop = date.fromisoformat(end)
    while current <= stop:
        yield current.isoformat()
        current += timedelta(days=1)


def main():
    args = sys.argv[1:]
    if not args:
        dates = [(date.today() - timedelta(days=1)).isoformat()]
        label = dates[0]
    elif len(args) == 1:
        dates = [args[0]]
        label = args[0]
    elif len(args) == 2:
        dates = list(date_range(args[0], args[1]))
        label = f"{args[0]}_{args[1]}"
    else:
        print("Usage: enrich_ips.py [start_date [end_date]]", file=sys.stderr)
        sys.exit(1)

    profiles = process_dates(dates)

    out_dir = ANALYSIS_DIR / label
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "ip_profiles.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=2, ensure_ascii=False)

    print(f"  {len(profiles)} unique IPs -> {out_file}")


if __name__ == "__main__":
    main()
