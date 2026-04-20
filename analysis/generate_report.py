#!/usr/bin/env python3
"""
generate_report.py — summary statistics from ip_profiles.json for research/publication.

Usage:
    python analysis/generate_report.py                        # yesterday
    python analysis/generate_report.py 2026-04-15             # specific date
    python analysis/generate_report.py 2026-04-10 2026-04-19  # date range

Input:  logs/analysis/LABEL/ip_profiles.json  (from enrich_ips.py)
Output: logs/analysis/LABEL/report.json
        logs/analysis/LABEL/report.txt
"""

import json
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
ANALYSIS_DIR = PROJECT_DIR / "logs" / "analysis"


def _top_n(counter: Counter, n: int = 20) -> list:
    return [{"value": k, "count": v} for k, v in counter.most_common(n)]


def build_report(profiles: dict) -> dict:
    total_events = sum(p["event_count"] for p in profiles.values())

    country_events: Counter = Counter()
    asn_events: Counter = Counter()
    protocol_ips: Counter = Counter()
    ssh_cred_counter: Counter = Counter()
    http_path_counter: Counter = Counter()
    cmd_counter: Counter = Counter()
    modbus_event_counter: Counter = Counter()
    mqtt_cred_counter: Counter = Counter()
    cross_protocol: list = []

    for ip, p in profiles.items():
        geo = p.get("geo", {})
        cc = geo.get("country_code") or "XX"
        cn = geo.get("country_name") or "Unknown"
        country_events[(cc, cn)] += p["event_count"]

        asn_num = geo.get("asn")
        asn_org = geo.get("asn_org") or "Unknown"
        if asn_num:
            asn_events[(asn_num, asn_org)] += p["event_count"]

        for proto in p.get("protocols", []):
            protocol_ips[proto] += 1

        if len(p.get("protocols", [])) >= 2:
            cross_protocol.append({
                "ip": ip,
                "protocols": p["protocols"],
                "event_count": p["event_count"],
            })

        for entry in p.get("ssh_credentials", []):
            ssh_cred_counter[entry["cred"]] += entry["count"]

        for entry in p.get("http_paths", []):
            http_path_counter[entry["path"]] += entry["count"]

        for entry in p.get("cowrie_commands", []):
            cmd_counter[entry["cmd"]] += entry["count"]

        for entry in p.get("modbus_events", []):
            modbus_event_counter[entry["event"]] += entry["count"]

        for entry in p.get("mqtt_credentials", []):
            mqtt_cred_counter[entry["cred"]] += entry["count"]

    ssh_user_counter: Counter = Counter()
    ssh_pw_counter: Counter = Counter()
    for cred_str, count in ssh_cred_counter.items():
        if ":" in cred_str:
            user, pw = cred_str.split(":", 1)
            ssh_user_counter[user] += count
            ssh_pw_counter[pw] += count

    return {
        "summary": {
            "unique_ips": len(profiles),
            "total_events": total_events,
            "unique_countries": len({cc for cc, _ in country_events}),
            "unique_asns": len(asn_events),
            "cross_protocol_ips": len(cross_protocol),
        },
        "top_countries": [
            {"country_code": cc, "country_name": cn, "event_count": count}
            for (cc, cn), count in country_events.most_common(20)
        ],
        "top_asns": [
            {"asn": asn, "org": org, "event_count": count}
            for (asn, org), count in asn_events.most_common(20)
        ],
        "protocol_breakdown": dict(protocol_ips),
        "top_ssh_usernames": _top_n(ssh_user_counter),
        "top_ssh_passwords": _top_n(ssh_pw_counter),
        "top_ssh_credentials": _top_n(ssh_cred_counter),
        "top_http_paths": _top_n(http_path_counter),
        "top_cowrie_commands": _top_n(cmd_counter),
        "modbus_events": dict(modbus_event_counter),
        "top_mqtt_credentials": _top_n(mqtt_cred_counter),
        "cross_protocol_attackers": sorted(cross_protocol, key=lambda x: -x["event_count"])[:50],
    }


def _fmt(report: dict, label: str) -> str:
    s = report["summary"]
    lines = [
        f"Honeypot Attack Report — {label}",
        "=" * 60,
        "",
        "SUMMARY",
        f"  Unique attacker IPs  : {s['unique_ips']}",
        f"  Total events         : {s['total_events']}",
        f"  Countries of origin  : {s['unique_countries']}",
        f"  Unique ASNs          : {s['unique_asns']}",
        f"  Cross-protocol IPs   : {s['cross_protocol_ips']}",
        "",
        "PROTOCOL BREAKDOWN (unique IPs per protocol)",
    ]
    for proto, cnt in sorted(report["protocol_breakdown"].items(), key=lambda x: -x[1]):
        lines.append(f"  {proto:<12} {cnt}")

    lines += ["", "TOP SOURCE COUNTRIES (by event count)"]
    for c in report["top_countries"][:15]:
        lines.append(f"  {c['country_code']:<4} {c['country_name']:<30} {c['event_count']}")

    lines += ["", "TOP SOURCE ASNs"]
    for a in report["top_asns"][:10]:
        lines.append(f"  AS{a['asn']:<8} {a['org']:<40} {a['event_count']}")

    lines += ["", "TOP SSH USERNAMES"]
    for u in report["top_ssh_usernames"][:15]:
        lines.append(f"  {u['count']:>6}  {u['value']}")

    lines += ["", "TOP SSH PASSWORDS"]
    for pw in report["top_ssh_passwords"][:15]:
        lines.append(f"  {pw['count']:>6}  {pw['value']}")

    if report.get("top_cowrie_commands"):
        lines += ["", "TOP COWRIE COMMANDS"]
        for c in report["top_cowrie_commands"][:20]:
            lines.append(f"  {c['count']:>6}  {c['value'][:80]}")

    if report.get("top_http_paths"):
        lines += ["", "TOP HTTP PATHS"]
        for p in report["top_http_paths"][:15]:
            lines.append(f"  {p['count']:>6}  {p['value']}")

    if report.get("modbus_events"):
        lines += ["", "MODBUS EVENTS"]
        for ev, cnt in sorted(report["modbus_events"].items(), key=lambda x: -x[1]):
            lines.append(f"  {cnt:>6}  {ev}")

    if report.get("top_mqtt_credentials"):
        lines += ["", "TOP MQTT CREDENTIALS"]
        for c in report["top_mqtt_credentials"][:10]:
            lines.append(f"  {c['count']:>6}  {c['value']}")

    if report.get("cross_protocol_attackers"):
        lines += ["", "CROSS-PROTOCOL ATTACKERS (top 10)"]
        for a in report["cross_protocol_attackers"][:10]:
            protos = ",".join(a["protocols"])
            lines.append(f"  {a['ip']:<20} protocols={protos}  events={a['event_count']}")

    return "\n".join(lines) + "\n"


def date_range(start: str, end: str):
    from datetime import date
    current = date.fromisoformat(start)
    stop = date.fromisoformat(end)
    while current <= stop:
        yield current.isoformat()
        current += timedelta(days=1)


def main():
    args = sys.argv[1:]
    if not args:
        label = (date.today() - timedelta(days=1)).isoformat()
    elif len(args) == 1:
        label = args[0]
    elif len(args) == 2:
        label = f"{args[0]}_{args[1]}"
    else:
        print("Usage: generate_report.py [start_date [end_date]]", file=sys.stderr)
        sys.exit(1)

    profile_file = ANALYSIS_DIR / label / "ip_profiles.json"
    if not profile_file.exists():
        print(f"ip_profiles.json not found: {profile_file}", file=sys.stderr)
        print("Run analysis/enrich_ips.py first.", file=sys.stderr)
        sys.exit(1)

    with open(profile_file, encoding="utf-8") as f:
        profiles = json.load(f)

    report = build_report(profiles)

    out_dir = ANALYSIS_DIR / label
    json_out = out_dir / "report.json"
    txt_out = out_dir / "report.txt"

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    text = _fmt(report, label)
    with open(txt_out, "w", encoding="utf-8") as f:
        f.write(text)

    print(text)
    print(f"  JSON -> {json_out}")


if __name__ == "__main__":
    main()
