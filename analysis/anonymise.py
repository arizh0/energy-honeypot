#!/usr/bin/env python3
"""
anonymise.py — pseudonymise IPs and sanitize credentials for safe publication.

IPs are replaced with a deterministic pseudonym (HMAC-SHA256 truncated to 8 hex chars)
using a per-dataset salt stored in logs/analysis/ip_salt.txt.  Events from the same
real IP get the same pseudonym within the dataset, preserving cross-event correlation
without exposing the real address.  Keep ip_salt.txt private.

Usage:
    python analysis/anonymise.py                        # yesterday
    python analysis/anonymise.py 2026-04-15             # specific date
    python analysis/anonymise.py 2026-04-10 2026-04-19  # date range

Input:  logs/enriched/YYYY-MM-DD/honeypot_enriched.ndjson  (from scripts/enrich.py)
Output: logs/analysis/YYYY-MM-DD/honeypot_anon.ndjson
"""

import gzip
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import date, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
ENRICHED_DIR = PROJECT_DIR / "logs" / "enriched"
ANALYSIS_DIR = PROJECT_DIR / "logs" / "analysis"

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.[a-zA-Z]{2,}")

_IP_FIELDS = ("src_ip", "src", "dst_ip", "dst")
_CRED_FIELDS = ("username", "password")
_TEXT_FIELDS = ("input", "user_agent", "message")


def _pseudo(ip: str, salt: bytes) -> str:
    h = hmac.new(salt, ip.encode(), hashlib.sha256).hexdigest()[:8]
    return f"IP-{h}"


def _scrub_line(line_str: str, salt: bytes) -> str:
    try:
        obj = json.loads(line_str)
    except (json.JSONDecodeError, AttributeError):
        return line_str

    for field in _IP_FIELDS:
        if obj.get(field):
            obj[field] = _pseudo(obj[field], salt)

    for field in _CRED_FIELDS:
        if isinstance(obj.get(field), str):
            obj[field] = _EMAIL_RE.sub("[redacted]", obj[field])

    for field in _TEXT_FIELDS:
        if isinstance(obj.get(field), str):
            obj[field] = _IP_RE.sub("[ip]", obj[field])

    return json.dumps(obj, ensure_ascii=False)


def anonymise_date(export_date: str, salt: bytes) -> int:
    src = ENRICHED_DIR / export_date / "honeypot_enriched.ndjson"
    if not src.exists():
        src_gz = src.with_suffix(".ndjson.gz")
        if src_gz.exists():
            src = src_gz
        else:
            print(f"  [{export_date}] enriched file not found — run scripts/enrich.py first", file=sys.stderr)
            return 0

    out_dir = ANALYSIS_DIR / export_date
    out_dir.mkdir(parents=True, exist_ok=True)
    dst = out_dir / "honeypot_anon.ndjson"

    open_fn = gzip.open if src.suffix == ".gz" else open
    count = 0
    with open_fn(src, "rt", encoding="utf-8") as fin, open(dst, "w", encoding="utf-8") as fout:
        for raw in fin:
            raw = raw.strip()
            if not raw:
                continue
            count += 1
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                fout.write(raw + "\n")
                continue

            rec["line"] = _scrub_line(rec.get("line", "{}"), salt)

            # Keep country/ASN (low-precision, safe to publish); drop precise location
            geo = rec.get("geo", {})
            for precise_field in ("latitude", "longitude", "city"):
                geo.pop(precise_field, None)

            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"  [{export_date}] {count} records -> {dst}")
    return count


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
    elif len(args) == 1:
        dates = [args[0]]
    elif len(args) == 2:
        dates = list(date_range(args[0], args[1]))
    else:
        print("Usage: anonymise.py [start_date [end_date]]", file=sys.stderr)
        sys.exit(1)

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    salt_file = ANALYSIS_DIR / "ip_salt.txt"
    if salt_file.exists():
        salt = bytes.fromhex(salt_file.read_text().strip())
    else:
        salt = os.urandom(32)
        salt_file.write_text(salt.hex())
        print(f"  Generated new salt -> {salt_file}  (keep private, do not commit)")

    for d in dates:
        anonymise_date(d, salt)


if __name__ == "__main__":
    main()
