#!/usr/bin/env python3
"""
enrich.py — add GeoIP (country, city, ASN) fields to exported honeypot NDJSON logs.

Each input record format (from vps-export.sh):
    {"ts":"<ns>","line":"{\"event\":\"...\",\"src_ip\":\"...\"}","labels":{...}}

Each output record: same structure with an added "geo" key on matching records.

Usage:
    python scripts/enrich.py                    # enriches yesterday's export
    python scripts/enrich.py 2026-04-15         # enriches a specific date
    python scripts/enrich.py 2026-04-10 2026-04-15   # enriches a date range

Output: logs/enriched/YYYY-MM-DD/honeypot_enriched.ndjson

Requirements:
    pip install geoip2
    Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in the geoip/ directory.
    Both are free downloads from maxmind.com (requires free account registration).
"""

import gzip
import json
import sys
from datetime import date, timedelta
from pathlib import Path

try:
    import geoip2.database
    import geoip2.errors
    import maxminddb
except ImportError:
    print("Missing dependency: pip install geoip2", file=sys.stderr)
    sys.exit(1)

# --- Paths ---
SCRIPT_DIR  = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
EXPORTS_DIR = PROJECT_DIR / "logs" / "exports"
ENRICHED_DIR = PROJECT_DIR / "logs" / "enriched"
GEOIP_DIR   = PROJECT_DIR / "geoip"
MMDB_CITY   = GEOIP_DIR / "GeoLite2-City.mmdb"
MMDB_ASN    = GEOIP_DIR / "GeoLite2-ASN.mmdb"

# Private/reserved ranges — no GeoIP lookup needed or possible.
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.", "::1")


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _lookup(city_reader, asn_reader, ip: str) -> dict:
    geo = {}
    try:
        city = city_reader.city(ip)
        geo["country_code"] = city.country.iso_code or ""
        geo["country_name"] = city.country.name or ""
        geo["city"]         = city.city.name or ""
        geo["latitude"]     = city.location.latitude
        geo["longitude"]    = city.location.longitude
    except (geoip2.errors.AddressNotFoundError, ValueError):
        pass

    try:
        asn = asn_reader.asn(ip)
        geo["asn"]     = asn.autonomous_system_number
        geo["asn_org"] = asn.autonomous_system_organization or ""
    except (geoip2.errors.AddressNotFoundError, ValueError):
        pass

    return geo


def _honeypot_export_path(export_date: str) -> Path:
    export_dir = EXPORTS_DIR / export_date
    for name in ("honeypot.ndjson.gz", "honeypot.ndjson"):
        candidate = export_dir / name
        if candidate.exists():
            return candidate
    return export_dir / "honeypot.ndjson.gz"


def enrich_date(export_date: str, city_reader, asn_reader) -> int:
    src = _honeypot_export_path(export_date)
    dst = ENRICHED_DIR / export_date / "honeypot_enriched.ndjson"

    if not src.exists():
        print(f"  [{export_date}] export not found: {src.parent / 'honeypot.ndjson[.gz]'} - skipping", file=sys.stderr)
        return 0

    dst.parent.mkdir(parents=True, exist_ok=True)
    count = enriched = 0
    open_fn = gzip.open if src.suffix == ".gz" else open

    with open_fn(src, "rt", encoding="utf-8") as fin, \
         open(dst, "w", encoding="utf-8") as fout:
        for raw in fin:
            raw = raw.strip()
            if not raw:
                continue
            count += 1
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                fout.write(raw + "\n")
                continue

            # src_ip is inside the nested .line JSON string
            ip = ""
            try:
                line_obj = json.loads(record.get("line", "{}"))
                ip = line_obj.get("src_ip") or line_obj.get("src") or ""
            except (json.JSONDecodeError, AttributeError):
                pass

            if ip and not _is_private(ip):
                record["geo"] = _lookup(city_reader, asn_reader, ip)
                enriched += 1

            fout.write(json.dumps(record) + "\n")

    print(f"  [{export_date}] {count} records, {enriched} geo-enriched -> {dst}")
    return count


def date_range(start: str, end: str):
    """Yield each date string from start to end inclusive."""
    current = date.fromisoformat(start)
    stop    = date.fromisoformat(end)
    while current <= stop:
        yield current.isoformat()
        current += timedelta(days=1)


def main():
    if not MMDB_CITY.exists() or not MMDB_ASN.exists():
        missing = []
        if not MMDB_CITY.exists():
            missing.append("GeoLite2-City.mmdb")
        if not MMDB_ASN.exists():
            missing.append("GeoLite2-ASN.mmdb")
        print(f"Missing GeoIP databases in {GEOIP_DIR}/: {', '.join(missing)}", file=sys.stderr)
        print("Download from https://www.maxmind.com/en/geolite2/signup", file=sys.stderr)
        print("Place both .mmdb files in the geoip/ directory.", file=sys.stderr)
        sys.exit(1)

    args = sys.argv[1:]
    if len(args) == 0:
        dates = [(date.today() - timedelta(days=1)).isoformat()]
    elif len(args) == 1:
        dates = [args[0]]
    elif len(args) == 2:
        dates = list(date_range(args[0], args[1]))
    else:
        print("Usage: enrich.py [start_date [end_date]]", file=sys.stderr)
        sys.exit(1)

    # MODE_FILE forces the pure Python reader — the C extension only accepts
    # path strings and fails on Windows paths with non-ASCII (Cyrillic) chars.
    with geoip2.database.Reader(MMDB_CITY, mode=maxminddb.MODE_FILE) as city_reader, \
         geoip2.database.Reader(MMDB_ASN,  mode=maxminddb.MODE_FILE) as asn_reader:
        for d in dates:
            enrich_date(d, city_reader, asn_reader)


if __name__ == "__main__":
    main()
