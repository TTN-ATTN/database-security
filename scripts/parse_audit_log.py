"""Phase 3: parse MySQL general.log and slow.log into structured audit evidence.

Outputs:
  - logs/mysql/audit_report.json  (per-event records)
  - logs/mysql/audit_summary.csv  (per-category counts)
  - stdout summary

The general log format on MySQL 8.4:
    2026-05-21T10:11:12.345678Z   42 Query     SELECT ...
    2026-05-21T10:11:12.345678Z   42 Connect   appuser@172.18.0.5 on testdb using TCP/IP

The slow log format:
    # Time: 2026-05-21T10:11:12.345678Z
    # User@Host: appuser[appuser] @  [172.18.0.5]  Id: 42
    # Query_time: 1.234567  Lock_time: 0.000123 Rows_sent: 100  Rows_examined: 50000
    SET timestamp=1700000000;
    SELECT ...;
"""

import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs" / "mysql"
GENERAL_LOG = LOG_DIR / "general.log"
SLOW_LOG = LOG_DIR / "slow.log"
REPORT_JSON = LOG_DIR / "audit_report.json"
SUMMARY_CSV = LOG_DIR / "audit_summary.csv"

PHASE3_TAG = re.compile(r"/\* phase3:([\w\-]+) \*/")
GENERAL_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+(?P<cid>\d+)\s+(?P<cmd>\w+)\s*(?P<arg>.*)$"
)
SLOW_USER_HOST = re.compile(
    r"^# User@Host:\s+(?P<user>[\w\[\]]+)\s+@\s+(?P<host>\S*)\s+\[(?P<ip>[^\]]*)\]"
)
SLOW_QUERY_TIME = re.compile(r"^# Query_time:\s+(?P<qt>[\d.]+)\s+.*Rows_examined:\s+(?P<rex>\d+)")
SLOW_TIME = re.compile(r"^# Time:\s+(?P<ts>\S+)")


def parse_general():
    events = []
    if not GENERAL_LOG.exists():
        return events
    current = None
    with GENERAL_LOG.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            m = GENERAL_LINE.match(line)
            if m:
                if current:
                    events.append(current)
                arg = m.group("arg").strip()
                tag = PHASE3_TAG.search(arg)
                current = {
                    "source": "general",
                    "timestamp": m.group("ts"),
                    "connection_id": int(m.group("cid")),
                    "command": m.group("cmd"),
                    "argument": arg,
                    "phase3_tag": tag.group(1) if tag else None,
                }
            else:
                if current:
                    current["argument"] += " " + line.strip()
        if current:
            events.append(current)
    return events


def parse_slow():
    events = []
    if not SLOW_LOG.exists():
        return events
    with SLOW_LOG.open("r", encoding="utf-8", errors="replace") as f:
        block = []
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith("# Time:") and block:
                events.append(_finalize_slow_block(block))
                block = [line]
            else:
                block.append(line)
        if block:
            events.append(_finalize_slow_block(block))
    return [e for e in events if e]


def _finalize_slow_block(lines):
    ev = {"source": "slow", "phase3_tag": None}
    query_parts = []
    for line in lines:
        m = SLOW_TIME.match(line)
        if m:
            ev["timestamp"] = m.group("ts")
            continue
        m = SLOW_USER_HOST.match(line)
        if m:
            ev["user"] = m.group("user")
            ev["ip"] = m.group("ip")
            continue
        m = SLOW_QUERY_TIME.match(line)
        if m:
            ev["query_time"] = float(m.group("qt"))
            ev["rows_examined"] = int(m.group("rex"))
            continue
        if line.startswith("#") or line.startswith("SET timestamp") or line.startswith("use "):
            continue
        if line.strip():
            query_parts.append(line.strip().rstrip(";"))
    if not query_parts:
        return None
    ev["query"] = " ".join(query_parts)
    tag = PHASE3_TAG.search(ev["query"])
    if tag:
        ev["phase3_tag"] = tag.group(1)
    return ev


def summarize(events):
    by_tag = Counter()
    by_command = Counter()
    pii_hits = []
    denied_attempts = []
    slow_queries = []
    for e in events:
        if e.get("phase3_tag"):
            by_tag[e["phase3_tag"]] += 1
        if e["source"] == "general":
            by_command[e["command"]] += 1
            arg = e.get("argument", "")
            if any(k in arg.lower() for k in ("credit_card", "ssn", " email", "phone")) and "from users" in arg.lower():
                pii_hits.append(e)
        if e["source"] == "slow":
            slow_queries.append(e)
    return {
        "total_events": len(events),
        "by_phase3_tag": dict(by_tag),
        "by_command": dict(by_command),
        "pii_table_hits": len(pii_hits),
        "slow_query_count": len(slow_queries),
    }


def main():
    if not GENERAL_LOG.exists() and not SLOW_LOG.exists():
        print(f"[ERROR] No logs found in {LOG_DIR}", file=sys.stderr)
        sys.exit(1)

    general = parse_general()
    slow = parse_slow()
    all_events = general + slow
    summary = summarize(all_events)

    REPORT_JSON.write_text(json.dumps(all_events, indent=2, default=str), encoding="utf-8")

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "count"])
        w.writerow(["total_events", summary["total_events"]])
        w.writerow(["pii_table_hits", summary["pii_table_hits"]])
        w.writerow(["slow_query_count", summary["slow_query_count"]])
        for tag, n in sorted(summary["by_phase3_tag"].items()):
            w.writerow([f"tag:{tag}", n])
        for cmd, n in sorted(summary["by_command"].items()):
            w.writerow([f"cmd:{cmd}", n])

    print(f"Parsed {len(general)} general-log events, {len(slow)} slow-log events")
    print(f"Total: {summary['total_events']}")
    print(f"PII table direct hits: {summary['pii_table_hits']}")
    print(f"Slow queries: {summary['slow_query_count']}")
    print("Events per phase3 tag:")
    for k, v in sorted(summary["by_phase3_tag"].items()):
        print(f"  {k}: {v}")
    print(f"\nJSON: {REPORT_JSON}")
    print(f"CSV : {SUMMARY_CSV}")


if __name__ == "__main__":
    main()
