"""Phase 6: Sensitive Data Discovery - data pattern scan.

Where phase6_scan_schema.py asks "which column *names* look sensitive?", this script
asks "where is sensitive data *actually* sitting?" It samples real rows from every
text-like column and runs regexes for email, phone, credit card (Luhn-validated) and
SSN over the values.

The most valuable findings are PII in columns whose *name* gives no hint - e.g. the
free-text `activity_logs.notes`, where the Phase 2 seeder deliberately plants emails,
phone numbers, card numbers and SSNs that name-based discovery and view/RBAC masking
would miss.

Each finding also gets an `access_verdict`: it cross-checks grants to decide whether a
low-priv account (default `appuser`) can SELECT the underlying base table directly. If
so the PII is reachable raw -> EXPOSED, and the real values are recorded in
`exposed_values` as proof; otherwise PROTECTED. Because EXPOSED findings carry real
PII, the output files are .gitignore'd. Use --mask-all for a safe, shareable report.

Outputs (logs/discovery/):
  - data_findings.json  (one record per table/column/pattern)
  - data_findings.csv   (flat table)
  - stdout summary

Usage:
  python3 scripts/phase6_scan_data_patterns.py [--limit 1000] [--examples 3]
                                               [--app-users appuser] [--mask-all]
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv
import mysql.connector

# Reuse the name-based classifier so we can tell "expected" PII columns (name already
# looks sensitive) apart from leaks (PII in an innocuously-named free-text column).
from phase6_scan_schema import classify

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "logs" / "discovery"
FINDINGS_JSON = OUT_DIR / "data_findings.json"
FINDINGS_CSV = OUT_DIR / "data_findings.csv"

DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_HOST_PORT", "3307")),
    "user": "root",
    "password": os.getenv("MYSQL_ROOT_PASSWORD", "rootpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
}
TARGET_SCHEMA = os.getenv("MYSQL_DATABASE", "testdb")

# Text-like SQL types worth scanning for embedded PII.
TEXT_TYPES = {"char", "varchar", "tinytext", "text", "mediumtext", "longtext", "enum", "set"}

PATTERNS = {
    "EMAIL": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    # Candidate card number: 13-19 digits possibly split by spaces/dashes. Validated in
    # find_matches() by length + IIN prefix + Luhn to cut false positives.
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    # Phone is matched last and is the loosest; kept conservative to limit noise.
    "PHONE": re.compile(r"(?<!\d)(?:\+?\d{1,3}[-. ]?)?(?:\(\d{2,4}\)[-. ]?)?\d{3}[-. ]\d{3,4}(?:[-. ]?\d{2,4})?(?:\s?x\d+)?(?!\d)"),
}

# Used to suppress phone false positives: dotted IPv4 quads (e.g. 192.168.1.1) look
# phone-like to the loose phone regex.
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Common card lengths (Visa 13/16/19, Diners 14, Amex 15, MC/Discover 16).
CARD_LENGTHS = {13, 14, 15, 16, 19}

# Severity + remediation per PII type when found in data.
PATTERN_META = {
    "CREDIT_CARD": ("HIGH", "Encrypt at rest (Acra) + mask to last 4; never store in free-text."),
    "SSN": ("HIGH", "Encrypt at rest + mask (***-**-1234); never store in free-text."),
    "EMAIL": ("MEDIUM", "Mask via view; if in free-text, redact at write time."),
    "PHONE": ("MEDIUM", "Mask all but last 3-4 digits; redact from free-text."),
}

# Low-privilege application accounts whose access we audit. If one of these can SELECT
# a PII-bearing base table directly (i.e. NOT only through a masked view), the masking/
# RBAC layer is insufficient for that data. Infra accounts (root, dbfuser, monitor,
# exporter) are intentionally excluded - they are not the untrusted app identity.
DEFAULT_APP_USERS = ["appuser"]


def connect():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"[ERROR] Cannot connect to MySQL: {err}", file=sys.stderr)
        sys.exit(1)


def luhn_ok(digits):
    """Standard Luhn checksum; `digits` is a string of 13-19 digits."""
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_matches(pattern_type, regex, text):
    """Yield raw matched substrings for a pattern, with validation where relevant."""
    # Phone false-positive guard: spans of any IPv4 address in this text.
    ip_spans = [m.span() for m in IPV4.finditer(text)] if pattern_type == "PHONE" else []
    for m in regex.finditer(text):
        raw = m.group(0)
        if pattern_type == "CREDIT_CARD":
            digits = re.sub(r"\D", "", raw)
            # Real cards: known length, valid IIN first digit (2=MC 2-series, 3=Amex/
            # Diners/JCB, 4=Visa, 5=MC, 6=Discover/UnionPay), Luhn-valid.
            if len(digits) not in CARD_LENGTHS or digits[0] not in "23456" or not luhn_ok(digits):
                continue
        if pattern_type == "PHONE":
            s, e = m.span()
            # Drop matches that fall inside an IPv4 address (e.g. "192.168.1").
            if any(not (e <= a or s >= b) for a, b in ip_spans):
                continue
            digits = re.sub(r"\D", "", raw)
            if not (7 <= len(digits) <= 15):
                continue
        yield raw


def text_columns(cursor):
    cursor.execute(
        """
        SELECT table_name, column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = %s AND data_type IN ({})
        ORDER BY table_name, ordinal_position
        """.format(",".join(["%s"] * len(TEXT_TYPES))),
        (TARGET_SCHEMA, *sorted(TEXT_TYPES)),
    )
    return cursor.fetchall()


def _grantee_user(grantee):
    """'appuser'@'%' -> appuser."""
    return grantee.split("@", 1)[0].strip().strip("'\"`")


def base_tables(cursor):
    """Object name -> table_type ('BASE TABLE' | 'VIEW') for the target schema."""
    cursor.execute(
        "SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = %s",
        (TARGET_SCHEMA,),
    )
    return {name: ttype for name, ttype in cursor.fetchall()}


def app_readable_objects(cursor, app_users):
    """For each app user, the objects they can SELECT *directly* and via which grant.

    Returns {user: {object_name: grant_reason}}. Combines schema-level grants (ON db.*)
    and table-level grants; table-level is more specific and overrides. Reading PII
    through a masked view is fine; direct SELECT on the underlying base table is the
    risk, and the grant_reason tells us exactly how that access was given.
    """
    readable = {u: {} for u in app_users}
    all_objs = set(base_tables(cursor).keys())

    # Schema-wide SELECT grants the user every object in the schema.
    cursor.execute(
        "SELECT grantee, privilege_type FROM information_schema.schema_privileges "
        "WHERE table_schema = %s",
        (TARGET_SCHEMA,),
    )
    for grantee, priv in cursor.fetchall():
        u = _grantee_user(grantee)
        if u in readable and priv == "SELECT":
            for obj in all_objs:
                readable[u].setdefault(obj, f"schema-level SELECT on {TARGET_SCHEMA}.*")

    # Table/view level SELECT grants (more specific -> override).
    cursor.execute(
        "SELECT grantee, table_name, privilege_type FROM information_schema.table_privileges "
        "WHERE table_schema = %s",
        (TARGET_SCHEMA,),
    )
    for grantee, table, priv in cursor.fetchall():
        u = _grantee_user(grantee)
        if u in readable and priv == "SELECT":
            readable[u][table] = f"table-level SELECT on {table}"
    return readable


def scan(cursor, limit, max_examples, app_users, reveal_exposed):
    findings = []
    obj_types = base_tables(cursor)
    readable = app_readable_objects(cursor, app_users)
    columns = text_columns(cursor)
    for table, column, _dtype in columns:
        cursor.execute(
            f"SELECT `{column}` FROM `{table}` WHERE `{column}` IS NOT NULL LIMIT %s",
            (limit,),
        )
        rows = cursor.fetchall()

        # pattern -> {count, rows, raw (unmasked sample kept as exposed-PII proof)}
        agg = defaultdict(lambda: {"count": 0, "rows": set(), "raw": []})
        for idx, (val,) in enumerate(rows):
            text = val if isinstance(val, str) else str(val)
            for ptype, regex in PATTERNS.items():
                for raw in find_matches(ptype, regex, text):
                    a = agg[ptype]
                    a["count"] += 1
                    a["rows"].add(idx)
                    if len(a["raw"]) < max_examples:
                        a["raw"].append(raw.strip())

        # A leak = PII in a column whose name gives no hint (free-text), so no masking was
        # ever designed for it. This is the "why it leaked", folded into the assessment.
        is_leak = classify(column) is None
        where = "leaked into free-text column" if is_leak else "in PII column"

        # Access exposure: a low-priv account reading a BASE TABLE directly sees raw PII;
        # reading through a VIEW is the masking layer itself, so not an exposure.
        is_base_table = obj_types.get(table) == "BASE TABLE"
        exposed_to = sorted(u for u in app_users if table in readable[u]) if is_base_table else []
        access_verdict = "EXPOSED" if exposed_to else "PROTECTED"
        # The exact grant(s) that cause the exposure (the "why"). Empty when PROTECTED.
        exposure_path = [f"{u}: {readable[u][table]}" for u in exposed_to]

        for ptype, a in agg.items():
            if a["count"] == 0:
                continue
            severity, remediation = PATTERN_META[ptype]
            if is_leak:
                remediation = f"LEAK in free-text: {remediation}"
            if access_verdict == "EXPOSED":
                remediation = (f"{remediation} App user(s) {exposed_to} can SELECT this raw "
                               f"table - add a masked view + REVOKE direct access.")
                assessment = (
                    f"{a['count']} raw {ptype} value(s) {where} {table}.{column}, readable by "
                    f"low-priv account(s) via {'; '.join(exposure_path)}; no masked view in "
                    f"between -> low-priv account sees the real PII."
                )
            else:
                assessment = (
                    f"{a['count']} {ptype} value(s) {where} {table}.{column}, but no audited "
                    f"low-priv account ({app_users}) can SELECT it directly (only admin/root, "
                    f"or low-priv via a masked view) -> not exposed."
                )
            # Raw PII proof, ONLY for findings actually exposed to a low-priv account
            # (and only when not in --mask-all mode). Limits real PII landing in the file.
            exposed_values = a["raw"] if (access_verdict == "EXPOSED" and reveal_exposed) else []
            findings.append({
                "table": table,
                "column": column,
                "pattern_type": ptype,
                "severity": severity,
                "access_verdict": access_verdict,
                "exposed_to": exposed_to,
                "exposure_path": exposure_path,
                "assessment": assessment,
                "match_count": a["count"],
                "rows_affected": len(a["rows"]),
                "exposed_values": exposed_values,
                "remediation": remediation,
            })
    return findings


def write_outputs(findings):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_JSON.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    with FINDINGS_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "table", "column", "pattern_type", "severity", "access_verdict",
            "exposed_to", "exposure_path", "assessment", "match_count", "rows_affected",
            "exposed_values_RAW", "remediation",
        ])
        for r in findings:
            w.writerow([
                r["table"], r["column"], r["pattern_type"], r["severity"],
                r["access_verdict"], ";".join(r["exposed_to"]), "; ".join(r["exposure_path"]),
                r["assessment"], r["match_count"], r["rows_affected"],
                "; ".join(r["exposed_values"]), r["remediation"],
            ])


def main():
    ap = argparse.ArgumentParser(description="Phase 6 data pattern scan")
    ap.add_argument("--limit", type=int, default=1000, help="max rows sampled per column")
    ap.add_argument("--examples", type=int, default=3, help="masked examples kept per finding")
    ap.add_argument("--app-users", default=",".join(DEFAULT_APP_USERS),
                    help="comma-separated low-priv accounts to audit for direct PII access")
    ap.add_argument("--mask-all", action="store_true",
                    help="keep EXPOSED values masked too (safe mode; no raw PII in report)")
    args = ap.parse_args()
    app_users = [u.strip() for u in args.app_users.split(",") if u.strip()]
    reveal_exposed = not args.mask_all

    conn = connect()
    cursor = conn.cursor()
    try:
        findings = scan(cursor, args.limit, args.examples, app_users, reveal_exposed)
    finally:
        cursor.close()
        conn.close()

    sev_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings.sort(key=lambda r: (r["access_verdict"] != "EXPOSED",
                                 -sev_rank[r["severity"]], r["table"], r["column"]))
    write_outputs(findings)

    exposed = [f for f in findings if f["access_verdict"] == "EXPOSED"]

    print(f"== Phase 6 data pattern scan: database '{TARGET_SCHEMA}' ==")
    print(f"App users audited : {app_users}")
    print(f"Findings          : {len(findings)} (low-priv exposures: {len(exposed)})")
    print()
    print(f"{'TABLE':<16}{'COLUMN':<14}{'PII':<13}{'ACCESS':<11}{'MATCHES':<9}{'SEV':<8}")
    print("-" * 70)
    for r in findings:
        print(f"{r['table']:<16}{r['column']:<14}{r['pattern_type']:<13}"
              f"{r['access_verdict']:<11}{r['match_count']:<9}{r['severity']:<8}")

    if exposed:
        print()
        print("[!!] MASKING/RBAC INSUFFICIENT - low-priv account can read raw PII directly:")
        for r in exposed:
            vals = ", ".join(r["exposed_values"]) if r["exposed_values"] else "(masked)"
            print(f"    - {r['exposed_to']} can SELECT {r['table']}.{r['column']} "
                  f"({r['pattern_type']}) -> actual exposed PII: {vals}")

    wrote_raw = any(f["exposed_values"] for f in findings)
    print()
    if wrote_raw:
        print("[WARNING] data_findings now contains REAL unmasked PII for EXPOSED findings.")
        print("          It is .gitignore'd (logs/**/*.json|csv); do NOT commit or share it.")
        print("          Re-run with --mask-all for a safe, shareable report.")
    print(f"JSON: {FINDINGS_JSON}")
    print(f"CSV : {FINDINGS_CSV}")


if __name__ == "__main__":
    main()
