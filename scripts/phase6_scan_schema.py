"""Phase 6: Sensitive Data Discovery - schema scan.

Scans INFORMATION_SCHEMA.COLUMNS for the target database and flags columns whose
*name* suggests they hold PII or credentials (email, phone, address, credit card,
SSN, password, token, ...). This is the "where could sensitive data live?" pass; the
companion script phase6_scan_data_patterns.py does the "is sensitive data actually
present?" content pass.

For every flagged column it records a PII type, a severity and a concrete remediation
(mask / encrypt / restrict / hash) so the report doubles as an action list.

Outputs (logs/discovery/):
  - schema_findings.json  (one record per flagged column)
  - schema_findings.csv   (flat table for spreadsheets/report)
  - stdout summary

Exit code is non-zero only if it cannot reach MySQL.
"""

import csv
import json
import os
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv
import mysql.connector

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "logs" / "discovery"
FINDINGS_JSON = OUT_DIR / "schema_findings.json"
FINDINGS_CSV = OUT_DIR / "schema_findings.csv"

DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_HOST_PORT", "3307")),
    "user": "root",
    "password": os.getenv("MYSQL_ROOT_PASSWORD", "rootpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
}
TARGET_SCHEMA = os.getenv("MYSQL_DATABASE", "testdb")

# Severity ordering used to pick the most serious match when a column name hits
# more than one category, and to sort the final report.
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Each category: substrings to look for in the lowercased column name, the PII type
# we attribute, a severity, and the recommended remediation.
CATEGORIES = [
    {
        "category": "credential",
        "keywords": ["password", "passwd", "pwd"],
        "pii_type": "CREDENTIAL",
        "severity": "CRITICAL",
        "remediation": "Never store plaintext; hash with bcrypt/argon2 and restrict access.",
    },
    {
        "category": "secret",
        "keywords": ["token", "secret", "api_key", "apikey", "access_key"],
        "pii_type": "CREDENTIAL",
        "severity": "CRITICAL",
        "remediation": "Encrypt or hash at rest; rotate regularly; strict RBAC.",
    },
    {
        "category": "credit_card",
        "keywords": ["credit_card", "creditcard", "card_number", "card_no", "cardnum", "ccnum"],
        "pii_type": "CREDIT_CARD",
        "severity": "HIGH",
        "remediation": "Encrypt at rest (Acra) + mask to last 4 digits (PCI-DSS); never log raw.",
    },
    {
        "category": "ssn",
        "keywords": ["ssn", "social_security", "national_id", "tax_id"],
        "pii_type": "SSN",
        "severity": "HIGH",
        "remediation": "Encrypt at rest + mask (***-**-1234) + strict RBAC.",
    },
    {
        "category": "email",
        "keywords": ["email", "e_mail"],
        "pii_type": "EMAIL",
        "severity": "MEDIUM",
        "remediation": "Mask via view (n***@domain) and restrict raw-table access to admins.",
    },
    {
        "category": "phone",
        "keywords": ["phone", "mobile", "tel_no", "telephone"],
        "pii_type": "PHONE",
        "severity": "MEDIUM",
        "remediation": "Mask all but last 3-4 digits; restrict raw access.",
    },
    {
        "category": "address",
        "keywords": ["address", "addr", "street", "postal", "zipcode", "zip_code"],
        "pii_type": "ADDRESS",
        "severity": "MEDIUM",
        "remediation": "Mask/generalize (city only) and restrict raw access.",
    },
    {
        "category": "dob",
        "keywords": ["dob", "birth", "birthday", "date_of_birth"],
        "pii_type": "DOB",
        "severity": "MEDIUM",
        "remediation": "Restrict access; consider generalization (year only).",
    },
]


def connect():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"[ERROR] Cannot connect to MySQL: {err}", file=sys.stderr)
        sys.exit(1)


def classify(column_name):
    """Return the most-severe matching category for a column name, or None."""
    name = column_name.lower()
    best = None
    for cat in CATEGORIES:
        for kw in cat["keywords"]:
            if kw in name:
                if best is None or SEVERITY_RANK[cat["severity"]] > SEVERITY_RANK[best["severity"]]:
                    best = {**cat, "matched_keyword": kw}
                break
    return best


def scan_columns(cursor):
    # Join tables so each column carries its object type: a VIEW named with PII keywords
    # (e.g. users_masked) is usually the masking layer, not a raw exposure - the
    # object_type lets the report tell those apart from BASE TABLE PII.
    cursor.execute(
        """
        SELECT c.table_name, c.column_name, c.data_type, c.column_type,
               c.is_nullable, t.table_type
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema AND t.table_name = c.table_name
        WHERE c.table_schema = %s
        ORDER BY c.table_name, c.ordinal_position
        """,
        (TARGET_SCHEMA,),
    )
    findings = []
    total = 0
    for table, column, data_type, column_type, nullable, table_type in cursor.fetchall():
        total += 1
        hit = classify(column)
        if not hit:
            continue
        findings.append({
            "table": table,
            "object_type": table_type,
            "column": column,
            "data_type": data_type,
            "column_type": column_type,
            "nullable": nullable,
            "pii_type": hit["pii_type"],
            "category": hit["category"],
            "matched_keyword": hit["matched_keyword"],
            "severity": hit["severity"],
            "remediation": hit["remediation"],
        })
    return findings, total


def write_outputs(findings):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_JSON.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    with FINDINGS_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "table", "object_type", "column", "data_type", "pii_type", "category",
            "matched_keyword", "severity", "remediation",
        ])
        for r in findings:
            w.writerow([
                r["table"], r["object_type"], r["column"], r["data_type"], r["pii_type"],
                r["category"], r["matched_keyword"], r["severity"], r["remediation"],
            ])


def main():
    conn = connect()
    cursor = conn.cursor()
    try:
        findings, total = scan_columns(cursor)
    finally:
        cursor.close()
        conn.close()

    # Sort most-severe first for a readable report.
    findings.sort(key=lambda r: (-SEVERITY_RANK[r["severity"]], r["table"], r["column"]))
    write_outputs(findings)

    by_sev = Counter(r["severity"] for r in findings)
    by_type = Counter(r["pii_type"] for r in findings)

    print(f"== Phase 6 schema scan: database '{TARGET_SCHEMA}' ==")
    print(f"Columns scanned : {total}")
    print(f"Columns flagged : {len(findings)}")
    print(f"By severity     : " + ", ".join(f"{k}={by_sev[k]}" for k in
          ("CRITICAL", "HIGH", "MEDIUM", "LOW") if by_sev[k]))
    print(f"By PII type     : " + ", ".join(f"{k}={v}" for k, v in sorted(by_type.items())))
    print()
    print(f"{'TABLE':<16}{'TYPE':<12}{'COLUMN':<16}{'PII TYPE':<14}{'SEVERITY':<10}REMEDIATION")
    print("-" * 110)
    for r in findings:
        otype = "VIEW" if r["object_type"] == "VIEW" else "TABLE"
        print(f"{r['table']:<16}{otype:<12}{r['column']:<16}{r['pii_type']:<14}"
              f"{r['severity']:<10}{r['remediation']}")

    print()
    print(f"JSON: {FINDINGS_JSON}")
    print(f"CSV : {FINDINGS_CSV}")


if __name__ == "__main__":
    main()
