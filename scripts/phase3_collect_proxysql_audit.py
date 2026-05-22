"""Phase 3 Active Monitor - ProxySQL data-plane audit source.

Added in Phase 4: when ProxySQL sits in front of MySQL, the MySQL general_log only
sees ProxySQL's single backend connection, losing per-client attribution. ProxySQL's
own stats recover it: stats_mysql_query_digest records the FRONTEND username + the
normalized query, and stats_mysql_query_rules records firewall deny hits. Together they
are the proxy-layer audit trail for Active Monitor.

This script:
  1. Generates a little tagged traffic through ProxySQL (allowed + denied).
  2. Reads the query digest and rule-hit stats from the ProxySQL admin interface.
  3. Writes logs/proxysql/proxysql_audit.json and proxysql_audit_summary.csv.

Uses PyMySQL (not mysql-connector-python): connector/8.x prepends MySQL query
attributes to COM_QUERY, which the ProxySQL admin parser rejects.
"""

import csv
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
import pymysql

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "logs" / "proxysql"
OUT_JSON = OUT_DIR / "proxysql_audit.json"
OUT_CSV = OUT_DIR / "proxysql_audit_summary.csv"

HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
DB = os.getenv("MYSQL_DATABASE", "testdb")

CLIENT_CFG = {
    "host": HOST,
    "port": int(os.getenv("PROXYSQL_CLIENT_HOST_PORT", "6033")),
    "user": os.getenv("DBF_USER", "dbfuser"),
    "password": os.getenv("DBF_PASSWORD", "dbfpass"),
    "database": DB,
    "ssl_disabled": True,
}

ADMIN_CFG = {
    "host": HOST,
    "port": int(os.getenv("PROXYSQL_ADMIN_HOST_PORT", "6032")),
    "user": os.getenv("PROXYSQL_ADMIN_USER", "radmin"),
    "password": os.getenv("PROXYSQL_ADMIN_PASSWORD", "radmin"),
    "ssl_disabled": True,
}

ALLOWED = [
    "SELECT id, product, amount FROM orders LIMIT 3",
    "SELECT id, email, phone FROM users_masked LIMIT 3",
    "SELECT COUNT(*) FROM orders WHERE status = 'shipped'",
]
DENIED = [
    "DROP TABLE dbf_scratch",
    "SELECT * FROM users",
    "SELECT id FROM orders WHERE id = 1 OR '1'='1'",
]


def generate_traffic():
    conn = pymysql.connect(**CLIENT_CFG)
    cur = conn.cursor()
    for q in ALLOWED:
        try:
            cur.execute(q)
            cur.fetchall()
        except pymysql.MySQLError:
            pass
    for q in DENIED:
        try:
            cur.execute(q)
            cur.fetchall()
        except pymysql.MySQLError:
            pass  # blocked by DBF; recorded in rule-hit stats
    cur.close()
    conn.close()


def collect():
    conn = pymysql.connect(**ADMIN_CFG)
    cur = conn.cursor(pymysql.cursors.DictCursor)

    cur.execute(
        "SELECT hostgroup, schemaname, username, digest_text, count_star, "
        "first_seen, last_seen FROM stats_mysql_query_digest "
        "WHERE schemaname = %s ORDER BY count_star DESC",
        (DB,),
    )
    digests = cur.fetchall()

    cur.execute(
        "SELECT rule_id, hits FROM stats_mysql_query_rules ORDER BY rule_id"
    )
    rule_hits = cur.fetchall()

    cur.close()
    conn.close()
    return digests, rule_hits


def main():
    try:
        generate_traffic()
        digests, rule_hits = collect()
    except pymysql.MySQLError as err:
        print(f"[ERROR] ProxySQL audit collection failed: {err}", file=sys.stderr)
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {"query_digest": digests, "rule_hits": rule_hits}
    OUT_JSON.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["username", "schema", "count", "query_digest"])
        for d in digests:
            w.writerow([d["username"], d["schemaname"], d["count_star"], d["digest_text"]])
        w.writerow([])
        w.writerow(["rule_id", "deny_hits"])
        for r in rule_hits:
            w.writerow([r["rule_id"], r["hits"]])

    print(f"Collected {len(digests)} query-digest rows, {len(rule_hits)} rule-hit rows")
    print("\nProxySQL query attribution (frontend user -> normalized query):")
    for d in digests[:10]:
        print(f"  {d['username']:<10} x{d['count_star']:<4} {d['digest_text']}")
    print("\nFirewall deny hits:")
    for r in rule_hits:
        print(f"  rule {r['rule_id']}: {r['hits']} hit(s)")
    print(f"\nJSON: {OUT_JSON}")
    print(f"CSV : {OUT_CSV}")


if __name__ == "__main__":
    main()
