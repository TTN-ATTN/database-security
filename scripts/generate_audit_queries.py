"""Phase 3: generate a set of audit-worthy queries to populate MySQL general/slow log.

Categories:
  - Normal app queries (appuser, expected traffic)
  - PII access on raw table (root only; demonstrates privileged access)
  - PII access denied (appuser hits raw users table -> error logged)
  - Abnormal/dangerous (root runs DELETE/DROP-style on a scratch table)
  - Slow query (forces filesort/cross join above long_query_time)

Each category is tagged with a SQL comment so the log parser can group them.
"""

import os
import sys
import time

from dotenv import load_dotenv
import mysql.connector

load_dotenv()

COMMON = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_HOST_PORT", "3307")),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
}

ROOT_CFG = {**COMMON, "user": "root", "password": os.getenv("MYSQL_ROOT_PASSWORD", "rootpass")}
APP_CFG = {
    **COMMON,
    "user": os.getenv("MYSQL_APP_USER", "appuser"),
    "password": os.getenv("MYSQL_APP_PASSWORD", "apppass"),
}


def run(cfg, label, queries):
    """Run a list of queries; tolerate errors so denied queries still hit the log."""
    print(f"\n[{label}] connecting as {cfg['user']} ...")
    conn = mysql.connector.connect(**cfg)
    cur = conn.cursor()
    for q in queries:
        tagged = f"/* phase3:{label} */ {q}"
        try:
            cur.execute(tagged)
            try:
                rows = cur.fetchall()
                print(f"  OK    {q[:70]}{'...' if len(q) > 70 else ''}  -> {len(rows)} row(s)")
            except mysql.connector.errors.InterfaceError:
                print(f"  OK    {q[:70]}{'...' if len(q) > 70 else ''}  -> no result set")
        except mysql.connector.Error as err:
            print(f"  DENY  {q[:70]}{'...' if len(q) > 70 else ''}  -> {err.msg}")
        conn.commit()
    cur.close()
    conn.close()


NORMAL_APP = [
    "SELECT id, email, phone FROM users_masked LIMIT 5",
    "SELECT id, product, amount, status FROM orders WHERE status='shipped' LIMIT 5",
    "SELECT id, action, ip_address FROM activity_logs ORDER BY created_at DESC LIMIT 5",
    "SELECT COUNT(*) FROM orders WHERE amount > 1000",
]

PII_ACCESS_ROOT = [
    "SELECT id, email, phone, credit_card, ssn FROM users LIMIT 3",
    "SELECT id, address, credit_card FROM users WHERE id BETWEEN 100 AND 105",
    "SELECT user_id, notes FROM activity_logs WHERE notes LIKE '%card%' LIMIT 3",
]

PII_ACCESS_DENIED_APP = [
    "SELECT id, email, phone, credit_card, ssn FROM users LIMIT 1",
    "SELECT credit_card FROM users WHERE id=1",
]

ABNORMAL_ROOT = [
    "CREATE TABLE IF NOT EXISTS audit_scratch (id INT PRIMARY KEY AUTO_INCREMENT, payload VARCHAR(100))",
    "INSERT INTO audit_scratch (payload) VALUES ('row-a'), ('row-b'), ('row-c')",
    "DELETE FROM audit_scratch WHERE id < 3",
    "TRUNCATE TABLE audit_scratch",
    "DROP TABLE audit_scratch",
]

SLOW_QUERY_ROOT = [
    "SELECT SQL_NO_CACHE u.id, COUNT(o.id) AS n FROM users u "
    "LEFT JOIN orders o ON o.user_id=u.id GROUP BY u.id "
    "ORDER BY RAND() LIMIT 50",
    "SELECT SQL_NO_CACHE BENCHMARK(2000000, MD5(NOW()))",
]


def main():
    print("Phase 3 - generating audit query traffic ...")
    run(ROOT_CFG, "normal-app", NORMAL_APP)
    run(APP_CFG, "normal-app-as-appuser", NORMAL_APP)
    run(ROOT_CFG, "pii-access-root", PII_ACCESS_ROOT)
    run(APP_CFG, "pii-access-denied-appuser", PII_ACCESS_DENIED_APP)
    run(ROOT_CFG, "abnormal-root", ABNORMAL_ROOT)
    run(ROOT_CFG, "slow-query-root", SLOW_QUERY_ROOT)
    time.sleep(1)
    print("\n[DONE] Audit traffic generated. Inspect logs/mysql/general.log and logs/mysql/slow.log.")


if __name__ == "__main__":
    try:
        main()
    except mysql.connector.Error as err:
        print(f"[FATAL] {err}")
        sys.exit(1)
