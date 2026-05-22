"""Phase 4: verify the ProxySQL Database Firewall allow/deny behavior.

Connects through ProxySQL (client port 6033) as dbfuser, who has broad privileges on
testdb. Because MySQL itself would allow the dangerous queries, any rejection proves
ProxySQL's firewall intercepted the query before it reached MySQL.

Exit code is non-zero if any case does not behave as expected, so phase4_check.sh can
rely on it.
"""

import os
import sys

from dotenv import load_dotenv
import mysql.connector

load_dotenv()

CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("PROXYSQL_CLIENT_HOST_PORT", "6033")),
    "user": os.getenv("DBF_USER", "dbfuser"),
    "password": os.getenv("DBF_PASSWORD", "dbfpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
    "ssl_disabled": True,
}

failures = 0


def connect():
    try:
        return mysql.connector.connect(**CFG)
    except mysql.connector.Error as err:
        print(f"[FATAL] Cannot connect through ProxySQL at "
              f"{CFG['host']}:{CFG['port']} as {CFG['user']}: {err}")
        sys.exit(2)


def expect_allow(cur, label, query):
    global failures
    try:
        cur.execute(query)
        try:
            rows = cur.fetchall()
            print(f"  [PASS] ALLOW  {label}: returned {len(rows)} row(s)")
        except mysql.connector.errors.InterfaceError:
            print(f"  [PASS] ALLOW  {label}: executed (no result set)")
    except mysql.connector.Error as err:
        failures += 1
        print(f"  [FAIL] ALLOW  {label}: unexpectedly blocked -> {err.msg}")


def expect_block(cur, label, query, expect_text="DBF:"):
    global failures
    try:
        cur.execute(query)
        try:
            cur.fetchall()
        except mysql.connector.errors.InterfaceError:
            pass
        failures += 1
        print(f"  [FAIL] BLOCK  {label}: query was NOT blocked (firewall miss!)")
    except mysql.connector.Error as err:
        if expect_text in (err.msg or ""):
            print(f"  [PASS] BLOCK  {label}: {err.msg}")
        else:
            # Still blocked, but not by our DBF rule (e.g. MySQL-side error).
            failures += 1
            print(f"  [FAIL] BLOCK  {label}: blocked but not by DBF -> {err.msg}")


def main():
    conn = connect()
    cur = conn.cursor()

    print("Phase 4 - ProxySQL DBF allow/deny test (via port "
          f"{CFG['port']} as {CFG['user']})\n")

    # Scratch table for destructive-rule tests; CREATE is not a denied pattern.
    expect_allow(cur, "CREATE scratch table",
                 "CREATE TABLE IF NOT EXISTS dbf_scratch (id INT PRIMARY KEY, note VARCHAR(50))")
    conn.commit()

    print("\n-- Legitimate queries (should be allowed) --")
    expect_allow(cur, "SELECT from orders",
                 "SELECT id, product, amount FROM orders LIMIT 3")
    expect_allow(cur, "SELECT from masked view",
                 "SELECT id, email, phone FROM users_masked LIMIT 3")
    expect_allow(cur, "INSERT into scratch",
                 "INSERT INTO dbf_scratch (id, note) VALUES (1, 'ok') "
                 "ON DUPLICATE KEY UPDATE note='ok'")
    conn.commit()

    print("\n-- Dangerous queries (should be blocked by ProxySQL) --")
    expect_block(cur, "DROP TABLE", "DROP TABLE dbf_scratch")
    expect_block(cur, "TRUNCATE TABLE", "TRUNCATE TABLE dbf_scratch")
    expect_block(cur, "SELECT * FROM users", "SELECT * FROM users")
    expect_block(cur, "SQL injection tautology",
                 "SELECT id FROM orders WHERE id = 1 OR '1'='1'")

    cur.close()
    conn.close()

    print()
    if failures:
        print(f"[RESULT] {failures} case(s) failed.")
        sys.exit(1)
    print("[RESULT] All DBF allow/deny cases behaved as expected.")


if __name__ == "__main__":
    main()
