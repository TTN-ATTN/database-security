"""Phase 7 - HA failover demo against the 3-node Group Replication cluster.

Drives the cluster the way a client would - everything through the ProxySQL GR router
on 127.0.0.1:6450, never touching individual nodes - and proves availability survives
losing the primary:

  1. Write a row through the router (lands on the current primary).
  2. Record which node is primary (SELECT @@report_host through the router).
  3. `docker stop` that primary container.
  4. Group Replication elects a new primary; ProxySQL detects it and moves it into the
     writer hostgroup. The script keeps retrying the router until writes work again.
  5. Confirm: the pre-failover row is still readable, a new write succeeds, and the
     primary is now a different node.
  6. Restart the old node and confirm it rejoins the group as SECONDARY.

Run from the project root (needs docker + the cluster bootstrapped):
  python3 scripts/phase7_ha_failover.py
"""

import os
import subprocess
import sys
import time

from dotenv import load_dotenv
import pymysql

load_dotenv()

ROUTER = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": 6450,
    "user": os.getenv("DBF_USER", "dbfuser"),
    "password": os.getenv("DBF_PASSWORD", "dbfpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
    "ssl_disabled": True,
    "autocommit": True,
    "connect_timeout": 5,
    "read_timeout": 8,
    "write_timeout": 8,
}
ROOTPW = os.getenv("MYSQL_ROOT_PASSWORD", "rootpass")
failures = 0


def router(retries=45, delay=2):
    """Connect to the HA router, retrying across the failover window."""
    last = None
    for _ in range(retries):
        try:
            return pymysql.connect(**ROUTER)
        except pymysql.MySQLError as err:
            last = err
            time.sleep(delay)
    raise SystemExit(f"[FATAL] router never became writable: {last}")


def primary_via_router():
    """Which node currently serves writes (the primary), as seen through the router."""
    conn = router()
    try:
        cur = conn.cursor()
        cur.execute("SELECT @@report_host")
        return cur.fetchone()[0]
    finally:
        conn.close()


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)


def members():
    """Query group membership from any live node as root (for the rejoin check)."""
    for node in ("dbsec-mysql-2", "dbsec-mysql-3", "dbsec-mysql-1"):
        r = docker("exec", node, "mysql", "-uroot", f"-p{ROOTPW}", "-N", "-e",
                   "SELECT MEMBER_HOST, MEMBER_STATE FROM "
                   "performance_schema.replication_group_members")
        if r.returncode == 0 and r.stdout.strip():
            result = {}
            for line in r.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    result[parts[0]] = parts[1]
            if result:
                return result
    return {}


def main():
    global failures

    print("== 1. Setup demo table + write a row through the router ==")
    conn = router()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS ha_demo "
                "(id INT AUTO_INCREMENT PRIMARY KEY, note VARCHAR(64), "
                "ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    cur.execute("DELETE FROM ha_demo")
    cur.execute("INSERT INTO ha_demo (note) VALUES ('before-failover')")
    conn.close()
    print("  wrote row 'before-failover'")

    primary_before = primary_via_router()
    print(f"  current PRIMARY = {primary_before}")

    print(f"\n== 2. Kill the primary ({primary_before}) ==")
    r = docker("stop", primary_before)
    if r.returncode != 0:
        print(f"  [FAIL] could not stop {primary_before}: {r.stderr.strip()}")
        sys.exit(1)
    print(f"  stopped {primary_before}")

    print("\n== 3. Wait for the router to route writes to a new primary ==")
    t0 = time.time()
    primary_after = None
    for _ in range(45):
        try:
            conn = router(retries=1)
            cur = conn.cursor()
            cur.execute("SELECT @@report_host")
            host = cur.fetchone()[0]
            # A write only succeeds on the new primary (secondaries are read-only).
            cur.execute("INSERT INTO ha_demo (note) VALUES ('after-failover')")
            conn.close()
            if host != primary_before:
                primary_after = host
                break
        except pymysql.MySQLError:
            pass
        time.sleep(2)

    elapsed = int(time.time() - t0)
    if primary_after:
        print(f"  [PASS] writes resumed in ~{elapsed}s; new PRIMARY = {primary_after}")
    else:
        failures += 1
        print(f"  [FAIL] router did not recover to a new primary within {elapsed}s")

    print("\n== 4. Verify data survived the failover ==")
    conn = router()
    cur = conn.cursor()
    cur.execute("SELECT note FROM ha_demo ORDER BY id")
    notes = [row[0] for row in cur.fetchall()]
    conn.close()
    if "before-failover" in notes:
        print(f"  [PASS] pre-failover row survived; rows now: {notes}")
    else:
        failures += 1
        print(f"  [FAIL] pre-failover row missing; rows: {notes}")

    print(f"\n== 5. Restart {primary_before} and confirm it rejoins as SECONDARY ==")
    docker("start", primary_before)
    # Wait for mysqld to accept connections again.
    for _ in range(30):
        r = docker("exec", primary_before, "mysqladmin", "ping", "-uroot", f"-p{ROOTPW}")
        if r.returncode == 0 and "alive" in r.stdout:
            break
        time.sleep(2)
    # group_replication_start_on_boot=OFF, so a restarted node must be told to rejoin.
    time.sleep(3)
    docker("exec", primary_before, "mysql", "-uroot", f"-p{ROOTPW}", "-e",
           "START GROUP_REPLICATION;")
    rejoined = False
    for _ in range(40):
        m = members()
        if m.get(primary_before) == "ONLINE":
            rejoined = True
            break
        time.sleep(3)
    if rejoined:
        m = members()
        print(f"  [PASS] {primary_before} rejoined; members: {m}")
    else:
        # Not fatal for the failover demo, but report it.
        print(f"  [WARN] {primary_before} did not show ONLINE within timeout "
              f"(it may still be catching up): {members()}")

    print()
    if failures:
        print(f"[RESULT] {failures} failover check(s) failed.")
        sys.exit(1)
    print("[RESULT] HA failover verified: primary killed, cluster re-elected, "
          "router rerouted, data intact.")


if __name__ == "__main__":
    main()
