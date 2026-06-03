"""Phase 7 - HA Read/Write split demo.

The HA cluster already proves "no data loss on primary kill". But a 3-node cluster
that only serves the primary is wasting 2 nodes. This demo proves the R/W split layer
added to ProxySQL HA-router (proxysql-ha.cnf):

  * WRITES (INSERT/UPDATE/DELETE) always hit hostgroup 2 (the current primary).
  * READS  (SELECT, SHOW)         hit hostgroup 3 (the secondaries) and round-robin
    across them.

The demo runs a small workload through ha-router on port 6450, then asks ProxySQL's
own `stats_mysql_query_digest` admin view "for each query type, which hostgroup
served you?" That is the source of truth - it's ProxySQL's audit of its own routing
decisions, not our guess.

Run from project root after `make ha-bootstrap`:
  python3 scripts/phase7_ha_rw_demo.py
"""

import os
import random
import string
import sys
import time

from dotenv import load_dotenv
import pymysql

load_dotenv()

ROUTER_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
ROUTER_PORT = 6450   # ha-router R/W client interface
ADMIN_PORT = 6452    # ha-router admin interface
DB = os.getenv("MYSQL_DATABASE", "testdb")

CLIENT = {"host": ROUTER_HOST, "port": ROUTER_PORT, "user": "dbfuser", "password": "dbfpass",
          "database": DB, "ssl_disabled": True, "autocommit": True}
ADMIN = {"host": ROUTER_HOST, "port": ADMIN_PORT, "user": "radmin", "password": "radmin",
         "database": "main", "ssl_disabled": True, "autocommit": True}


def admin_query(sql):
    conn = pymysql.connect(**ADMIN); cur = conn.cursor()
    cur.execute(sql); rows = cur.fetchall(); cur.close(); conn.close()
    return rows


def main():
    failures = 0

    # 1. Reset ProxySQL's per-query stats so the demo measures THIS run only.
    print("== 1. Reset ProxySQL query stats (per-run snapshot) ==")
    conn = pymysql.connect(**ADMIN); cur = conn.cursor()
    cur.execute("SELECT * FROM stats_mysql_query_digest_reset LIMIT 1")
    cur.fetchall(); cur.close(); conn.close()
    print("   stats cleared")

    # 2. Confirm topology BEFORE workload. ProxySQL admin returns hostgroup_id as a
    # string, so coerce to int once.
    print("\n== 2. Hostgroup topology as seen by ha-router ==")
    rows = admin_query(
        "SELECT hostgroup_id, hostname, status FROM runtime_mysql_servers "
        "ORDER BY hostgroup_id, hostname"
    )
    writers, readers = [], []
    for hg, host, status in rows:
        hg = int(hg)
        bucket = "WRITER" if hg == 2 else ("READER" if hg == 3 else f"hg{hg}")
        print(f"   hg={hg}  host={host}  status={status}  [{bucket}]")
        if hg == 2 and status == "ONLINE": writers.append(host)
        if hg == 3 and status == "ONLINE": readers.append(host)
    if len(writers) != 1:
        print(f"   [FAIL] expected exactly 1 writer, got {len(writers)}: {writers}"); failures += 1
    else:
        print(f"   [PASS] 1 writer ({writers[0]}), {len(readers)} reader(s)")

    # 2b. Ensure at least a few users exist so the orders INSERT FKs resolve. The HA
    # cluster is bootstrapped with schema only (no seed), so we self-seed minimally.
    seed = pymysql.connect(**CLIENT); scur = seed.cursor()
    scur.execute("SELECT COUNT(*) FROM users")
    if scur.fetchone()[0] < 5:
        for i in range(1, 6):
            scur.execute(
                "INSERT IGNORE INTO users (id, first_name, last_name, email, phone, "
                "address, ssn, credit_card) VALUES (%s,'Demo','User',%s,'000','x','000-00-0000','0')",
                (i, f"demo{i}@example.com"),
            )
        print("   seeded 5 demo users for FK satisfaction")
    scur.close(); seed.close()

    # 3. Workload through the R/W front (6450).
    print("\n== 3. Run a mixed workload through ha-router on port 6450 ==")
    conn = pymysql.connect(**CLIENT); cur = conn.cursor()

    n_writes, n_reads, n_shows = 5, 12, 3
    # Writes -> primary. Bound user_id to 1..5 to respect the self-seeded users above.
    for _ in range(n_writes):
        product = "rw-demo-" + "".join(random.choices(string.ascii_lowercase, k=6))
        cur.execute(
            "INSERT INTO orders (user_id, product, amount, status) VALUES (%s, %s, %s, %s)",
            (random.randint(1, 5), product, round(random.random() * 100, 2), "pending"),
        )
    # Reads -> should fan out to secondaries.
    for _ in range(n_reads):
        cur.execute("SELECT id, product FROM orders ORDER BY id DESC LIMIT 5")
        cur.fetchall()
    for _ in range(n_shows):
        cur.execute("SHOW STATUS LIKE 'Threads_connected'")
        cur.fetchall()
    cur.close(); conn.close()
    print(f"   ran {n_writes} INSERTs, {n_reads} SELECTs, {n_shows} SHOWs through 6450")
    # Give ProxySQL a beat to flush stats.
    time.sleep(1)

    # 4. Read ProxySQL's own audit of routing decisions.
    print("\n== 4. Per-query routing audit (stats_mysql_query_digest) ==")
    rows = admin_query("""
        SELECT hostgroup, count_star, digest_text
          FROM stats_mysql_query_digest
         WHERE schemaname = '""" + DB + """'
           AND digest_text NOT LIKE '%stats_mysql_query_digest%'
         ORDER BY hostgroup, count_star DESC
    """)
    writer_hits, reader_hits = 0, 0
    for hg, n, digest in rows:
        hg, n = int(hg), int(n)
        bucket = "WRITER" if hg == 2 else ("READER" if hg == 3 else f"hg{hg}")
        print(f"   hg={hg}[{bucket}]  n={n}  digest={digest[:80]}")
        if hg == 2: writer_hits += n
        elif hg == 3: reader_hits += n

    print()
    print(f"   total: writer={writer_hits}, reader={reader_hits}")
    if writer_hits >= n_writes and reader_hits >= (n_reads + n_shows):
        print("   [PASS] writes routed to primary; reads + SHOWs routed to secondaries")
    else:
        print(f"   [FAIL] routing mismatch (expected >={n_writes} writer hits and "
              f">={n_reads + n_shows} reader hits)")
        failures += 1

    # 5. Per-reader fan-out sanity check via stats_mysql_connection_pool.
    print("\n== 5. Per-backend usage (connection pool stats) ==")
    rows = admin_query("""
        SELECT hostgroup, srv_host, Queries
          FROM stats_mysql_connection_pool
         WHERE status = 'ONLINE'
         ORDER BY hostgroup, srv_host
    """)
    reader_queries = []
    for hg, host, q in rows:
        hg, q = int(hg), int(q)
        bucket = "WRITER" if hg == 2 else ("READER" if hg == 3 else f"hg{hg}")
        print(f"   hg={hg}[{bucket}]  host={host}  queries_run={q}")
        if hg == 3: reader_queries.append(q)
    nonzero = sum(1 for q in reader_queries if q > 0)
    if nonzero >= 1:
        print(f"   [PASS] {nonzero}/{len(reader_queries)} readers received traffic")
    else:
        print("   [FAIL] no reader received any query"); failures += 1

    print()
    if failures:
        print(f"[RESULT] {failures} check(s) failed.")
        sys.exit(1)
    print("[RESULT] R/W split verified: writes -> primary, reads -> secondaries, "
          "ProxySQL audit confirms routing.")


if __name__ == "__main__":
    main()
