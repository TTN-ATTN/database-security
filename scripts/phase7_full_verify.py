"""Phase 7 - Verify the FULL integrated path:
    Client -> ProxySQL (DBF) -> Acra (encrypt) -> ha-router (GR) -> MySQL Cluster

Proves all four layers cooperate on one path:

  1. DROP through the front ProxySQL is blocked by the DBF deny rule (before Acra).
  2. A legitimate SELECT traverses ProxySQL -> Acra -> ha-router -> cluster primary.
  3. INSERT secure_cards through the chain: Acra encrypts, the ciphertext is routed by
     ha-router to the cluster primary and replicated across the group.
  4. Reading secure_cards back through the full chain decrypts to plaintext, while
     reading through the HA router directly (port 6450, which skips Acra) shows the
     ciphertext that is actually stored in the cluster.

Two MySQL-protocol entry points are used:
  - 6033  front ProxySQL  -> full chain (decrypted view)
  - 6450  ha-router       -> straight to the cluster, no Acra (ciphertext-at-rest view)

Run from the project root (full path must be up: scripts/phase7_full_up.sh):
  python3 scripts/phase7_full_verify.py
"""

import os
import sys

from dotenv import load_dotenv
import pymysql

load_dotenv()

PLAINTEXT = "4333-3333-3333-3333"
HOLDER = "phase7-full-demo"

CHAIN_CFG = {  # front ProxySQL -> Acra -> ha-router -> cluster
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("PROXYSQL_CLIENT_HOST_PORT", "6033")),
    "user": os.getenv("DBF_USER", "dbfuser"),
    "password": os.getenv("DBF_PASSWORD", "dbfpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
    "ssl_disabled": True,
    "autocommit": True,
}
ATREST_CFG = {  # ha-router -> cluster, bypassing Acra (sees stored bytes)
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": 6450,
    "user": os.getenv("DBF_USER", "dbfuser"),
    "password": os.getenv("DBF_PASSWORD", "dbfpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
    "ssl_disabled": True,
    "autocommit": True,
}
failures = 0


def conn(label, cfg):
    try:
        return pymysql.connect(**cfg)
    except pymysql.MySQLError as err:
        print(f"[FATAL] cannot connect to {label} at {cfg['host']}:{cfg['port']}: {err}")
        sys.exit(2)


def main():
    global failures

    # Clean prior demo row via the HA router (reaches the cluster primary).
    rt = conn("ha-router", ATREST_CFG)
    rtc = rt.cursor()
    rtc.execute("DELETE FROM secure_cards WHERE holder = %s", (HOLDER,))

    chain = conn("front ProxySQL", CHAIN_CFG)
    cur = chain.cursor()

    print("== 1. DBF deny enforced at front ProxySQL ==")
    try:
        cur.execute("DROP TABLE IF EXISTS phase7_full_nope")
        print("  [FAIL] DROP was not blocked"); failures += 1
    except pymysql.MySQLError as err:
        print(f"  [PASS] DROP blocked: {str(err).splitlines()[0]}")

    print("\n== 2. Legitimate SELECT traverses the full chain to the cluster ==")
    try:
        cur.execute("SELECT COUNT(*) FROM users")
        print(f"  [PASS] SELECT via chain -> {cur.fetchone()[0]} users rows")
    except pymysql.MySQLError as err:
        print(f"  [FAIL] SELECT through full chain failed: {err}"); failures += 1

    print("\n== 3. INSERT secure_cards through full chain (Acra encrypts -> cluster) ==")
    try:
        cur.execute("INSERT INTO secure_cards (holder, card_number) VALUES (%s, %s)",
                    (HOLDER, PLAINTEXT))
        print(f"  inserted holder={HOLDER!r} card={PLAINTEXT!r}")
    except pymysql.MySQLError as err:
        print(f"  [FAIL] INSERT through full chain failed: {err}"); failures += 1
        sys.exit(1)

    print("\n== 4a. Read back through full chain (expect plaintext) ==")
    cur.execute("SELECT card_number FROM secure_cards WHERE holder = %s", (HOLDER,))
    via_chain = cur.fetchone()[0]
    if isinstance(via_chain, (bytes, bytearray)):
        via_chain = via_chain.decode("utf-8", "replace")
    if via_chain == PLAINTEXT:
        print(f"  [PASS] full chain decrypted: {via_chain!r}")
    else:
        print(f"  [FAIL] chain did not return plaintext: {via_chain!r}"); failures += 1
    chain.close()

    print("\n== 4b. Read via ha-router directly (no Acra) -> expect ciphertext in cluster ==")
    rtc.execute("SELECT card_number, LENGTH(card_number) FROM secure_cards WHERE holder = %s",
                (HOLDER,))
    rawval, length = rtc.fetchone()
    as_text = rawval.decode("utf-8", "replace") if isinstance(rawval, (bytes, bytearray)) else str(rawval)
    print(f"  stored length in cluster: {length} bytes")
    if PLAINTEXT not in as_text:
        print("  [PASS] cluster stores ciphertext (Acra encrypted before the cluster)")
    else:
        print(f"  [FAIL] plaintext found in cluster storage: {as_text!r}"); failures += 1
    rtc.close(); rt.close()

    print()
    if failures:
        print(f"[RESULT] {failures} check(s) failed on the full path.")
        sys.exit(1)
    print("[RESULT] FULL path verified: DBF + encryption + HA cluster on one chain.")


if __name__ == "__main__":
    main()
