"""Phase 7 - Verify the CHAINED data path: Client -> ProxySQL -> Acra -> MySQL.

Proves end-to-end that BOTH layers do their job in the same path:

  1. DROP on a non-existent table goes through ProxySQL first - ProxySQL's deny rule
     blocks it BEFORE it ever reaches Acra. (DBF works.)
  2. A legitimate SELECT on users flows ProxySQL -> Acra -> MySQL and returns rows.
     Acra passes it through unchanged (users is not in the encryptor config).
  3. INSERT into secure_cards (which IS in the encryptor config) through the chain:
     ProxySQL allows it -> Acra encrypts card_number -> MySQL stores AcraStruct
     ciphertext. SELECT through the chain decrypts back to plaintext.
  4. Reading the same row directly from MySQL (bypassing the chain) shows the raw
     ciphertext - confirming Acra was in the write path.

Uses PyMySQL (not mysql-connector) for the chained connection: connector prepends
MySQL query attributes (a \\x00\\x01 prefix) that Acra's SQL parser cannot strip, so
INSERTs would silently skip encryption. Same workaround as phase4_encryption_test.

Exit code is non-zero if any check fails.
"""

import os
import sys

from dotenv import load_dotenv
import pymysql

load_dotenv()

PLAINTEXT = "4222-2222-2222-2222"
HOLDER = "phase7-chain-demo"

# Connection through the CHAIN: client speaks to ProxySQL (port 6033), ProxySQL
# forwards to acra-server, acra-server forwards to MySQL.
CHAIN_CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("PROXYSQL_CLIENT_HOST_PORT", "6033")),
    "user": os.getenv("DBF_USER", "dbfuser"),
    "password": os.getenv("DBF_PASSWORD", "dbfpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
    "ssl_disabled": True,
    "autocommit": True,
}

# Direct MySQL connection for the "what is actually stored at rest" check.
MYSQL_CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_HOST_PORT", "3307")),
    "user": "root",
    "password": os.getenv("MYSQL_ROOT_PASSWORD", "rootpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
}

failures = 0


def connect(label, cfg):
    try:
        return pymysql.connect(**cfg)
    except pymysql.MySQLError as err:
        print(f"[FATAL] cannot connect to {label} at {cfg['host']}:{cfg['port']}: {err}")
        sys.exit(2)


def main():
    global failures

    # Clean any leftover row from a previous run, directly in MySQL (avoids going
    # through the chain at cleanup time so we don't confuse the encryption test).
    raw = pymysql.connect(**MYSQL_CFG)
    rcur = raw.cursor()
    rcur.execute("DELETE FROM secure_cards WHERE holder = %s", (HOLDER,))
    raw.commit()

    chain = connect("ProxySQL chain", CHAIN_CFG)
    cur = chain.cursor()

    # --- 1. ProxySQL DBF still blocks dangerous queries (before Acra ever sees them).
    print("== 1. DBF deny still enforced at ProxySQL (chain entry) ==")
    try:
        cur.execute("DROP TABLE IF EXISTS phase7_should_not_exist")
        print("  [FAIL] DROP was not blocked by ProxySQL")
        failures += 1
    except pymysql.MySQLError as err:
        msg = str(err)
        if "DBF" in msg or "denied" in msg.lower() or err.args[0] in (1148, 1064, 1142, 1227):
            print(f"  [PASS] DROP blocked by ProxySQL: {msg.splitlines()[0]}")
        else:
            print(f"  [FAIL] unexpected error (not a DBF deny): {msg}")
            failures += 1

    # --- 2. Legitimate read goes ProxySQL -> Acra -> MySQL and returns rows.
    print("\n== 2. Legitimate SELECT flows through the whole chain ==")
    try:
        cur.execute("SELECT COUNT(*) FROM users")
        n = cur.fetchone()[0]
        if n > 0:
            print(f"  [PASS] SELECT COUNT(*) FROM users via chain -> {n} rows")
        else:
            print("  [WARN] users table is empty (run `make seed`); chain still worked")
    except pymysql.MySQLError as err:
        print(f"  [FAIL] legitimate SELECT failed through chain: {err}")
        failures += 1

    # --- 3. INSERT secure_cards through chain: Acra must encrypt card_number.
    print("\n== 3. INSERT secure_cards through chain (Acra must encrypt) ==")
    try:
        cur.execute(
            "INSERT INTO secure_cards (holder, card_number) VALUES (%s, %s)",
            (HOLDER, PLAINTEXT),
        )
        print(f"  inserted holder={HOLDER!r} card={PLAINTEXT!r} via chain")
    except pymysql.MySQLError as err:
        print(f"  [FAIL] INSERT through chain failed: {err}")
        failures += 1
        cur.close(); chain.close(); rcur.close(); raw.close()
        sys.exit(1)

    # --- 4. SELECT secure_cards through chain: Acra must decrypt back to plaintext.
    print("\n== 4. SELECT secure_cards through chain (Acra must decrypt) ==")
    cur.execute("SELECT card_number FROM secure_cards WHERE holder = %s", (HOLDER,))
    via_chain = cur.fetchone()[0]
    if isinstance(via_chain, (bytes, bytearray)):
        via_chain = via_chain.decode("utf-8", "replace")
    if via_chain == PLAINTEXT:
        print(f"  [PASS] chain returned plaintext: {via_chain!r}")
    else:
        print(f"  [FAIL] chain did not return original plaintext: {via_chain!r}")
        failures += 1
    cur.close()
    chain.close()

    # --- 5. Direct MySQL read: must show ciphertext, NOT plaintext.
    print("\n== 5. Direct MySQL read (must see ciphertext at rest) ==")
    rcur.execute(
        "SELECT card_number, HEX(card_number), LENGTH(card_number) "
        "FROM secure_cards WHERE holder = %s",
        (HOLDER,),
    )
    rawval, hexval, length = rcur.fetchone()
    if isinstance(hexval, (bytes, bytearray)):
        hexval = hexval.decode()
    as_text = rawval.decode("utf-8", "replace") if isinstance(rawval, (bytes, bytearray)) else str(rawval)
    print(f"  stored length : {length} bytes")
    print(f"  stored HEX    : {hexval[:64]}{'...' if len(hexval) > 64 else ''}")
    if PLAINTEXT not in as_text:
        print("  [PASS] plaintext NOT in raw MySQL storage -> Acra encrypted in chain")
    else:
        print(f"  [FAIL] plaintext leaked into MySQL: {as_text!r}")
        failures += 1
    rcur.close()
    raw.close()

    print()
    if failures:
        print(f"[RESULT] {failures} check(s) failed in chained mode.")
        sys.exit(1)
    print("[RESULT] Chained path verified: ProxySQL DBF + Acra encryption on one path.")


if __name__ == "__main__":
    main()
