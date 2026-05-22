"""Phase 4: demonstrate Acra transparent encryption.

Proves that data written through acra-server is stored as ciphertext in MySQL but
returned as plaintext when read back through acra-server:

  1. INSERT a card number through acra-server (port 9393).
  2. Read it back through acra-server  -> expect plaintext.
  3. Read the same row directly from MySQL (port 3307) -> expect binary ciphertext
     that does NOT contain the plaintext.

Uses PyMySQL (not mysql-connector-python) for the Acra path: connector/8.x prepends
MySQL query attributes (a \\x00\\x01 prefix) to COM_QUERY, which acra-server's SQL
parser cannot strip, so it never matches the table and skips encryption. PyMySQL sends
a plain COM_QUERY that acra parses correctly.

Exit code is non-zero if the round-trip or the ciphertext check fails.
"""

import os
import sys

from dotenv import load_dotenv
import pymysql

load_dotenv()

PLAINTEXT = "4111-1111-1111-1111"
HOLDER = "phase4-demo"

ACRA_CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("ACRA_SERVER_HOST_PORT", "9393")),
    "user": os.getenv("DBF_USER", "dbfuser"),
    "password": os.getenv("DBF_PASSWORD", "dbfpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
    "ssl_disabled": True,
}

MYSQL_CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_HOST_PORT", "3307")),
    "user": "root",
    "password": os.getenv("MYSQL_ROOT_PASSWORD", "rootpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
}

failures = 0


def main():
    global failures

    # Clean any previous demo rows directly in MySQL.
    raw = pymysql.connect(**MYSQL_CFG)
    raw_cur = raw.cursor()
    raw_cur.execute("DELETE FROM secure_cards WHERE holder = %s", (HOLDER,))
    raw.commit()

    try:
        acra = pymysql.connect(**ACRA_CFG)
    except pymysql.MySQLError as err:
        print(f"[FATAL] cannot connect to acra-server at "
              f"{ACRA_CFG['host']}:{ACRA_CFG['port']}: {err}")
        sys.exit(2)
    acra_cur = acra.cursor()

    print("== 1. INSERT card number through acra-server ==")
    acra_cur.execute(
        "INSERT INTO secure_cards (holder, card_number) VALUES (%s, %s)",
        (HOLDER, PLAINTEXT),
    )
    acra.commit()
    print(f"  inserted holder={HOLDER!r} card={PLAINTEXT!r}")

    print("\n== 2. Read back through acra-server (expect plaintext) ==")
    acra_cur.execute("SELECT card_number FROM secure_cards WHERE holder = %s", (HOLDER,))
    via_acra = acra_cur.fetchone()[0]
    if isinstance(via_acra, (bytes, bytearray)):
        via_acra = via_acra.decode("utf-8", "replace")
    if via_acra == PLAINTEXT:
        print(f"  [PASS] acra returned plaintext: {via_acra!r}")
    else:
        failures += 1
        print(f"  [FAIL] acra did not return the original plaintext: {via_acra!r}")
    acra_cur.close()
    acra.close()

    print("\n== 3. Read directly from MySQL (expect ciphertext) ==")
    raw_cur.execute(
        "SELECT card_number, HEX(card_number), LENGTH(card_number) "
        "FROM secure_cards WHERE holder = %s",
        (HOLDER,),
    )
    rawval, hexval, length = raw_cur.fetchone()
    if isinstance(hexval, (bytes, bytearray)):
        hexval = hexval.decode()
    as_text = rawval.decode("utf-8", "replace") if isinstance(rawval, (bytes, bytearray)) else str(rawval)
    print(f"  stored length : {length} bytes")
    print(f"  stored HEX    : {hexval[:64]}{'...' if len(hexval) > 64 else ''}")
    if PLAINTEXT not in as_text:
        print("  [PASS] plaintext is NOT present in the MySQL-stored value")
    else:
        failures += 1
        print(f"  [FAIL] plaintext leaked into MySQL storage: {as_text!r}")
    raw_cur.close()
    raw.close()

    print()
    if failures:
        print(f"[RESULT] {failures} check(s) failed.")
        sys.exit(1)
    print("[RESULT] Transparent encryption verified: ciphertext at rest, plaintext via Acra.")


if __name__ == "__main__":
    main()
