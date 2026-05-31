"""Phase 7.5 - Encrypt existing users.ssn / users.credit_card in place via Acra.

After the schema migration widens ssn/cc to VARBINARY, the rows still hold the OLD
plaintext bytes (the ALTER preserved them, it just changed the column type). This
script walks every user row, reads the plaintext through a direct MySQL connection
(root, port 3307), then UPDATEs ssn/credit_card through the chained data path
(ProxySQL -> Acra -> MySQL) so Acra encrypts the value on the way through. After this
runs, MySQL stores AcraStruct ciphertext for those columns; the DBA reading direct
sees ciphertext, fraud reading through Acra sees the decrypted plaintext.

Uses PyMySQL on the chained path because mysql-connector-python prepends MySQL query
attributes that break Acra's SQL parser (same workaround as Phase 4/7 encryption
tests).

Skips rows that already look encrypted (start with the AcraStruct magic prefix), so
the script is safe to re-run.

Run from the project root after scripts/phase7_5_apply.sh's earlier steps:
  python3 scripts/phase7_5_encrypt_users_pii.py
"""

import os
import sys

from dotenv import load_dotenv
import mysql.connector
import pymysql

load_dotenv()

# AcraStruct (keystore v1) header starts with the ASCII bytes "%%%" (0x25 0x25 0x25)
# followed by a version byte. Use that prefix to detect rows that have already been
# encrypted so a re-run does not double-encrypt. (Observed in Phase 4 + Phase 7.5 hex
# dumps: e.g. ssn_hex_head=252525A1...)
ACRA_MAGIC = b"\x25\x25\x25"

DIRECT_CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_HOST_PORT", "3307")),
    "user": "root",
    "password": os.getenv("MYSQL_ROOT_PASSWORD", "rootpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
}

CHAIN_CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("PROXYSQL_CLIENT_HOST_PORT", "6033")),
    "user": os.getenv("DBF_USER", "dbfuser"),
    "password": os.getenv("DBF_PASSWORD", "dbfpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
    "ssl_disabled": True,
    "autocommit": True,
}


def to_text(b):
    if b is None:
        return None
    if isinstance(b, (bytes, bytearray)):
        return b.decode("utf-8", "replace")
    return str(b)


def main():
    # 1. Read every user's current ssn/credit_card direct from MySQL.
    direct = mysql.connector.connect(**DIRECT_CFG)
    dcur = direct.cursor()
    dcur.execute("SELECT id, ssn, credit_card FROM users ORDER BY id")
    rows = dcur.fetchall()
    dcur.close()
    direct.close()
    total = len(rows)
    print(f"  found {total} user row(s) to encrypt")

    # 2. UPDATE each row through the chain so Acra encrypts ssn + credit_card.
    chain = pymysql.connect(**CHAIN_CFG)
    ccur = chain.cursor()

    skipped = 0
    encrypted = 0
    for i, (uid, ssn_bytes, cc_bytes) in enumerate(rows, 1):
        # Already-encrypted detection: AcraStruct magic in either column -> skip.
        looks_encrypted = (
            isinstance(ssn_bytes, (bytes, bytearray)) and ssn_bytes.startswith(ACRA_MAGIC)
        ) or (
            isinstance(cc_bytes, (bytes, bytearray)) and cc_bytes.startswith(ACRA_MAGIC)
        )
        if looks_encrypted:
            skipped += 1
            continue

        ssn_txt = to_text(ssn_bytes)
        cc_txt = to_text(cc_bytes)
        ccur.execute(
            "UPDATE users SET ssn = %s, credit_card = %s WHERE id = %s",
            (ssn_txt, cc_txt, uid),
        )
        encrypted += 1
        if i % 200 == 0 or i == total:
            print(f"  ... {i}/{total} processed")

    ccur.close()
    chain.close()

    print(f"  encrypted {encrypted}, already-encrypted (skipped) {skipped}")

    # 3. Verify on one row.
    print("\n  verification (row id 1):")
    direct = mysql.connector.connect(**DIRECT_CFG)
    dcur = direct.cursor()
    dcur.execute("SELECT LENGTH(ssn), LENGTH(credit_card), HEX(LEFT(ssn,8)) FROM users WHERE id=1")
    ssn_len, cc_len, ssn_head = dcur.fetchone()
    print(f"    direct read: ssn_len={ssn_len} cc_len={cc_len} ssn_hex_head={ssn_head}")
    dcur.close(); direct.close()

    chain = pymysql.connect(**CHAIN_CFG)
    ccur = chain.cursor()
    ccur.execute("SELECT ssn, credit_card FROM users WHERE id=1")
    s, c = ccur.fetchone()
    print(f"    via chain : ssn={to_text(s)!r}  credit_card={to_text(c)!r}")
    ccur.close(); chain.close()

    print("\n  [OK] users.ssn / users.credit_card now encrypted at rest")


if __name__ == "__main__":
    main()
