"""Phase 7 - Self-service path demo.

Adds a 4th role to the data-classification model: the customer themselves. The
goal is "let customer X read their OWN full PII (including ssn/cc, Acra-decrypted),
but NOTHING else". We do NOT trust the caller's claim of identity (raw `WHERE id = ?`
with a shared account is IDOR-vulnerable). Instead we use a stored-procedure gate:

  CALL get_my_profile(customer_id, self_token)

where self_token = SHA2(customer_id || ':self_service_secret', 256). The procedure
is the ONLY thing the `self_service` MySQL account can EXECUTE - it has NO direct
SELECT on users. So:

  * Correct token for customer 1 -> returns the row, Acra decrypts ssn/cc.
  * Wrong  token  for customer 1 -> SIGNAL 45000 'invalid or missing self-auth token'.
  * Token for customer 1 with id=2 in same call -> fails (token <> expected for 2).
  * Try `SELECT FROM users` directly via self_service -> 1142 (no SELECT grant).

The token simulates what an app would compute server-side (using a secret loaded
from a vault) AFTER authenticating the customer's session + step-up auth. The
secret is hard-coded here for demo only.

Run from project root after `make classify-apply`:
  python3 scripts/phase7_self_service_demo.py
"""

import hashlib
import os
import sys

from dotenv import load_dotenv
import pymysql

load_dotenv()

# Must match the secret hard-coded inside mysql/phase7_5_classification.sql.
SECRET = "self_service_secret"

CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("PROXYSQL_CLIENT_HOST_PORT", "6033")),
    "user": "self_service",
    "password": "selfpass",
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
    "ssl_disabled": True,
    "autocommit": True,
}


def token_for(customer_id):
    return hashlib.sha256(f"{customer_id}:{SECRET}".encode()).hexdigest()


def to_text(b):
    if b is None:
        return None
    if isinstance(b, (bytes, bytearray)):
        return b.decode("utf-8", "replace")
    return str(b)


def main():
    failures = 0

    # ── 1. Customer 1 reads OWN profile with correct token.
    print("== 1. Customer 1 reads OWN profile (correct token) ==")
    conn = pymysql.connect(**CFG); cur = conn.cursor()
    cur.callproc("get_my_profile", (1, token_for(1)))
    row = cur.fetchone()
    if row is None:
        print("   [FAIL] expected a row, got none"); failures += 1
    else:
        uid, fn, ln, email, phone, address, ssn, cc, created = row
        ssn_t, cc_t = to_text(ssn), to_text(cc)
        print(f"   id={uid}  name={fn} {ln}")
        print(f"   email={email!r}  phone={phone!r}")
        print(f"   ssn={ssn_t!r}  credit_card={cc_t!r}")
        import re
        if re.match(r"\d{3}-\d{2}-\d{4}", ssn_t or ""):
            print("   [PASS] customer reads own full PII; Acra decrypted ssn/cc")
        else:
            print(f"   [FAIL] ssn not plaintext: {ssn_t!r}"); failures += 1
    cur.close(); conn.close()

    # ── 2. Customer 1 tries to read customer 2 with token-of-1 -> token mismatch.
    print("\n== 2. Customer 1 tries to access customer 2 (token for id=1) ==")
    conn = pymysql.connect(**CFG); cur = conn.cursor()
    try:
        cur.callproc("get_my_profile", (2, token_for(1)))
        cur.fetchone()
        print("   [FAIL] enumeration succeeded; should have been refused"); failures += 1
    except pymysql.MySQLError as err:
        msg = str(err).splitlines()[0]
        if "self-auth token" in msg or "45000" in msg or "1644" in msg:
            print(f"   [PASS] refused with: {msg}")
        else:
            print(f"   [FAIL] wrong error: {msg}"); failures += 1
    cur.close(); conn.close()

    # ── 3. Caller forgets token (NULL) -> refused.
    print("\n== 3. Caller forgets self_token (NULL) ==")
    conn = pymysql.connect(**CFG); cur = conn.cursor()
    try:
        cur.callproc("get_my_profile", (1, None))
        cur.fetchone()
        print("   [FAIL] proc returned data without token"); failures += 1
    except pymysql.MySQLError as err:
        msg = str(err).splitlines()[0]
        print(f"   [PASS] refused with: {msg}")
    cur.close(); conn.close()

    # ── 4. Bypass attempt: SELECT FROM users directly -> denied by grants.
    print("\n== 4. Bypass attempt: direct SELECT FROM users via self_service ==")
    conn = pymysql.connect(**CFG); cur = conn.cursor()
    try:
        cur.execute("SELECT id, ssn FROM users LIMIT 1")
        cur.fetchone()
        print("   [FAIL] self_service could SELECT users directly"); failures += 1
    except pymysql.MySQLError as err:
        msg = str(err).splitlines()[0]
        if "1142" in msg or "command denied" in msg:
            print(f"   [PASS] denied with: {msg}")
        else:
            print(f"   [FAIL] wrong error: {msg}"); failures += 1
    cur.close(); conn.close()

    print()
    if failures:
        print(f"[RESULT] {failures} check(s) failed.")
        sys.exit(1)
    print("[RESULT] Self-service verified: customer X reads ONLY id=X with the matching "
          "token, and has no other reach into users.")


if __name__ == "__main__":
    main()
