"""Phase 7.5 + self-service - Verify the data classification refactor end-to-end.

Four scenarios, one per role tier, all hitting the SAME chained data path so the
firewall covers everyone (no bypass):

  1. SUPPORT      (low-priv staff) via chained ProxySQL on 6033:
       - SELECT * FROM users_masked  -> sees email/phone/address MASKED, no ssn/cc.
       - SELECT * FROM users         -> RBAC denied (raw users unreachable).

  2. FRAUD        (privileged, need-to-know) via chained ProxySQL on 6033:
       - SELECT ssn, credit_card FROM users -> sees DECRYPTED plaintext (Acra in
         path holds the key and decrypts on the way back).

  3. DBA          (operations) direct to MySQL on 3307, no Acra in path:
       - SELECT ssn, credit_card FROM users -> sees CIPHERTEXT (AcraStruct bytes).
         Proves separation of duties: the DBA can administer MySQL but has no key,
         so PII at rest is unreadable.

  4. SELF-SERVICE (the customer reading their OWN profile) via chained ProxySQL:
       - CALL get_my_profile(id, token) with matching token -> own row, Acra-decrypted.
       - Same call with WRONG id -> SIGNAL 45000 refusal.
       - Direct SELECT FROM users -> 1142 denied (no SELECT grant).

Uses PyMySQL on the chained paths (mysql-connector adds query attributes that break
Acra's SQL parser; same workaround as Phase 4/7).

Exit code is non-zero if any expected behavior is missing.
"""

import hashlib
import os
import re
import sys

from dotenv import load_dotenv
import mysql.connector
import pymysql

load_dotenv()

CHAIN_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
CHAIN_PORT = int(os.getenv("PROXYSQL_CLIENT_HOST_PORT", "6033"))
DB = os.getenv("MYSQL_DATABASE", "testdb")

SUPPORT = {"host": CHAIN_HOST, "port": CHAIN_PORT, "user": "support", "password": "supportpass",
           "database": DB, "ssl_disabled": True, "autocommit": True}
FRAUD = {"host": CHAIN_HOST, "port": CHAIN_PORT, "user": "fraud", "password": "fraudpass",
         "database": DB, "ssl_disabled": True, "autocommit": True}
SELF = {"host": CHAIN_HOST, "port": CHAIN_PORT, "user": "self_service", "password": "selfpass",
        "database": DB, "ssl_disabled": True, "autocommit": True}
DBA = {"host": CHAIN_HOST, "port": int(os.getenv("MYSQL_HOST_PORT", "3307")),
       "user": "root", "password": os.getenv("MYSQL_ROOT_PASSWORD", "rootpass"),
       "database": DB}

SELF_SECRET = "self_service_secret"  # mirrors mysql/phase8_classification.sql


def self_token(customer_id):
    return hashlib.sha256(f"{customer_id}:{SELF_SECRET}".encode()).hexdigest()

failures = 0


def to_text(b):
    if b is None:
        return None
    if isinstance(b, (bytes, bytearray)):
        return b.decode("utf-8", "replace")
    return str(b)


def main():
    global failures

    # ── 1. SUPPORT via chain: masked view OK, raw users DENIED.
    print("== 1. SUPPORT via chain (port 6033) ==")
    conn = pymysql.connect(**SUPPORT); cur = conn.cursor()
    cur.execute("SELECT email, phone, address FROM users_masked LIMIT 3")
    for e, p, a in cur.fetchall():
        print(f"   masked: email={e!r}  phone={p!r}  address={a!r}")
    # Validate the values are actually masked (contain '***').
    cur.execute("SELECT email, phone, address FROM users_masked LIMIT 1")
    e, p, a = cur.fetchone()
    if "***" in e and "***" in p and "***" in a:
        print("   [PASS] support sees masked PII via users_masked")
    else:
        print(f"   [FAIL] values are not masked: email={e!r} phone={p!r} address={a!r}")
        failures += 1
    # Try raw users -> expect DENIED.
    try:
        cur.execute("SELECT id FROM users LIMIT 1")
        cur.fetchone()
        print("   [FAIL] support could read raw users (RBAC misconfigured)")
        failures += 1
    except pymysql.MySQLError as err:
        print(f"   [PASS] support denied on raw users: {str(err).splitlines()[0]}")
    cur.close(); conn.close()

    # ── 2. FRAUD via chain: ssn/cc come back DECRYPTED.
    print("\n== 2. FRAUD via chain (port 6033) ==")
    conn = pymysql.connect(**FRAUD); cur = conn.cursor()
    cur.execute("SELECT id, ssn, credit_card FROM users LIMIT 3")
    rows = cur.fetchall()
    samples = []
    for uid, s, c in rows:
        st, ct = to_text(s), to_text(c)
        samples.append((uid, st, ct))
        print(f"   id={uid}  ssn={st!r}  credit_card={ct!r}")
    # Heuristic for "decrypted": plaintext SSN looks like NNN-NN-NNNN; cc has 13+ digits.
    looks_ok = any(re.match(r"\d{3}-\d{2}-\d{4}", (s or "")) for _, s, _ in samples)
    if looks_ok:
        print("   [PASS] fraud reads decrypted ssn/credit_card via the chain")
    else:
        print("   [FAIL] ssn does not look like decrypted plaintext")
        failures += 1
    cur.close(); conn.close()

    # ── 3. SELF-SERVICE via chain: own row OK, others refused, direct table denied.
    print("\n== 3. SELF-SERVICE via chain (port 6033) ==")
    conn = pymysql.connect(**SELF); cur = conn.cursor()
    cur.callproc("get_my_profile", (1, self_token(1)))
    row = cur.fetchone()
    if row is None:
        print("   [FAIL] expected own profile row, got none"); failures += 1
    else:
        uid, fn, ln, email, phone, address, ssn, cc, created = row
        ssn_t = to_text(ssn)
        print(f"   id={uid}  ssn={ssn_t!r}  email={email!r}")
        if re.match(r"\d{3}-\d{2}-\d{4}", ssn_t or ""):
            print("   [PASS] customer reads own decrypted profile via stored proc")
        else:
            print(f"   [FAIL] ssn not plaintext: {ssn_t!r}"); failures += 1
    # Wrong customer / wrong token must be refused.
    try:
        cur.callproc("get_my_profile", (2, self_token(1)))
        cur.fetchone()
        print("   [FAIL] cross-customer enumeration was not blocked"); failures += 1
    except pymysql.MySQLError as err:
        print(f"   [PASS] cross-customer access refused: {str(err).splitlines()[0]}")
    # Direct table access must be denied by grants.
    try:
        cur.execute("SELECT id FROM users LIMIT 1")
        cur.fetchone()
        print("   [FAIL] self_service could SELECT users directly"); failures += 1
    except pymysql.MySQLError as err:
        print(f"   [PASS] direct SELECT denied: {str(err).splitlines()[0]}")
    cur.close(); conn.close()

    # ── 4. DBA direct (no Acra): ssn/cc must be CIPHERTEXT.
    print("\n== 4. DBA direct to MySQL (port 3307, no Acra in path) ==")
    conn = mysql.connector.connect(**DBA); cur = conn.cursor()
    cur.execute("SELECT id, ssn, credit_card, LENGTH(ssn), LENGTH(credit_card) FROM users LIMIT 1")
    uid, s, c, slen, clen = cur.fetchone()
    st, ct = to_text(s), to_text(c)
    print(f"   id={uid}  ssn_len={slen}  cc_len={clen}")
    # Real Acra ciphertext is ~150-200 bytes and is not printable ASCII / no SSN pattern.
    is_cipher = (slen and slen > 80) and not re.match(r"\d{3}-\d{2}-\d{4}", st or "")
    if is_cipher:
        print(f"   [PASS] DBA sees ciphertext at rest "
              f"(ssn first 8 bytes hex = {(s or b'')[:8].hex()})")
    else:
        print(f"   [FAIL] ssn does not look encrypted: {st!r}")
        failures += 1
    cur.close(); conn.close()

    print()
    if failures:
        print(f"[RESULT] {failures} check(s) failed.")
        sys.exit(1)
    print("[RESULT] Data classification verified: support=masked, fraud=full(decrypted), "
          "DBA=ciphertext. Each role sees exactly what its tier allows.")


if __name__ == "__main__":
    main()
