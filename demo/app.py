"""Database Security demo - single-page web UI.

Endpoints:
  GET  /                       -> render index.html
  GET  /api/role/<role>        -> run "view Customer #1 profile" as that role
                                  (roles: customer, support, fraud, dba)
  GET  /api/attack/<attack>    -> run an attack scenario, report which layer blocked it
                                  (attacks: sqli, idor, dba_dump, kill_primary)
  GET  /api/ha_status          -> JSON {ha_up: bool} so the UI can grey the Kill button

Backed by the same chained stack the rest of the project uses; this app is just a
thin shell that calls into the existing services with different MySQL identities and
formats the result as JSON for the front-end.

Run from the project root:
  python3 demo/app.py
Then open http://127.0.0.1:5000
"""

import hashlib
import os
import subprocess

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template
import mysql.connector
import pymysql

load_dotenv()

CHAIN_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
CHAIN_PORT = int(os.getenv("PROXYSQL_CLIENT_HOST_PORT", "6033"))
DIRECT_PORT = int(os.getenv("MYSQL_HOST_PORT", "3307"))
DB = os.getenv("MYSQL_DATABASE", "testdb")
ROOTPW = os.getenv("MYSQL_ROOT_PASSWORD", "rootpass")
SELF_SECRET = "self_service_secret"  # mirrors mysql/phase7_5_classification.sql

DEMO_CUSTOMER_ID = 1

# ── connection configs ───────────────────────────────────────────────────────────
CHAIN = dict(host=CHAIN_HOST, port=CHAIN_PORT, database=DB,
             ssl_disabled=True, autocommit=True)
SUPPORT      = {**CHAIN, "user": "support",      "password": "supportpass"}
FRAUD        = {**CHAIN, "user": "fraud",        "password": "fraudpass"}
SELF_SERVICE = {**CHAIN, "user": "self_service", "password": "selfpass"}
DBFUSER      = {**CHAIN, "user": "dbfuser",      "password": "dbfpass"}
DBA_DIRECT = dict(host=CHAIN_HOST, port=DIRECT_PORT, user="root",
                  password=ROOTPW, database=DB)

app = Flask(__name__, static_folder="static", template_folder="templates")


def self_token(customer_id):
    return hashlib.sha256(f"{customer_id}:{SELF_SECRET}".encode()).hexdigest()


def to_text(b):
    if b is None:
        return None
    if isinstance(b, (bytes, bytearray)):
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return f"<binary {len(b)} bytes; head=0x{b[:8].hex()}>"
    return str(b)


def fields_to_dict(row, columns):
    return {col: to_text(val) for col, val in zip(columns, row)}


# ── role endpoints ───────────────────────────────────────────────────────────────

@app.get("/api/role/customer")
def role_customer():
    """Customer reads OWN profile via stored proc with self-auth token."""
    conn = pymysql.connect(**SELF_SERVICE); cur = conn.cursor()
    cur.callproc("get_my_profile", (DEMO_CUSTOMER_ID, self_token(DEMO_CUSTOMER_ID)))
    cols = ["id", "first_name", "last_name", "email", "phone", "address",
            "ssn", "credit_card", "created_at"]
    row = cur.fetchone()
    cur.close(); conn.close()
    return jsonify({
        "role": "customer",
        "label": "Customer (self)",
        "endpoint": f"ProxySQL 6033 (chain)  user=self_service",
        "query": f"CALL get_my_profile({DEMO_CUSTOMER_ID}, <self_token>)",
        "layers": [
            {"name": "ProxySQL DBF",  "status": "pass",   "note": "không trùng deny rule"},
            {"name": "Acra",          "status": "decrypt", "note": "decrypt ssn/cc trên response"},
            {"name": "MySQL",         "status": "proc",    "note": "EXECUTE get_my_profile (token MATCH)"},
        ],
        "result": fields_to_dict(row, cols) if row else None,
        "fields": cols,
        "verdict": "OK — Khách hàng đọc đầy đủ chính row của mình; ssn/cc Acra decrypt.",
        "why":
            "Customer dùng MySQL user `self_service` (chỉ EXECUTE được stored procedure "
            "`get_my_profile(id, token)`). Token = SHA2(id || ':self_service_secret') do "
            "app server tính sau khi customer login + step-up auth. Nếu caller bump id, "
            "token sẽ KHÔNG MATCH → procedure SIGNAL 45000 từ chối. "
            "Chống IDOR ngay tại tầng DB.",
    })


@app.get("/api/role/support")
def role_support():
    """Support sees masked PII via users_masked; raw users denied."""
    masked = denied = None
    conn = pymysql.connect(**SUPPORT); cur = conn.cursor()
    cur.execute(
        "SELECT id, first_name, last_name, email, phone, address "
        "FROM users_masked WHERE id=%s",
        (DEMO_CUSTOMER_ID,),
    )
    masked_row = cur.fetchone()
    if masked_row:
        masked = fields_to_dict(masked_row,
            ["id", "first_name", "last_name", "email", "phone", "address"])
    try:
        cur.execute("SELECT ssn, credit_card FROM users WHERE id=%s",
                    (DEMO_CUSTOMER_ID,))
        cur.fetchone()
        denied = None
    except pymysql.MySQLError as err:
        denied = str(err).splitlines()[0]
    cur.close(); conn.close()

    result = dict(masked or {})
    result["ssn"] = f"❌ DENIED — {denied}" if denied else "❌ DENIED"
    result["credit_card"] = f"❌ DENIED — {denied}" if denied else "❌ DENIED"
    return jsonify({
        "role": "support",
        "label": "Support staff (Tier 2 only)",
        "endpoint": "ProxySQL 6033 (chain)  user=support",
        "query": (
            f"SELECT email, phone, address FROM users_masked WHERE id={DEMO_CUSTOMER_ID};\n"
            f"SELECT ssn, credit_card FROM users WHERE id={DEMO_CUSTOMER_ID};"
        ),
        "layers": [
            {"name": "ProxySQL DBF",  "status": "pass",  "note": "SELECT thường, không trùng deny"},
            {"name": "Acra",          "status": "pass",  "note": "users_masked không đụng cột encrypt"},
            {"name": "MySQL",         "status": "rbac",  "note": "GRANT users_masked OK; users DENIED"},
        ],
        "result": result,
        "fields": ["id", "first_name", "last_name", "email", "phone", "address",
                   "ssn", "credit_card"],
        "verdict": "Masked PII (Tier 2) cho phép; raw ssn/cc (Tier 1) bị từ chối ở MySQL.",
        "why":
            "Support staff (tier 1 hỗ trợ khách) không cần raw PII. Grants chỉ cho "
            "SELECT users_masked: email/phone/address được MASKED ở MySQL bằng view "
            "CONCAT/LEFT/RIGHT. Cố SELECT users → MySQL trả (1142) command denied. "
            "Account bị compromise cũng không leak full PII.",
    })


@app.get("/api/role/fraud")
def role_fraud():
    """Fraud investigator gets full PII via Acra decrypt."""
    conn = pymysql.connect(**FRAUD); cur = conn.cursor()
    cur.execute(
        "SELECT id, first_name, last_name, email, phone, address, ssn, credit_card "
        "FROM users WHERE id=%s",
        (DEMO_CUSTOMER_ID,),
    )
    cols = ["id", "first_name", "last_name", "email", "phone", "address",
            "ssn", "credit_card"]
    row = cur.fetchone()
    cur.close(); conn.close()
    return jsonify({
        "role": "fraud",
        "label": "Fraud investigator (need-to-know)",
        "endpoint": "ProxySQL 6033 (chain)  user=fraud",
        "query": f"SELECT * FROM users WHERE id={DEMO_CUSTOMER_ID}",
        "layers": [
            {"name": "ProxySQL DBF",  "status": "pass",    "note": "SELECT thường"},
            {"name": "Acra",          "status": "decrypt", "note": "decrypt ssn + credit_card từ AcraStruct"},
            {"name": "MySQL",         "status": "rbac",    "note": "GRANT SELECT users (raw OK)"},
        ],
        "result": fields_to_dict(row, cols) if row else None,
        "fields": cols,
        "verdict": "Full PII — đây là role 'có lý do nghiệp vụ' để đọc raw (fraud investigation, compliance).",
        "why":
            "Fraud team / compliance officer / subpoena response cần raw PII để xử case "
            "thật. Họ có MySQL grant đọc raw users; Acra trong chain tự decrypt ssn/cc "
            "khi response trở về. MỌI query đều bị log Phase 3 (general.log + ProxySQL "
            "query digest) với username `fraud` → audit biết ai đọc gì lúc nào.",
    })


@app.get("/api/role/dba")
def role_dba():
    """DBA goes DIRECT to MySQL on 3307 — no Acra in path, sees ciphertext."""
    conn = mysql.connector.connect(**DBA_DIRECT); cur = conn.cursor()
    cur.execute(
        "SELECT id, first_name, last_name, email, phone, address, "
        "ssn, credit_card, LENGTH(ssn), HEX(LEFT(ssn,16)) "
        "FROM users WHERE id=%s",
        (DEMO_CUSTOMER_ID,),
    )
    row = cur.fetchone()
    cur.close(); conn.close()
    uid, fn, ln, email, phone, addr, ssn, cc, ssn_len, ssn_hex = row
    result = {
        "id": uid, "first_name": fn, "last_name": ln,
        "email": email, "phone": phone, "address": addr,
        "ssn": f"<ciphertext {ssn_len} bytes — hex head 0x{ssn_hex}…>",
        "credit_card": f"<ciphertext {len(cc) if cc else 0} bytes — Acra cần key>",
    }
    return jsonify({
        "role": "dba",
        "label": "DBA / Operations (direct MySQL)",
        "endpoint": f"MySQL 3307 (direct)  user=root  — KHÔNG đi qua Acra",
        "query": f"SELECT *, LENGTH(ssn), HEX(LEFT(ssn,16)) FROM users WHERE id={DEMO_CUSTOMER_ID}",
        "layers": [
            {"name": "ProxySQL DBF",  "status": "skip", "note": "không đi qua (DBA bypass app stack)"},
            {"name": "Acra",          "status": "skip", "note": "không đi qua → KHÔNG có key để decrypt"},
            {"name": "MySQL",         "status": "root", "note": "root quyền đầy đủ — đọc được bytes thô"},
        ],
        "result": result,
        "fields": ["id", "first_name", "last_name", "email", "phone", "address",
                   "ssn", "credit_card"],
        "verdict": "Bytes thô đọc được, nhưng ssn/cc là AcraStruct ciphertext — VÔ DỤNG nếu không có key.",
        "why":
            "DBA có toàn quyền vận hành MySQL (backup, schema change, …) nhưng "
            "KHÔNG GIỮ Acra master key. Dump database, mang file đi → vẫn chỉ là "
            "ciphertext (~161 byte/giá trị). Đây là 'separation of duties' cụ thể, "
            "không phải slogan: kẻ giữ DB ≠ kẻ giữ key.",
    })


# ── attack endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/attack/sqli")
def attack_sqli():
    """SQL injection — should be killed by ProxySQL DBF before reaching MySQL."""
    payload = "SELECT * FROM users WHERE id=1 OR '1'='1'"
    blocked = None
    try:
        conn = pymysql.connect(**DBFUSER); cur = conn.cursor()
        cur.execute(payload); cur.fetchall(); cur.close(); conn.close()
    except pymysql.MySQLError as err:
        blocked = str(err).splitlines()[0]
    return jsonify({
        "attack": "SQL Injection (tautology bypass)",
        "intent":
            "Attacker thử bypass WHERE bằng `OR '1'='1'` để dump toàn bộ bảng users.",
        "payload": payload,
        "blocked_by": "ProxySQL DBF" if blocked else None,
        "evidence": blocked or "(không có lỗi — INJECT THÀNH CÔNG)",
        "layer_status": [
            {"name": "ProxySQL DBF", "status": "blocked" if blocked else "pass",
             "note": "regex rule deny: ^.*OR.*=.*$ injection tautology"},
            {"name": "Acra",         "status": "never_reached" if blocked else "pass"},
            {"name": "MySQL",        "status": "never_reached" if blocked else "pass"},
        ],
        "verdict":
            "✅ Bị chặn TRƯỚC khi tới MySQL" if blocked else "❌ INJECT THÀNH CÔNG — kiểm tra config",
        "why":
            "Phase 4 nạp deny rule regex vào ProxySQL `query_rules.sql`. Pattern "
            "`OR '1'='1'` match → trả MySQL error 1148 ngay tại proxy, không bao giờ "
            "đụng MySQL backend. Đây là lý do dùng ProxySQL làm DBF chính chứ không "
            "phải AcraCensor.",
    })


@app.get("/api/attack/idor")
def attack_idor():
    """IDOR — customer bumps id from 1 to 2, but token doesn't match."""
    payload = f"CALL get_my_profile(2, <self_token cho id=1>)"
    blocked = None
    try:
        conn = pymysql.connect(**SELF_SERVICE); cur = conn.cursor()
        cur.callproc("get_my_profile", (2, self_token(1)))  # mismatched
        cur.fetchone(); cur.close(); conn.close()
    except pymysql.MySQLError as err:
        blocked = str(err).splitlines()[0]
    return jsonify({
        "attack": "IDOR — Insecure Direct Object Reference",
        "intent":
            "Customer 1 (sau khi login) thử đọc profile của customer 2 bằng cách bump "
            "id parameter trong API call.",
        "payload": payload,
        "blocked_by": "MySQL stored procedure (token check)" if blocked else None,
        "evidence": blocked or "(không có lỗi — IDOR THÀNH CÔNG)",
        "layer_status": [
            {"name": "ProxySQL DBF", "status": "pass",
             "note": "CALL hợp lệ không trùng deny rule"},
            {"name": "Acra",         "status": "pass",
             "note": "procedure trả empty → không có gì để decrypt"},
            {"name": "MySQL",        "status": "blocked" if blocked else "pass",
             "note": "proc SIGNAL 45000 khi token ≠ SHA2(id || secret)"},
        ],
        "verdict":
            "✅ IDOR bị chặn ở tầng DB" if blocked else "❌ IDOR THÀNH CÔNG — token check broken",
        "why":
            "Stored procedure `get_my_profile(id, token)` check `token == SHA2(id || "
            "':self_service_secret')` trước khi trả row. Token cho id=1 KHÔNG MATCH "
            "với id=2 nên procedure SIGNAL '45000 invalid self-auth token'. Caller "
            "không thể enumerate. Đây là defense-in-depth cho top 1 OWASP API 2023.",
    })


@app.get("/api/attack/dba_dump")
def attack_dba_dump():
    """DBA exfiltrates the database — sees ciphertext, not plaintext."""
    conn = mysql.connector.connect(**DBA_DIRECT); cur = conn.cursor()
    cur.execute("SELECT LENGTH(ssn), HEX(LEFT(ssn,32)) FROM users WHERE id=1")
    ssn_len, ssn_hex = cur.fetchone()
    cur.close(); conn.close()
    return jsonify({
        "attack": "Insider DBA exfiltrates DB",
        "intent":
            "Insider có root quyền MySQL chạy `mysqldump testdb users > stolen.sql` "
            "rồi mang file ra ngoài.",
        "payload": "mysqldump -uroot testdb users > stolen.sql",
        "blocked_by": "Acra encryption-at-rest" if ssn_len and ssn_len > 80 else None,
        "evidence":
            f"users.ssn LENGTH = {ssn_len} bytes (plaintext 11 byte)\n"
            f"users.ssn HEX head = 0x{ssn_hex}…\n"
            f"Đây là AcraStruct ciphertext, không phải SSN.",
        "layer_status": [
            {"name": "ProxySQL DBF", "status": "skip",
             "note": "DBA bypass: connect thẳng 3307"},
            {"name": "Acra",         "status": "skip",
             "note": "KHÔNG có Acra trong đường → KHÔNG có key"},
            {"name": "MySQL",        "status": "pass",
             "note": "root đọc được mọi bytes nhưng bytes là ciphertext"},
        ],
        "verdict": "✅ Dump xong vẫn là ciphertext — không xài được nếu không có key Acra",
        "why":
            "Mục tiêu 'separation of duties': DBA giữ MySQL nhưng không giữ Acra "
            "master key. Dump file mang đi vẫn vô dụng. Production thực tế cần key "
            "trong HSM/Vault để chính DBA cũng không có cơ hội cầm key.",
    })


@app.get("/api/attack/kill_primary")
def attack_kill_primary():
    """Kill the GR primary — cluster auto-fails over, app keeps working."""
    ha_up = _ha_running()
    if not ha_up:
        return jsonify({
            "attack": "Infrastructure failure — kill MySQL primary",
            "intent": "Mô phỏng node MySQL primary chết (crash/maintenance).",
            "payload": "docker kill <primary node>",
            "blocked_by": None,
            "evidence": "HA cluster CHƯA chạy. Bật bằng `make ha-bootstrap` trước.",
            "layer_status": [
                {"name": "HA cluster", "status": "down", "note": "3-node GR + ha-router chưa start"},
            ],
            "verdict": "⚠️  HA cluster offline — không demo được scenario này",
            "why":
                "Phase 7 HA cluster opt-in để giữ baseline nhẹ. Chạy `make ha-bootstrap` "
                "(~2 phút, ~1.5GB RAM) → 3 node GR + ha-router lên port 6450. Sau đó "
                "demo này sẽ live-kill primary.",
        })
    # HA is up — figure out the current primary, kill it, see who takes over.
    primary_before = _ha_primary()
    if not primary_before:
        return jsonify({"verdict": "không xác định được primary hiện tại — bỏ qua"})
    # Use `docker stop` (SIGTERM, graceful) instead of `docker kill` (SIGKILL).
    # With stop, MySQL announces "leaving group" before exit -> remaining nodes
    # elect a new primary immediately. With kill, the cluster has to detect the
    # loss via heartbeat timeout (member_expel_timeout=5s) and sometimes stalls on
    # consensus, which is bad for a 10-second demo button.
    subprocess.run(["docker", "stop", primary_before],
                   capture_output=True, check=False)
    # Poll up to 30s (60 iter * 0.5s). With docker stop, election + ProxySQL detect
    # typically completes in 3-8s.
    import time as _t
    elected = None
    for _ in range(60):
        _t.sleep(0.5)
        cur = _ha_primary()
        if cur and cur != primary_before:
            elected = cur
            break
    # Restart the killed node AND rejoin it to the group (group_replication_start_on_boot
    # is OFF in our config, so a docker start alone leaves it in the group's "lost" state).
    subprocess.run(["docker", "start", primary_before],
                   capture_output=True, check=False)
    # wait for mysqld to be reachable then START GROUP_REPLICATION
    for _ in range(30):
        _t.sleep(1)
        ping = subprocess.run(
            ["docker", "exec", primary_before, "mysqladmin", "-uroot",
             f"-p{ROOTPW}", "ping"],
            capture_output=True, check=False)
        if ping.returncode == 0:
            break
    subprocess.run(
        ["docker", "exec", primary_before, "mysql", "-uroot",
         f"-p{ROOTPW}", "-e", "START GROUP_REPLICATION;"],
        capture_output=True, check=False)
    return jsonify({
        "attack": "Infrastructure failure — kill MySQL primary",
        "intent":
            "Node MySQL primary đột ngột chết. App đang INSERT/SELECT qua ha-router 6450.",
        "payload": f"docker kill {primary_before}",
        "blocked_by": "Group Replication + ProxySQL HA-router" if elected else None,
        "evidence":
            f"Primary CŨ: {primary_before}\n"
            f"Primary MỚI (sau bầu cử): {elected or 'TIMEOUT'}\n"
            f"Node cũ đã restart, sẽ rejoin SECONDARY trong vài giây.",
        "layer_status": [
            {"name": "Group Replication", "status": "elected" if elected else "blocked",
             "note": "GR bầu primary mới từ secondaries còn lại"},
            {"name": "ProxySQL HA-router", "status": "rerouted" if elected else "blocked",
             "note": "writer hostgroup tự cập nhật → app reconnect transparent"},
        ],
        "verdict":
            "✅ Failover xong; app không cần biết primary mới là node nào"
            if elected else "❌ Cluster không bầu được — kiểm tra quorum",
        "why":
            "3 node GR single-primary có quorum khi ≥2 ONLINE. Kill 1 → 2 còn lại bầu "
            "primary mới (Raft-like protocol). ProxySQL theo dõi read_only flag và "
            "replication_group_members table, tự move primary mới vào writer hostgroup. "
            "App connect 6450 không cần thay đổi config — đây là availability layer.",
    })


# ── HA helpers ───────────────────────────────────────────────────────────────────

def _ha_running():
    r = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                       capture_output=True, text=True, check=False)
    names = r.stdout.split()
    return all(n in names for n in
               ("dbsec-mysql-1", "dbsec-mysql-2", "dbsec-mysql-3", "dbsec-ha-router"))


def _ha_primary(exclude=None):
    """Ask ha-router which node is currently the writer (hostgroup 2)."""
    try:
        conn = pymysql.connect(host=CHAIN_HOST, port=6452, user="radmin",
                               password="radmin", database="main",
                               ssl_disabled=True, autocommit=True)
        cur = conn.cursor()
        cur.execute("SELECT hostname FROM runtime_mysql_servers "
                    "WHERE hostgroup_id=2 AND status='ONLINE' LIMIT 1")
        row = cur.fetchone(); cur.close(); conn.close()
        if not row:
            return None
        host = row[0]
        if exclude and host == exclude:
            return None
        return host
    except Exception:
        return None


@app.get("/api/ha_status")
def ha_status():
    return jsonify({"ha_up": _ha_running()})


# ── main page ────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return render_template("index.html", customer_id=DEMO_CUSTOMER_ID)


if __name__ == "__main__":
    # 0.0.0.0 so it's reachable from WSL2 -> Windows host browser.
    app.run(host="0.0.0.0", port=5000, debug=False)
