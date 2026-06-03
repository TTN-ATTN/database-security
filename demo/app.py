"""Database Security demo - single-page web UI.

Endpoints:
  GET   /                          -> render index.html
  GET   /api/role/<role>           -> run "view Customer #1 profile" as that role
                                      (roles: customer, support, fraud, dba)
  GET   /api/attack/<attack>       -> run an attack scenario; report which layer blocked
                                      (attacks: sqli, idor, dba_dump, kill_primary)
  GET   /api/ha_status             -> JSON {ha_up: bool}
  GET   /api/alerts                -> proxied Prometheus alerts (firing + pending)
  GET   /api/stream/mysql-log      -> Server-Sent Events: tail logs/mysql/general.log
  POST  /api/stress/<kind>         -> trigger Phase 5 stress (slow_query / conn_burst /
                                      mixed_load) - long-running, returns "started"
  POST  /api/discovery/scan        -> run Phase 6 PII pattern scan; return JSON findings

Backed by the same chained stack the rest of the project uses; this app is just a
thin shell that calls into the existing services with different MySQL identities and
formats the result as JSON for the front-end.

Run from the project root:
  python3 demo/app.py
Then open http://127.0.0.1:5000
"""

import hashlib
import json
import os
import re
import subprocess
import threading
import time

try:
    import requests
except ImportError:
    # `requests` is only used by /api/alerts (Prometheus proxy). Make it optional so
    # the demo still boots if someone forgets `pip install -r requirements.txt`.
    requests = None
from dotenv import load_dotenv
from flask import (
    Flask, Response, abort, jsonify, redirect, render_template, request,
    session, stream_with_context, url_for,
)
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
# Demo secret; fine for a school project, NOT for prod.
app.secret_key = os.getenv("DEMO_SECRET_KEY", "dbsec-demo-not-a-real-secret")

# ── Fake login accounts. 2 customers + 1 support + 1 admin.
# Click-to-login: the UI submits username only; password mirrors username for the demo.
# In production this is replaced by a real IdP / OAuth.
USERS = {
    "alice": {"password": "alice", "role": "customer", "customer_id": 1,
              "display_name": "Alice", "subtitle": "Customer (id=1)"},
    "bob":   {"password": "bob",   "role": "customer", "customer_id": 2,
              "display_name": "Bob",   "subtitle": "Customer (id=2)"},
    "carol": {"password": "carol", "role": "support", "customer_id": None,
              "display_name": "Carol", "subtitle": "Support staff"},
    "dave":  {"password": "dave",  "role": "admin",   "customer_id": None,
              "display_name": "Dave",  "subtitle": "DBA / Admin"},
}


def current_user():
    """Returns the dict for the logged-in user, or None."""
    u = session.get("user")
    if not u:
        return None
    return USERS.get(u) | {"username": u} if u in USERS else None


def require_role(*roles):
    """Decorator factory: only allow these roles to hit the route."""
    from functools import wraps

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login_page"))
            if user["role"] not in roles:
                # Logged in but wrong role -> push them to their own home.
                return redirect(url_for("role_home"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.context_processor
def inject_user():
    """Make `user` available in every template."""
    return {"user": current_user()}


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


# ── Live monitoring proxies + streams ────────────────────────────────────────────

PROM_URL = os.getenv("PROMETHEUS_URL", "http://127.0.0.1:9090")
GRAFANA_URL = os.getenv("GRAFANA_URL", "http://127.0.0.1:3000")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://127.0.0.1:9093")
GENERAL_LOG_PATH = os.getenv("MYSQL_GENERAL_LOG", "logs/mysql/general.log")


@app.get("/api/monitoring_urls")
def monitoring_urls():
    """Frontend uses these to build the 'open in new tab' links."""
    return jsonify({
        "prometheus": PROM_URL,
        "grafana": GRAFANA_URL,
        "alertmanager": ALERTMANAGER_URL,
    })


@app.get("/api/alerts")
def alerts():
    """Proxy Prometheus alerts so the browser doesn't hit CORS."""
    if requests is None:
        return jsonify({"error": "requests not installed — run `pip install requests`",
                        "firing_count": 0, "pending_count": 0,
                        "firing": [], "pending": []}), 503
    try:
        r = requests.get(f"{PROM_URL}/api/v1/alerts", timeout=2)
        data = r.json().get("data", {}).get("alerts", [])
        firing = [a for a in data if a.get("state") == "firing"]
        pending = [a for a in data if a.get("state") == "pending"]
        return jsonify({
            "firing_count": len(firing),
            "pending_count": len(pending),
            "firing": [
                {"name": a["labels"].get("alertname"),
                 "instance": a["labels"].get("instance", ""),
                 "summary": a.get("annotations", {}).get("summary", "")}
                for a in firing
            ],
            "pending": [
                {"name": a["labels"].get("alertname"),
                 "instance": a["labels"].get("instance", "")}
                for a in pending
            ],
        })
    except Exception as e:
        return jsonify({"error": str(e), "firing_count": 0, "pending_count": 0,
                        "firing": [], "pending": []}), 503


@app.get("/api/stream/mysql-log")
def stream_mysql_log():
    """Server-Sent Events: tail logs/mysql/general.log.

    Sends each new line as an SSE 'data:' frame. Browser EventSource auto-reconnects
    if Flask restarts. Filters out the very chatty session-init noise (SET names,
    SELECT version, etc.) so the stream stays focused on real client queries.
    """
    log_path = os.path.join(os.path.dirname(__file__), "..", GENERAL_LOG_PATH)
    log_path = os.path.abspath(log_path)

    # Patterns we want to drop from the stream (session boilerplate + monitor health).
    skip_re = re.compile(
        r"(SET (NAMES|SESSION|@|wait_timeout|autocommit)|SELECT @@version|SHOW STATUS|"
        r"SELECT 1\b|monitor@|administrator command|/\* mysql-connector\b)",
        re.IGNORECASE,
    )

    @stream_with_context
    def generate():
        # On first connect, send the last ~10 lines so the panel isn't empty.
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-30:]
                for line in lines:
                    line = line.rstrip()
                    if line and not skip_re.search(line):
                        yield f"data: {line}\n\n"
        except FileNotFoundError:
            yield "data: (logs/mysql/general.log not found yet — run a query first)\n\n"
            return
        # Then tail forever.
        last_size = os.path.getsize(log_path)
        idle = 0
        while True:
            time.sleep(0.5)
            try:
                size = os.path.getsize(log_path)
            except FileNotFoundError:
                continue
            if size < last_size:  # file got truncated / rotated
                last_size = 0
            if size > last_size:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(last_size)
                    chunk = f.read()
                last_size = size
                for line in chunk.splitlines():
                    line = line.rstrip()
                    if line and not skip_re.search(line):
                        yield f"data: {line}\n\n"
                idle = 0
            else:
                idle += 1
                if idle % 30 == 0:  # heartbeat every 15s so the connection stays alive
                    yield ": keepalive\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Phase 5 stress triggers ──────────────────────────────────────────────────────

_stress_threads = {}  # kind -> Thread

def _run_stress_thread(kind, fn):
    """Run fn() in a background daemon thread; reuse the same slot per kind."""
    existing = _stress_threads.get(kind)
    if existing and existing.is_alive():
        return False  # already running
    t = threading.Thread(target=fn, name=f"stress-{kind}", daemon=True)
    t.start()
    _stress_threads[kind] = t
    return True


def _stress_slow_query():
    """SELECT SLEEP(8) - lands in slow_query log (long_query_time defaults to 2s)."""
    try:
        conn = pymysql.connect(**DBFUSER, connect_timeout=5, read_timeout=20)
        cur = conn.cursor()
        cur.execute("SELECT SLEEP(8), 'phase5-slow-query-demo' AS tag")
        cur.fetchall(); cur.close(); conn.close()
    except Exception:
        pass


def _stress_conn_burst():
    """Open 50 concurrent connections + hold ~10s -> Threads_connected spike."""
    conns = []
    cfg = {**DBFUSER, "connect_timeout": 5}
    try:
        for _ in range(50):
            try:
                conns.append(pymysql.connect(**cfg))
            except Exception:
                pass
        time.sleep(10)
    finally:
        for c in conns:
            try: c.close()
            except Exception: pass


def _stress_mixed_load():
    """Mixed SELECT/INSERT/UPDATE workload for ~30s via PyMySQL on the chain."""
    import random
    start = time.time()
    try:
        conn = pymysql.connect(**DBFUSER); cur = conn.cursor()
        while time.time() - start < 30:
            op = random.choice(["select", "select", "select", "insert", "update"])
            try:
                if op == "select":
                    cur.execute("SELECT id, product FROM orders ORDER BY id DESC LIMIT 10")
                    cur.fetchall()
                elif op == "insert":
                    cur.execute(
                        "INSERT INTO orders (user_id, product, amount, status) "
                        "VALUES (%s, %s, %s, 'pending')",
                        (random.randint(1, 100),
                         f"phase5-load-{random.randint(1000, 9999)}",
                         round(random.random() * 100, 2)))
                else:
                    cur.execute(
                        "UPDATE orders SET status='shipped' "
                        "WHERE product LIKE 'phase5-load-%' AND status='pending' "
                        "ORDER BY id DESC LIMIT 1")
            except Exception:
                pass
        cur.close(); conn.close()
    except Exception:
        pass


@app.post("/api/stress/<kind>")
def stress(kind):
    plans = {
        "slow_query": (_stress_slow_query, "SELECT SLEEP(8) - sẽ vào slow.log, kích "
                       "alert MysqlSlowQueryRateHigh nếu lặp đủ tần suất",
                       "8s"),
        "conn_burst": (_stress_conn_burst, "Mở 50 connection cùng lúc, giữ 10s - "
                       "kích Threads_connected spike",
                       "~10s"),
        "mixed_load": (_stress_mixed_load, "SELECT/INSERT/UPDATE liên tục 30s qua "
                       "chained path - tạo QPS đủ để dashboard có dữ liệu",
                       "30s"),
    }
    if kind not in plans:
        return jsonify({"error": f"unknown stress kind: {kind}"}), 400
    fn, desc, dur = plans[kind]
    started = _run_stress_thread(kind, fn)
    return jsonify({
        "kind": kind,
        "started": started,
        "duration": dur,
        "description": desc,
        "watch": "Mở Grafana (link trên header) → dashboard 'Database Security - Phase 5 "
                 "Performance' và Alertmanager để xem reaction.",
    })


# ── Phase 6 discovery ────────────────────────────────────────────────────────────

@app.post("/api/discovery/scan")
def discovery_scan():
    """Run Phase 6 data pattern scanner; return parsed JSON findings.

    The scanner writes findings to logs/discovery/data_findings.json. We invoke it
    inline (subprocess) so we always read the freshest result.
    """
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    try:
        r = subprocess.run(
            ["python3", "scripts/phase6_scan_data_patterns.py", "--mask-all"],
            cwd=root, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "discovery scan timed out (>60s)"}), 504
    # Read findings written to disk.
    findings_path = os.path.join(root, "logs", "discovery", "data_findings.json")
    if not os.path.exists(findings_path):
        return jsonify({"error": "no findings file produced",
                        "stderr": r.stderr[-400:]}), 500
    with open(findings_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Shape it for the UI: list of {table, column, pattern, severity, verdict, count}.
    findings = data if isinstance(data, list) else data.get("findings", [])
    rows = []
    for f in findings:
        rows.append({
            "table": f.get("table"),
            "column": f.get("column"),
            "pattern": f.get("pattern_type") or f.get("pattern"),
            "severity": f.get("severity"),
            "verdict": f.get("access_verdict") or f.get("verdict"),
            "exposed_to": f.get("exposed_to"),
            "exposure_path": f.get("exposure_path"),
            "count": f.get("match_count") or f.get("count"),
        })
    return jsonify({"findings": rows, "total": len(rows)})


# ═══════════════════════ login + role-aware pages ═══════════════════════════════

@app.get("/")
def index():
    """Logged in -> jump to role home. Otherwise -> login page."""
    if current_user():
        return redirect(url_for("role_home"))
    return render_template("login.html", users=USERS)


@app.post("/login")
def login():
    username = (request.form.get("username") or "").strip().lower()
    if username in USERS:
        session.clear()
        session["user"] = username
        return redirect(url_for("role_home"))
    return redirect(url_for("login_page", error="unknown user"))


@app.get("/login")
def login_page():
    return render_template("login.html", users=USERS, error=request.args.get("error"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.get("/home")
def role_home():
    """Send user to their role's home page."""
    u = current_user()
    if not u:
        return redirect(url_for("login_page"))
    if u["role"] == "customer":
        return redirect(url_for("customer_profile"))
    if u["role"] == "support":
        return redirect(url_for("support_list"))
    if u["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("login_page"))


# ── Customer portal ──────────────────────────────────────────────────────────────

@app.get("/profile")
@require_role("customer")
def customer_profile():
    """Customer's profile page. URL ?id=<n> simulates an app route that takes the
    target customer's id from the URL. Vulnerable apps would SELECT directly by that
    id (IDOR). Our backend computes the proc token using the SESSION's id, not the
    URL's, so when they differ the stored procedure refuses (1644).
    """
    user = current_user()
    session_id = user["customer_id"]
    # Default: visit own profile. Attacker can put any id in the URL.
    try:
        requested_id = int(request.args.get("id", session_id))
    except ValueError:
        requested_id = session_id

    # Token is bound to SESSION's id; the app passes the URL's id to the proc.
    token = self_token(session_id)
    conn = pymysql.connect(**SELF_SERVICE); cur = conn.cursor()
    row = None
    blocked = None
    try:
        cur.callproc("get_my_profile", (requested_id, token))
        row = cur.fetchone()
    except pymysql.MySQLError as err:
        blocked = str(err).splitlines()[0]
    finally:
        cur.close(); conn.close()

    cols = ["id", "first_name", "last_name", "email", "phone", "address",
            "ssn", "credit_card", "created_at"]
    profile = None
    if row:
        profile = {c: to_text(v) for c, v in zip(cols, row)}
    return render_template(
        "customer.html",
        session_id=session_id, requested_id=requested_id,
        profile=profile, blocked=blocked,
        is_idor_attempt=(requested_id != session_id),
    )


# ── Support portal ───────────────────────────────────────────────────────────────

@app.get("/support")
@require_role("support")
def support_list():
    """List customers with masked PII. Plus an optional search box that — to make the
    DBF demo work — concatenates the user's input into the WHERE clause (vulnerable
    pattern). If the user types injection like `' OR '1'='1`, ProxySQL DBF catches it.
    """
    q = request.args.get("q", "").strip()
    rows = []
    blocked_by_dbf = None
    try:
        conn = pymysql.connect(**SUPPORT); cur = conn.cursor()
        if q:
            # INTENTIONALLY concatenated to give DBF something to detect.
            # In real prod this would be a bind parameter, but then the regex rule
            # wouldn't see the injection string and couldn't block it.
            sql = (
                "SELECT id, first_name, last_name, email, phone "
                "FROM users_masked WHERE first_name LIKE '%" + q + "%' "
                "OR last_name LIKE '%" + q + "%' LIMIT 25"
            )
        else:
            sql = ("SELECT id, first_name, last_name, email, phone "
                   "FROM users_masked ORDER BY id LIMIT 25")
        cur.execute(sql)
        for r in cur.fetchall():
            rows.append({"id": r[0], "first_name": r[1], "last_name": r[2],
                         "email": r[3], "phone": r[4]})
        cur.close(); conn.close()
    except pymysql.MySQLError as err:
        msg = str(err)
        if "1148" in msg or "DBF" in msg:
            blocked_by_dbf = msg.splitlines()[0]
        else:
            blocked_by_dbf = f"(other MySQL error) {msg.splitlines()[0]}"
    return render_template("support_list.html",
                           rows=rows, q=q, blocked_by_dbf=blocked_by_dbf)


@app.get("/support/customer/<int:cid>")
@require_role("support")
def support_customer_detail(cid):
    """Masked detail for one customer. Plus an explicit 'try raw access' button that
    SELECTs users (not users_masked) -> MySQL refuses with 1142 -> Tier 1 protection
    visible."""
    detail = None
    try:
        conn = pymysql.connect(**SUPPORT); cur = conn.cursor()
        cur.execute(
            "SELECT id, first_name, last_name, email, phone, address "
            "FROM users_masked WHERE id=%s", (cid,))
        r = cur.fetchone()
        if r:
            detail = {"id": r[0], "first_name": r[1], "last_name": r[2],
                      "email": r[3], "phone": r[4], "address": r[5]}
        cur.close(); conn.close()
    except pymysql.MySQLError:
        detail = None

    # Try raw access (this will be denied; we show it as evidence in the UI).
    raw_denied = None
    try:
        conn = pymysql.connect(**SUPPORT); cur = conn.cursor()
        cur.execute("SELECT ssn, credit_card FROM users WHERE id=%s", (cid,))
        cur.fetchone(); cur.close(); conn.close()
    except pymysql.MySQLError as err:
        raw_denied = str(err).splitlines()[0]

    return render_template("support_detail.html",
                           cid=cid, detail=detail, raw_denied=raw_denied)


# ── Admin dashboard ──────────────────────────────────────────────────────────────

@app.get("/admin")
@require_role("admin")
def admin_dashboard():
    """Admin's multi-panel control center."""
    # Panel A: raw at-rest sample for customer 1, via DBA direct
    raw = None
    try:
        conn = mysql.connector.connect(**DBA_DIRECT); cur = conn.cursor()
        cur.execute(
            "SELECT id, first_name, last_name, "
            "  LENGTH(ssn), HEX(LEFT(ssn,16)), "
            "  LENGTH(credit_card), HEX(LEFT(credit_card,16)) "
            "FROM users WHERE id=1")
        r = cur.fetchone(); cur.close(); conn.close()
        if r:
            raw = {
                "id": r[0], "first_name": r[1], "last_name": r[2],
                "ssn_len": r[3], "ssn_hex": r[4],
                "cc_len": r[5], "cc_hex": r[6],
            }
    except Exception:
        pass

    # Panel B: HA cluster nodes (if up)
    nodes = []
    if _ha_running():
        try:
            conn = pymysql.connect(
                host=CHAIN_HOST, port=6452, user="radmin", password="radmin",
                database="main", ssl_disabled=True, autocommit=True)
            cur = conn.cursor()
            cur.execute(
                "SELECT hostgroup_id, hostname, status FROM runtime_mysql_servers "
                "ORDER BY hostname")
            for hg, host, status in cur.fetchall():
                hg = int(hg)
                role = "PRIMARY" if hg == 2 else ("SECONDARY" if hg == 3 else f"hg{hg}")
                nodes.append({"name": host, "role": role, "status": status})
            cur.close(); conn.close()
        except Exception:
            pass
    # Also include any HA containers that are offline (not in runtime_mysql_servers
    # in OFFLINE/SHUNNED state).
    container_names = {"dbsec-mysql-1", "dbsec-mysql-2", "dbsec-mysql-3"}
    seen = {n["name"] for n in nodes}
    if _ha_running():
        for missing in container_names - seen:
            nodes.append({"name": missing, "role": "?", "status": "OFFLINE"})

    return render_template("admin.html",
                           raw=raw, nodes=nodes, ha_up=_ha_running())


@app.post("/admin/kill/<node>")
@require_role("admin")
def admin_kill_node(node):
    """Stop a specific GR node + try to rejoin it after failover. Returns JSON."""
    allowed = {"dbsec-mysql-1", "dbsec-mysql-2", "dbsec-mysql-3"}
    if node not in allowed:
        return jsonify({"error": f"node not in allowlist: {allowed}"}), 400
    if not _ha_running():
        return jsonify({"error": "HA cluster not running"}), 503
    # docker stop = SIGTERM = graceful "leaving group" -> election starts immediately
    subprocess.run(["docker", "stop", node], capture_output=True, check=False)
    elected = None
    primary_before = node  # the one we just killed was a primary or secondary
    for _ in range(60):
        time.sleep(0.5)
        cur = _ha_primary()
        if cur and cur != primary_before:
            elected = cur
            break
    # Restart + rejoin so the cluster goes back to 3/3 after demo.
    subprocess.run(["docker", "start", node], capture_output=True, check=False)
    for _ in range(30):
        time.sleep(1)
        ping = subprocess.run(
            ["docker", "exec", node, "mysqladmin", "-uroot", f"-p{ROOTPW}", "ping"],
            capture_output=True, check=False)
        if ping.returncode == 0:
            break
    subprocess.run(
        ["docker", "exec", node, "mysql", "-uroot", f"-p{ROOTPW}",
         "-e", "START GROUP_REPLICATION;"],
        capture_output=True, check=False)
    return jsonify({"killed": node, "elected_primary": elected or "TIMEOUT"})


if __name__ == "__main__":
    # 0.0.0.0 so it's reachable from WSL2 -> Windows host browser.
    app.run(host="0.0.0.0", port=5000, debug=False)
