# Data Flow — đường đi query theo role

Tài liệu mô tả **đường đi vật lý** của 1 query khi user chạm UI, cho 3 role chính: customer, support, admin. Mỗi role đi qua tầng khác nhau và mỗi tầng làm 1 việc khác lên payload.

## Sơ đồ tổng thể

```mermaid
flowchart LR
    subgraph Client
        UA[Browser]
    end
    subgraph App
        FL[Flask demo<br/>:5000]
    end
    subgraph Chain[Chained data path]
        PR[ProxySQL DBF<br/>:6033]
        AC[Acra<br/>:9393]
    end
    subgraph Direct[DBA bypass]
        D3[MySQL host port<br/>:3307]
    end
    subgraph DB[Database layer]
        MY[MySQL 8.4<br/>users / users_masked / get_my_profile]
    end

    UA -->|HTTP+cookie| FL

    FL -->|pymysql| PR
    PR -->|MySQL wire| AC
    AC -->|MySQL wire| MY

    FL -.->|mysql.connector<br/>admin panel only| D3
    D3 -.-> MY

    style Chain fill:#eef6ff,stroke:#5079b3
    style Direct fill:#fff3e0,stroke:#b37a3a
    style DB fill:#f4f4f4,stroke:#6c757d
```

3 endpoint khác nhau:

| Endpoint | Port | Khi nào dùng |
|---|---|---|
| ProxySQL chained | `127.0.0.1:6033` | Customer + Support — mọi truy cập app-level |
| MySQL direct | `127.0.0.1:3307` | Admin panel "Storage sample" — chứng minh ciphertext at rest |
| ProxySQL HA-router admin | `127.0.0.1:6452` | Admin panel "Database cluster" — chỉ đọc topology |

---

## 1. Customer (Alice, Bob) — `/profile`

Khách hàng đọc hồ sơ của chính mình. App gọi stored procedure với token bound to session.

```mermaid
sequenceDiagram
    autonumber
    participant U as Alice (id=1)
    participant FL as Flask :5000
    participant PR as ProxySQL :6033
    participant AC as Acra :9393
    participant MY as MySQL :3306

    U->>FL: GET /profile?id=1 (cookie: session.id=1)
    Note over FL: token = SHA2("1:self_service_secret")
    FL->>PR: CALL get_my_profile(1, token)<br/>user=self_service
    Note over PR: Query rules check<br/>CALL không trùng deny → pass
    PR->>AC: Forward, re-auth as self_service
    AC->>MY: Forward, re-auth as self_service
    Note over MY: EXECUTE grant on procedure: OK<br/>Proc: verify token vs SHA2(arg_id||secret)<br/>Match → SELECT FROM users WHERE id=1
    MY-->>AC: Row(ssn=ciphertext, cc=ciphertext, …)
    Note over AC: Cột ssn, credit_card trong encryptor_config<br/>→ decrypt AcraStruct với private key
    AC-->>PR: Row(ssn=plaintext, cc=plaintext, …)
    PR-->>FL: Row
    FL-->>U: Render profile (full PII)
```

### Khi Alice thử IDOR `?id=2`

```mermaid
sequenceDiagram
    autonumber
    participant U as Alice (session.id=1)
    participant FL as Flask :5000
    participant PR as ProxySQL :6033
    participant AC as Acra :9393
    participant MY as MySQL :3306

    U->>FL: GET /profile?id=2
    Note over FL: token vẫn = SHA2("1:secret")<br/>vì session.id=1
    FL->>PR: CALL get_my_profile(2, token_for_1)
    PR->>AC: Forward
    AC->>MY: Forward
    Note over MY: expected = SHA2("2:secret")<br/>got = SHA2("1:secret")<br/>MISMATCH
    MY-->>AC: ERROR 1644 'invalid self-auth token'
    AC-->>PR: Error
    PR-->>FL: pymysql.MySQLError
    FL-->>U: 403 Forbidden page
```

**Note**: Token = `SHA2(id || ':self_service_secret', 256)` được app tính bằng `session.id`. Đổi URL không đổi được token → DB từ chối → IDOR bị chặn **tại tầng DB**, kể cả app dev quên check ownership.

---

## 2. Support (Carol) — `/support`

Support staff xem danh sách khách. Truy cập qua chain nhưng MySQL identity là `support`, không phải `self_service`.

```mermaid
sequenceDiagram
    autonumber
    participant C as Carol
    participant FL as Flask :5000
    participant PR as ProxySQL :6033
    participant AC as Acra :9393
    participant MY as MySQL :3306

    C->>FL: GET /support?q=Smith
    FL->>PR: SELECT … FROM users_masked WHERE first_name LIKE '%Smith%'<br/>user=support
    Note over PR: Query rules check<br/>Không trùng deny → pass
    PR->>AC: Forward, re-auth as support
    AC->>MY: Forward, re-auth as support
    Note over MY: support có SELECT trên users_masked<br/>(không có grant trên users raw)<br/>View tự CONCAT/LEFT mask email/phone/address
    MY-->>AC: Rows (email='j***@…', phone='***-***-3890', …)
    Note over AC: Không cột nào trong encryptor_config<br/>→ pass-through bytes
    AC-->>PR: Rows
    PR-->>FL: Rows
    FL-->>C: Render table (masked)
```

### Khi Carol thử SQL injection trong search box

```mermaid
sequenceDiagram
    autonumber
    participant C as Carol
    participant FL as Flask :5000
    participant PR as ProxySQL :6033
    participant AC as Acra :9393
    participant MY as MySQL :3306

    C->>FL: GET /support?q=' OR '1'='1
    FL->>PR: SELECT … WHERE first_name LIKE '%' OR '1'='1%' …<br/>user=support
    Note over PR: Query rules check<br/>Match regex "OR '1'='1'"<br/>→ DENY, return error<br/>(không xuống Acra/MySQL)
    PR-->>FL: ERROR 1148 'DBF blocked'
    FL-->>C: Render "Request rejected"
    Note over AC,MY: Không bao giờ thấy query này
```

### Khi Carol xem detail và thử raw access

```mermaid
sequenceDiagram
    autonumber
    participant C as Carol
    participant FL as Flask :5000
    participant PR as ProxySQL :6033
    participant AC as Acra :9393
    participant MY as MySQL :3306

    Note over FL: Flask auto-attempt raw access<br/>khi render detail page
    FL->>PR: SELECT ssn, credit_card FROM users WHERE id=N<br/>user=support
    PR->>AC: Forward
    AC->>MY: Forward
    Note over MY: support KHÔNG có grant SELECT<br/>trên users (raw)
    MY-->>AC: ERROR 1142 'SELECT command denied'
    AC-->>PR: Error
    PR-->>FL: pymysql.MySQLError
    FL-->>C: Render với "SSN restricted" + collapsible error
```

**Note**: Khác customer ở chỗ Carol không dùng stored procedure — Carol có grant trực tiếp trên `users_masked` view. View đã tự mask cho mỗi cột Tier 2. Tier 1 (ssn/cc) không có trong view → Carol không reach được, dù qua chain hay không.

---

## 3. Admin (Dave) — `/admin`

Admin có 4 panel, mỗi panel đi đường khác nhau.

### 3a. "Storage sample" panel — DBA direct, no proxy, no Acra

```mermaid
sequenceDiagram
    autonumber
    participant D as Dave
    participant FL as Flask :5000
    participant MY as MySQL :3307 (host port)

    D->>FL: GET /admin
    Note over FL: mysql.connector (NOT pymysql)<br/>Direct connect port 3307
    FL->>MY: SELECT id, ssn, credit_card,<br/>LENGTH(ssn), HEX(LEFT(ssn,16))<br/>FROM users WHERE id=1<br/>user=root
    Note over MY: root có toàn quyền<br/>Trả bytes thô như đang lưu
    MY-->>FL: Row(ssn=AcraStruct bytes 161B,<br/>cc=AcraStruct bytes 166B)
    FL-->>D: Render "[161B] 0x252525A1…"
```

**Key**: bypass cả ProxySQL lẫn Acra → DBA thấy chính xác cái MySQL lưu trên disk. Vì không qua Acra → không có key → chỉ thấy ciphertext bytes. **Đây là separation of duties cụ thể**: DBA quản DB nhưng không giữ key.

### 3b. "Database cluster" panel — query ProxySQL HA-router admin

```mermaid
sequenceDiagram
    autonumber
    participant D as Dave
    participant FL as Flask :5000
    participant HA as ProxySQL HA-router<br/>admin :6452

    D->>FL: GET /admin (đoạn render cluster panel)
    FL->>HA: SELECT hostgroup_id, hostname, status<br/>FROM runtime_mysql_servers<br/>user=radmin
    Note over HA: Đây là metadata table của ProxySQL,<br/>không phải query data
    HA-->>FL: 3 rows: mysql-1/2/3 + role + status
    FL-->>D: Render 3 node cards
```

**Note**: Đây là query **vào chính ProxySQL** chứ không phải qua nó. Trả về topology cluster, không động đến data tables.

### 3c. "Stop node" — gọi docker

```mermaid
sequenceDiagram
    autonumber
    participant D as Dave
    participant FL as Flask :5000
    participant DK as Docker daemon
    participant N as dbsec-mysql-N
    participant CL as GR cluster (2 còn lại)
    participant HA as ha-router :6452

    D->>FL: POST /admin/kill/dbsec-mysql-1
    FL->>DK: docker stop dbsec-mysql-1
    DK->>N: SIGTERM
    N->>CL: leaving group message
    CL->>CL: Bầu primary mới (raft-like)
    Note over CL: ~3-8s
    loop poll
        FL->>HA: SELECT writer FROM runtime_mysql_servers
        HA-->>FL: ?
    end
    HA-->>FL: dbsec-mysql-2 (mới)
    FL->>DK: docker start dbsec-mysql-1
    FL->>N: mysql -e 'START GROUP_REPLICATION'
    N->>CL: rejoin as SECONDARY
    FL-->>D: {elected_primary: 'dbsec-mysql-2'}
```

**Note**: Không có query data nào ở đây — chỉ docker control plane + ProxySQL admin probe.

### 3d. "Load testing" — Phase 5 stress qua chain

```mermaid
sequenceDiagram
    autonumber
    participant D as Dave
    participant FL as Flask :5000
    participant PR as ProxySQL :6033
    participant AC as Acra :9393
    participant MY as MySQL :3306
    participant PM as Prometheus :9090
    participant GF as Grafana :3000

    D->>FL: POST /api/stress/slow_query
    FL->>FL: Spawn thread
    FL-->>D: {started: true}
    par background load
        FL->>PR: SELECT SLEEP(8) (user=dbfuser)
        PR->>AC: Forward
        AC->>MY: Forward
        Note over MY: Chạy 8s → vào slow.log
        MY-->>AC: Done
        AC-->>PR: Done
        PR-->>FL: Done
    end
    Note over PM: mysqld_exporter scrape every 15s<br/>Phát hiện slow_queries tăng
    PM->>PM: Evaluate rules<br/>Có alert chuyển pending/firing
    D->>GF: Mở Grafana tab khác
    GF-->>D: Dashboard hiển thị spike
```

**Note**: Stress query đi qua chain bình thường, nhưng đáng quan tâm là cái nó tạo ra — slow query log + connection spike — được Prometheus thấy qua mysqld_exporter (kênh observability riêng, không qua Flask).

### 3e. "Compliance scan" — Phase 6 discovery

```mermaid
sequenceDiagram
    autonumber
    participant D as Dave
    participant FL as Flask :5000
    participant SC as scripts/phase6_scan_data_patterns.py
    participant MY as MySQL :3307 (direct)

    D->>FL: POST /api/discovery/scan
    FL->>SC: subprocess.run(--mask-all)
    SC->>MY: SELECT * FROM each text column
    MY-->>SC: rows
    Note over SC: Regex match cho SSN / phone /<br/>credit card (Luhn) / email
    SC->>SC: Cross-check grants → access_verdict
    SC->>SC: Write logs/discovery/data_findings.json
    SC-->>FL: exit
    FL->>FL: Read JSON file
    FL-->>D: {findings: [...]}
```

**Note**: Scanner connect direct → không qua chain. Đây là tool admin chứ không phải app traffic.

---

## Tổng kết — 3 role, 3 đường

| | **Customer** | **Support** | **Admin** |
|---|---|---|---|
| MySQL user | `self_service` | `support` | `root` (direct) hoặc `radmin` (ha-router) hoặc `dbfuser` (stress) |
| Endpoint | ProxySQL `:6033` | ProxySQL `:6033` | MySQL `:3307` + ha-router `:6452` + ProxySQL `:6033` |
| ProxySQL DBF | ✓ enforce | ✓ enforce | ✓ enforce (cho stress); skip cho storage/cluster panel |
| Acra encrypt/decrypt | ✓ decrypt ssn/cc | passthrough (view không có cột encrypted) | skip cho storage panel → thấy ciphertext |
| RBAC MySQL | EXECUTE on proc only | SELECT on `users_masked` only | full root |
| Defense per query | proc + token check | view masking + grant deny on raw users | none on direct path — chỉ encryption at rest bảo vệ |
| Cố thử IDOR | bị token check chặn | n/a | n/a (root đọc được mọi id) |
| Cố thử SQLi | ít gặp (proc args) | bị DBF chặn ở ProxySQL | có thể bypass DBF qua port 3307 — nhưng vô dụng vì ssn/cc đã encrypt |

### Điểm tinh tế

- **Cùng physical chain** cho customer + support — chỉ MySQL identity khác. ProxySQL pass-through username (không terminate auth) → MySQL áp đúng RBAC.
- **Admin có 3 đường khác nhau** trong cùng 1 page: direct MySQL (storage), ha-router admin (cluster), chain (stress). Không phải mọi action admin đều bypass — bypass chỉ là cho operations.
- **Acra chỉ kích hoạt** khi query đụng cột trong `encryptor_config.yaml` (`users.ssn`, `users.credit_card`). Mọi cột khác → pass-through.
- **DBF chỉ trên ProxySQL** — bypass ProxySQL (port 3307) thì không có firewall. Defense in depth bù lại bằng encryption at rest cho Tier 1.
