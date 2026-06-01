# Database Security Course Project

Đồ án môn học về Database Security, triển khai theo từng phase trong [proposal.md](proposal.md).

Trạng thái hiện tại của source code:

- **Phase 1 - Môi Trường Nền**: hoàn thành.
- **Phase 2 - Database, Seed Data, RBAC/Masking**: hoàn thành.
- **Phase 3 - Active Monitor**: hoàn thành (MySQL general log + slow log, audit trail, evidence parser).
- **Phase 4 - Database Firewall + Acra Encryption**: hoàn thành (ProxySQL DBF làm enforcement chính; Acra transparent encryption ở evaluation path).
- **Phase 5 - Performance Monitoring**: hoàn thành (Grafana dashboard nâng cao, alert rules, load test, connection stress test).
- **Phase 6 - Sensitive Data Discovery**: hoàn thành (schema scan theo tên cột + data pattern scan email/phone/card/SSN, phát hiện PII rò rỉ trong free-text, xuất JSON/CSV kèm remediation).
- **Phase 7 - Chained path + High Availability**: hoàn thành (chained `ProxySQL→Acra→MySQL` opt-in giữ fallback; HA 3-node MySQL Group Replication + ProxySQL GR-router với failover **+ R/W split** writes→primary, reads→secondaries; full integrated path + regression Phase 1-6).
- **Phase 7.5 - Data Classification (4-tier role model)**: hoàn thành (Tier 1 Encrypt-at-Acra cho `ssn`/`credit_card`; Tier 2 Mask-at-MySQL cho `email`/`phone`/`address`; Tier 3 Clear cho `id`/tên/timestamp). 4 MySQL identity với 4 quyền khác nhau: `support` (chỉ thấy masked view, bị deny raw `users`), `fraud` (need-to-know, đọc raw + Acra decrypt), `self_service` (khách đọc **đúng row của mình** qua stored procedure có token check, chống IDOR), DBA direct chỉ thấy ciphertext → separation of duties: DBA giữ DB nhưng không giữ key.

Phase 1 cung cấp baseline chạy bằng Docker Compose:

- MySQL 8.4.
- mysqld_exporter.
- Prometheus.
- Alertmanager.
- Grafana với datasource và dashboard được provision sẵn.
- Alert rules cơ bản cho trạng thái target và connection count.
- Script kiểm tra endpoint sau khi khởi động stack.

Phase 2 hiện có:

- Schema `users`, `orders`, `activity_logs`.
- View `users_masked`.
- RBAC để `appuser` đọc view masked, không đọc trực tiếp bảng `users`.
- Script seed dữ liệu giả lập.
- Script kiểm tra masking/RBAC.

Phase 3 hiện có:

- MySQL `general_log` và `slow_query_log` được bật qua [mysql/my.cnf](mysql/my.cnf), ghi file vào `/var/log/mysql` bên trong container, mount ra `logs/mysql/` trên host.
- Script [scripts/phase3_generate_audit_queries.py](scripts/phase3_generate_audit_queries.py) sinh các query có chủ đích (normal app traffic, root đọc PII, appuser bị deny PII, abnormal `DELETE/TRUNCATE/DROP` trên bảng scratch, slow query) và gắn tag `/* phase3:<category> */` vào từng query để dễ truy lùng trong log.
- Script [scripts/phase3_parse_audit_log.py](scripts/phase3_parse_audit_log.py) parse `general.log` + `slow.log` thành `audit_report.json` và `audit_summary.csv` làm bằng chứng audit (user, timestamp, command, query, query_time).
- Script [scripts/phase3_check.sh](scripts/phase3_check.sh) xác nhận log đang ghi, chạy traffic generator, flush log, parse và in các dòng evidence quan trọng (denied PII access, abnormal operations).

**Cập nhật từ Phase 4 — thêm 2 nguồn Active Monitor:**

- **ProxySQL data-plane audit** ([scripts/phase3_collect_proxysql_audit.py](scripts/phase3_collect_proxysql_audit.py)): khi ProxySQL đứng trước MySQL, `general_log` của MySQL chỉ thấy 1 connection backend duy nhất → **mất per-client attribution**. ProxySQL `stats_mysql_query_digest` ghi lại **frontend user + query normalized + số lần**, và `stats_mysql_query_rules` ghi deny hits. Đây mới là audit trail đúng ở tầng proxy. Xuất ra `logs/proxysql/proxysql_audit.json` + `.csv`.
- **Acra audit log**: bật `--audit_log_enable=true` trên acra-server → mỗi dòng log có `integrity=<hash>` (chuỗi hash chống tamper). `phase3_check.sh` thu các dòng này vào `logs/acra/acra_audit.log` làm audit trail của encryption gateway.

Cả 2 nguồn này được `phase3_check.sh` (step 9-10) chạy tự động **nếu** ProxySQL/acra-server đang lên, và **skip** gọn nếu chưa có. Đây là lý do Phase 3 "lớn dần" theo Phase 4 đúng như proposal mô tả (Active Monitor gom MySQL + ProxySQL + Acra logs).

Phase 4 hiện có:

- **ProxySQL** làm Database Firewall chính trên main demo path `Client -> ProxySQL -> MySQL`, cấu hình qua [config/proxysql/proxysql.cnf](config/proxysql/proxysql.cnf).
- Deny rules trong [config/proxysql/query_rules.sql](config/proxysql/query_rules.sql) chặn `DROP`, `TRUNCATE`, `SELECT * FROM users` và injection tautology `OR '1'='1'`.
- [scripts/phase4_dbf_test.py](scripts/phase4_dbf_test.py) chạy qua ProxySQL (port 6033) bằng `dbfuser` (có quyền rộng) để chứng minh firewall chặn **trước** khi tới MySQL, kèm hit counter ở `stats_mysql_query_rules`.
- **Acra transparent encryption** ở evaluation path `Client -> acra-server -> MySQL` (port 9393, behind compose profile `acra`). [scripts/phase4_encryption_test.py](scripts/phase4_encryption_test.py) chứng minh dữ liệu lưu trong MySQL là ciphertext (AcraStruct) nhưng đọc qua Acra ra plaintext.
- [scripts/phase4_check.sh](scripts/phase4_check.sh) verify toàn bộ: ProxySQL DBF (bắt buộc) + Acra encryption (nếu acra-server đang chạy).

Các phần sensitive discovery, HA database cluster và Kubernetes sẽ được triển khai ở các phase sau.

Phase 5 hiện có:

- **Grafana dashboard nâng cao** ([config/grafana/dashboards/mysql-phase5-performance.json](config/grafana/dashboards/mysql-phase5-performance.json)): 6 stat panels (MySQL status, threads connected/running, QPS, slow queries, aborted connects) + 10 time-series panels chia thành 5 section: Connections & Threads, Query Throughput, Slow Queries, InnoDB, Network & Bytes.
- **7 alert rules Phase 5** ([config/prometheus/rules/phase5-alerts.yml](config/prometheus/rules/phase5-alerts.yml)): slow query rate, threads running, aborted connections spike, InnoDB row lock waits, buffer pool hit ratio, connection usage >70%, QPS drop to zero.
- **Load generator** ([scripts/phase5_generate_load.py](scripts/phase5_generate_load.py)): chạy multi-threaded SELECT/INSERT/UPDATE + slow query trong thời gian cấu hình được (mặc định 60s), tag `/* phase5:<type> */` vào mỗi query.
- **Connection stress test** ([scripts/phase5_stress_connections.py](scripts/phase5_stress_connections.py)): mở nhiều connection đồng thời (mặc định 100) và giữ mở để tạo spike trên dashboard và trigger alert.
- **Verification script** ([scripts/phase5_check.sh](scripts/phase5_check.sh)): kiểm tra alert rules loaded, chạy load test + stress test, verify metrics có dữ liệu, in trạng thái alert.

Phase 6 hiện có:

- **Schema scanner** ([scripts/phase6_scan_schema.py](scripts/phase6_scan_schema.py)): quét `INFORMATION_SCHEMA.COLUMNS` của `testdb`, flag các cột mà **tên** gợi ý PII/credential (email, phone, address, credit_card, ssn, password, token...). Mỗi finding kèm `pii_type`, `severity` và remediation cụ thể (mask/encrypt/restrict/hash). Đây là pass "PII có thể nằm ở đâu".
- **Data pattern scanner** ([scripts/phase6_scan_data_patterns.py](scripts/phase6_scan_data_patterns.py)): sample dữ liệu thật từ mọi cột text và match regex email / phone / credit card (validate Luhn + IIN prefix + length) / SSN. Phát hiện giá trị nhạy cảm thật, kể cả PII rò rỉ trong cột free-text tên vô hại như `activity_logs.notes` — chỗ mà masking theo view/RBAC sẽ **bỏ sót**.
- **Masking/RBAC sufficiency cross-check** (trong cùng data scanner): mỗi finding kèm `access_verdict`. Scanner đọc grants từ `INFORMATION_SCHEMA.{SCHEMA,TABLE}_PRIVILEGES`, kiểm tra account low-priv (`appuser`, đổi qua `--app-users`) có `SELECT` trực tiếp lên **base table** chứa PII không. Đọc qua view mask = an toàn; đọc thẳng base table = raw → `EXPOSED`. Kết quả thực tế: `users.*` = `PROTECTED` (appuser chỉ thấy qua `users_masked`), còn `activity_logs.notes` = `EXPOSED` (appuser có `SELECT activity_logs` mà bảng này không có view mask). Đây là điểm nối Phase 6 ↔ Phase 2: discovery không chỉ tìm PII mà còn chỉ ra masking/RBAC **chưa đủ** ở đâu. Với mỗi finding `EXPOSED`, scanner ghi luôn **giá trị PII thật** (`exposed_values`) làm bằng chứng.
- **Verification script** ([scripts/phase6_check.sh](scripts/phase6_check.sh)): chạy cả 2 pass, xác nhận artifacts, và in các cột raw PII mà low-priv account đọc được (lộ gì / ở đâu / vì sao).

Phase 7 hiện có:

- **Chained data path** (opt-in, giữ fallback): override [compose.chained.yaml](compose.chained.yaml) đổi backend ProxySQL từ `dbsec-mysql` sang `dbsec-acra-server`, tạo path `Client → ProxySQL (DBF) → Acra (encrypt) → MySQL` trên **một đường duy nhất**. Deny rule vẫn chặn tại ProxySQL **trước** khi tới Acra; secure_cards được Acra mã hóa rồi mới vào MySQL. Bật bằng [scripts/phase7_chain_up.sh](scripts/phase7_chain_up.sh), về default bằng [phase7_chain_down.sh](scripts/phase7_chain_down.sh) (proposal §7.6).
- **High Availability cluster**: override [compose.ha.yaml](compose.ha.yaml) thêm 3 node MySQL 8.4 Group Replication (single-primary) + một ProxySQL **GR-aware** làm HA-router. Router tự theo dõi primary qua `read_only` + `performance_schema.replication_group_members`, route write tới primary, **tự reroute khi failover**. Bootstrap thủ công bằng SQL ([phase7_ha_bootstrap.sh](scripts/phase7_ha_bootstrap.sh)); failover demo ([phase7_ha_failover.py](scripts/phase7_ha_failover.py)) kill primary → cluster bầu primary mới → router reroute → data còn nguyên → node cũ rejoin.
- **R/W split (read scale-out)** ([config/proxysql/proxysql-ha.cnf](config/proxysql/proxysql-ha.cnf) + [phase7_ha_rw_demo.py](scripts/phase7_ha_rw_demo.py)): ProxySQL HA-router có thêm query rules — `^SELECT` và `^SHOW` route sang **reader hostgroup (3 = secondaries)**, mọi thứ khác fall-back sang **writer hostgroup (2 = primary)**. `SELECT … FOR UPDATE/FOR SHARE` lock buộc về writer (giữ lock + tránh stale read). Demo dùng `stats_mysql_query_digest` của ProxySQL **làm bằng chứng tự audit** việc route — không chỉ đoán: hiển thị từng digest_text + hostgroup phục vụ. Sống sót qua failover (writer hostgroup tự cập nhật primary mới).
- **Full integrated path**: [compose.full.yaml](compose.full.yaml) + [phase7_full_up.sh](scripts/phase7_full_up.sh) ghép tất cả: `Client → ProxySQL (DBF) → Acra (encrypt) → ha-router (GR) → MySQL Cluster`. [phase7_full_verify.py](scripts/phase7_full_verify.py) chứng minh 4 lớp cùng hoạt động.
- **Regression** ([phase7_regression.sh](scripts/phase7_regression.sh)): revert về default mode rồi chạy lại check Phase 1-6, đảm bảo các phase trước không vỡ.

Phase 7.5 hiện có:

- **Migration SQL** ([mysql/phase7_5_classification.sql](mysql/phase7_5_classification.sql)): widen `users.ssn` / `users.credit_card` lên `VARBINARY(512)` để chứa AcraStruct (~161-169 byte); rebuild view `users_masked` **không có** ssn/cc (vì sau khi encrypt-at-rest thì MySQL chỉ thấy ciphertext, mask trên byte sẽ ra rác); tạo 3 user mới `support`/`fraud`/`self_service` với grants theo tier; định nghĩa stored procedure `get_my_profile(customer_id, self_token)` cho self-service. Idempotent (DROP+CREATE user/proc, ALTER là no-op khi cột đã đúng type).
- **Acra encryptor config** ([config/acra/encryptor_config.yaml](config/acra/encryptor_config.yaml)): thêm `users` table với `ssn` + `credit_card` được mã hóa dưới `client_id=dbsec_client`. Khi đi qua chained path, Acra tự encrypt trên `INSERT/UPDATE`, tự decrypt trên `SELECT`. App không biết gì.
- **ProxySQL passthrough** ([config/proxysql/proxysql.cnf](config/proxysql/proxysql.cnf) + [proxysql.chained.cnf](config/proxysql/proxysql.chained.cnf)): thêm `support`/`fraud`/`self_service` vào `mysql_users` để ProxySQL pass-through authentication — username giữ nguyên xuống tới MySQL → MySQL apply RBAC + view masking đúng cho từng user.
- **Apply script** ([scripts/phase7_5_apply.sh](scripts/phase7_5_apply.sh)): orchestrate (1) chạy migration SQL → (2) force-recreate acra-server + proxysql để pick up config mới → (3) reload Phase 4 DBF deny rules → (4) chạy encrypt-in-place trên 1000 row existing data.
- **Encrypt-in-place** ([scripts/phase7_5_encrypt_users_pii.py](scripts/phase7_5_encrypt_users_pii.py)): đọc plaintext ssn/cc qua MySQL direct (root, port 3307) rồi `UPDATE` lại qua chained path (port 6033, PyMySQL, `dbfuser`) để Acra mã hóa trên đường vào. Skip row nào đã encrypted (detect prefix `25 25 25` của AcraStruct), nên re-run an toàn (idempotent: lần 2 báo "encrypted 0, skipped 1000").
- **Verify** ([scripts/phase7_5_verify.py](scripts/phase7_5_verify.py)): chạy 4 scenario trên **cùng 1 chain** (trừ DBA — cảnh đối chứng):
  - `support` qua port 6033 → `SELECT FROM users_masked` thấy `j***@…` / `***-***-3890` / `265**********...`, `SELECT FROM users` bị deny `(1142)`.
  - `fraud` qua port 6033 → `SELECT ssn, credit_card FROM users` ra plaintext `792-38-1308` / `3581618495931032` (Acra decrypt cho user có quyền đọc raw).
  - `self_service` qua port 6033 → chỉ chạy được `CALL get_my_profile(id, token)` với token đúng → đọc **đúng row của mình**, ssn/cc Acra-decrypted; token sai/null → `1644 invalid or missing self-auth token`; thử `SELECT FROM users` thẳng → `1142 denied`.
  - DBA direct port 3307 (no Acra) → `ssn_len=161` bytes, hex head `252525a1…` → ciphertext only. **DBA giữ DB, không giữ key.**
- **Self-service demo standalone** ([scripts/phase7_self_service_demo.py](scripts/phase7_self_service_demo.py)): minh họa cụ thể 4 trường hợp self-service (correct token, cross-customer enumeration, missing token, direct table bypass attempt) — chứng minh thiết kế chống **IDOR** (Insecure Direct Object Reference).

> **Threat model bao trùm:** mọi tier đều đi qua **một đường duy nhất** (ProxySQL DBF → Acra → MySQL), không có lỗ hổng "support team bypass firewall" hay "fraud connect thẳng Acra". Firewall vẫn enforce trước Acra cho mọi user. Per-user behavior khác nhau là do MySQL nhận đúng username và áp đúng grant + view/procedure — ProxySQL không terminate auth, chỉ re-auth user xuống MySQL.

> **Self-service threat model:** không trust caller's claim of identity. App giả sử đã authenticate customer (login + step-up auth) rồi tính `self_token = SHA2(customer_id || ':self_service_secret', 256)` server-side với secret lấy từ vault → pass token vào procedure. Procedure check token MATCH với customer_id mới trả row → **IDOR bị chặn ngay tại tầng DB** (caller không thể bump id từ 1 lên 2 vì token cho 1 ≠ token cho 2). Trong project demo, secret hard-coded; production = load từ Vault/KMS.

> **Lưu ý MySQL Router → ProxySQL-GR:** proposal định dùng MySQL Router cho HA endpoint, nhưng auto-failover của Router cần InnoDB Cluster metadata do **MySQL Shell** tạo, mà image MySQL Shell không pull được công khai (Oracle gate auth). Theo nguyên tắc fallback §4.3, dùng **ProxySQL cấu hình Group Replication** thay thế — cùng vai trò (HA endpoint ổn định, tự reroute), dùng image đã có. Group Replication vẫn là MySQL GR 3-node thật.

### Lưu ý kiến trúc Phase 4

Theo proposal mới nhất, **ProxySQL là DBF enforcement chính** còn Acra/AcraCensor là evaluation path. Lý do: AcraCensor SQL parser không parse được query qua MySQL 8.4 binary protocol (xem [problem.md](problem.md)), nên không dùng làm firewall tin cậy được. ProxySQL hiểu MySQL protocol native và match query bằng regex rules nên chặn ổn định. Acra vẫn được giữ để khai thác **transparent encryption** (điểm mạnh thật sự của Acra) và bám topic gốc.

## Môi Trường

Có thể chạy Phase 1 trên một trong các môi trường sau:

- WSL2 Ubuntu trên Windows.
- Ubuntu VM.
- Linux host.
- DigitalOcean VPS nếu muốn demo cloud optional.

Yêu cầu tối thiểu:

- Docker Engine hoặc Docker Desktop có WSL integration.
- Docker Compose v2 (`docker compose`).
- `curl`.
- Python 3.10+ nếu chuẩn bị chạy script Python ở các phase sau.

## Khởi Động Phase 1

Tạo file môi trường:

```bash
cp .env.example .env
```

Nếu máy đang chạy MySQL local trên port `3306`, giữ mặc định `MYSQL_HOST_PORT=3307` trong `.env`. Nếu muốn dùng port khác, chỉ cần đổi giá trị trong `.env` trước khi khởi động stack.

Khởi động stack:

```bash
docker compose up -d
```

Kiểm tra trạng thái container:

```bash
docker compose ps
```

Chạy kiểm tra baseline:

```bash
bash scripts/phase1_check.sh
```

Nếu mọi thứ ổn, script sẽ kiểm tra được:

- MySQL connectivity.
- mysqld_exporter metrics endpoint.
- Prometheus readiness và alert rules.
- Alertmanager readiness.
- Grafana health endpoint.

## Chạy Phase 2

Phase 2 cần Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Áp dụng schema, tạo masked view, cấu hình RBAC, seed dữ liệu và kiểm tra masking:

```bash
make phase2
```

Nếu chỉ muốn áp dụng lại SQL Phase 2 cho một database volume đã tồn tại:

```bash
make schema
```

Nếu muốn khởi tạo lại từ đầu bằng các file trong `docker-entrypoint-initdb.d`, chạy:

```bash
docker compose down -v
docker compose up -d
```

Lệnh `down -v` sẽ xóa dữ liệu MySQL, Prometheus và Grafana đã lưu trong named volumes.

## Chạy Phase 3 - Active Monitor

Phase 3 dựa trên MySQL `general_log` và `slow_query_log` để xây dựng audit trail. Cấu hình logging được khai báo trong [mysql/my.cnf](mysql/my.cnf); file log được ghi ra `logs/mysql/` trên host (đã `.gitignore` log content nhưng giữ thư mục).

Trước khi chạy lần đầu, đảm bảo thư mục log có quyền ghi cho container MySQL:

```bash
mkdir -p logs/mysql
chmod 777 logs/mysql
```

Nếu Phase 1 đang chạy trước khi bật Phase 3, recreate MySQL để áp config mới:

```bash
docker compose up -d --force-recreate mysql
```

Chạy toàn bộ verification Phase 3:

```bash
make check-phase3
```

Script sẽ:

1. Kiểm tra `general_log`, `slow_query_log`, `long_query_time`, `log_output` đang đúng giá trị.
2. Liệt kê file log bên trong container.
3. Chạy [scripts/phase3_generate_audit_queries.py](scripts/phase3_generate_audit_queries.py) để sinh traffic.
4. `FLUSH LOGS` để file phản ánh buffer hiện tại.
5. Xác nhận `logs/mysql/general.log` và `logs/mysql/slow.log` không rỗng.
6. Parse log bằng [scripts/phase3_parse_audit_log.py](scripts/phase3_parse_audit_log.py) → `audit_report.json` + `audit_summary.csv`.
7. In các dòng evidence quan trọng: appuser bị deny truy cập bảng `users` raw, root thực hiện `DELETE/TRUNCATE/DROP`.

Các target Make rời:

| Lệnh | Mô tả |
|---|---|
| `make audit-traffic` | Chỉ sinh traffic, không parse |
| `make parse-audit` | Chỉ parse log đã có sẵn |
| `make proxysql-audit` | (Phase 4 source) thu ProxySQL query-digest + rule-hit audit |
| `make tail-general` | `tail -f` general log |
| `make tail-slow` | `tail -f` slow log |

Bằng chứng Phase 3 sau khi chạy:

- `logs/mysql/general.log` - mọi query, kèm `user@host` và timestamp.
- `logs/mysql/slow.log` - query vượt `long_query_time = 0.5s`.
- `logs/mysql/audit_report.json` - structured per-event records.
- `logs/mysql/audit_summary.csv` - đếm theo phase3 tag và theo command.
- `logs/proxysql/proxysql_audit.json` + `.csv` - (Phase 4) attribution theo frontend user + deny hits ở tầng ProxySQL.
- `logs/acra/acra_audit.log` - (Phase 4) audit trail integrity-chained của acra-server.

## Chạy Phase 4 - Database Firewall + Acra Encryption

### Phần bắt buộc: ProxySQL DBF

ProxySQL đã nằm trong stack mặc định (`docker compose up -d`). Sau khi stack lên, nạp deny rules và verify:

```bash
make phase4
```

Lệnh này nạp [config/proxysql/query_rules.sql](config/proxysql/query_rules.sql) vào ProxySQL admin, rồi chạy [scripts/phase4_check.sh](scripts/phase4_check.sh):

1. Xác nhận container ProxySQL up.
2. Hiển thị 4 deny rules đang active.
3. Chạy DBF allow/deny test qua port `6033` bằng `dbfuser`: query hợp lệ pass, `DROP`/`TRUNCATE`/`SELECT * FROM users`/injection bị block với custom error `DBF: ...`.
4. In hit counter từ `stats_mysql_query_rules` làm bằng chứng.

> Lưu ý: MySQL 8.4 tắt `mysql_native_password` mặc định. Stack đã bật `--mysql-native-password=ON` để ProxySQL auth được. Users `dbfuser`/`monitor` (native password) được tạo qua [mysql/proxysql-users.sql](mysql/proxysql-users.sql).

### Phần optional: Acra transparent encryption (evaluation path)

acra-server nằm sau compose profile `acra` (không chạy mặc định vì cần `ACRA_MASTER_KEY`). Bật bằng:

```bash
make acra-keys      # sinh keystore + ghi ACRA_MASTER_KEY vào .env
make acra-up        # docker compose --profile acra up -d acra-server
make enc-test       # hoặc chạy lại make check-phase4 (tự động bao gồm Acra nếu đang chạy)
```

`make enc-test` chứng minh: INSERT qua acra-server (port `9393`) -> MySQL lưu **ciphertext** AcraStruct; đọc qua acra-server ra **plaintext**; đọc trực tiếp MySQL chỉ thấy binary.

> PyMySQL được dùng cho path Acra thay vì mysql-connector-python, vì connector 8.x gắn MySQL query attributes (`\x00\x01`) vào COM_QUERY mà acra-server không parse được nên bỏ qua việc mã hóa. PyMySQL gửi COM_QUERY thuần.

## Chạy Phase 5 - Performance Monitoring

Phase 5 mở rộng monitoring stack với dashboard chi tiết, alert rules nâng cao và script tạo tải để quan sát metrics.

Chạy toàn bộ verification Phase 5:

```bash
make phase5
```

Script sẽ:

1. Kiểm tra Prometheus và Grafana đang chạy.
2. Xác nhận 7 alert rules Phase 5 đã load.
3. Kiểm tra MySQL exporter target UP.
4. Chạy [scripts/phase5_generate_load.py](scripts/phase5_generate_load.py) (45s) để tạo mixed query traffic.
5. Chạy [scripts/phase5_stress_connections.py](scripts/phase5_stress_connections.py) (80 connections, hold 15s) để tạo connection spike.
6. Verify key metrics có dữ liệu (threads, slow queries, QPS, InnoDB, network).
7. In trạng thái alert hiện tại.

Các target Make rời:

| Lệnh | Mô tả |
|---|---|
| `make load-test` | Chạy load generator (60s mặc định, cấu hình bằng args) |
| `make stress-conn` | Chạy connection stress test (100 connections mặc định) |
| `make check-phase5` | Chạy toàn bộ verification Phase 5 |

Script load generator hỗ trợ tham số:

```bash
python3 scripts/phase5_generate_load.py --duration 120 --select-workers 8 --write-workers 4 --slow-workers 2
```

Script stress test hỗ trợ tham số:

```bash
python3 scripts/phase5_stress_connections.py --count 150 --hold 60
```

Dashboard Phase 5 được provision sẵn trong Grafana với tên **Database Security - Phase 5 Performance**. Sau khi chạy load test, mở Grafana để quan sát:

- Connection spike và so sánh với max_connections.
- QPS và command breakdown (SELECT/INSERT/UPDATE/DELETE).
- Slow query rate.
- InnoDB buffer pool hit ratio, row operations, row lock waits.
- Network traffic (bytes sent/received).

Alert rules Phase 5 sẽ chuyển sang trạng thái `pending` rồi `firing` nếu ngưỡng bị vượt trong thời gian đủ lâu. Kiểm tra tại `http://127.0.0.1:9090/alerts`.

## Chạy Phase 6 - Sensitive Data Discovery

Phase 6 quét nơi dữ liệu nhạy cảm có thể nằm (theo tên cột) và nơi nó thực sự nằm (theo giá trị), không cần browser — toàn bộ là script + bằng chứng JSON/CSV. Cần MySQL đang chạy và đã seed dữ liệu Phase 2 (`make seed`).

Chạy toàn bộ verification Phase 6:

```bash
make phase6
```

Script sẽ:

1. Xác nhận `dbsec-mysql` đang chạy.
2. Chạy [scripts/phase6_scan_schema.py](scripts/phase6_scan_schema.py): quét tên cột trong `INFORMATION_SCHEMA`, flag cột nghi PII kèm `object_type` (TABLE/VIEW), severity + remediation.
3. Chạy [scripts/phase6_scan_data_patterns.py](scripts/phase6_scan_data_patterns.py): sample dữ liệu, match pattern email/phone/card/SSN, và đánh `access_verdict` cho từng finding.
4. Xác nhận 4 file bằng chứng tồn tại.
5. In các cột raw PII mà account low-priv (`appuser`) `SELECT` trực tiếp được — lộ gì / ở đâu / vì sao — kèm giá trị PII thật làm bằng chứng.

Các target Make rời:

| Lệnh | Mô tả |
|---|---|
| `make scan-schema` | Chỉ quét tên cột (schema scan) |
| `make scan-data` | Chỉ quét giá trị + đánh giá access (data pattern scan), hỗ trợ `--limit`/`--examples`/`--app-users`/`--mask-all` |
| `make check-phase6` | Chạy toàn bộ verification Phase 6 |

Bằng chứng Phase 6 sau khi chạy (trong `logs/discovery/`):

- `schema_findings.json` + `.csv` - cột bị flag theo tên, kèm `object_type`, `pii_type`, `severity`, `remediation`.
- `data_findings.json` + `.csv` - mỗi finding gồm: `table`/`column` (lộ ở đâu), `pattern_type` (lộ cái gì), `severity`, `access_verdict` (`PROTECTED` vs `EXPOSED`), `exposed_to` (cho ai), `exposure_path` (vì sao — grant cụ thể, vd "appuser: table-level SELECT on activity_logs"), `assessment` (1 câu tóm tắt), `match_count`/`rows_affected`, `exposed_values` (giá trị PII **thật/unmasked**, chỉ cho finding `EXPOSED` làm bằng chứng), `remediation`.

> ⚠️ Mặc định, finding `EXPOSED` ghi PII **thật** vào `exposed_values` làm bằng chứng tuyệt đối. Vì vậy `data_findings.json/.csv` đã được `.gitignore` chặn (`logs/**/*.{json,csv}`) — **không commit/chia sẻ**. Cần bản an toàn để đính báo cáo thì chạy `python3 scripts/phase6_scan_data_patterns.py --mask-all` (mọi giá trị đều mask).

## Chạy Phase 7 - Chained Path + High Availability

Phase 7 là các chế độ **opt-in** chồng lên stack mặc định bằng compose override; default `docker compose up -d` không đổi nên Phase 1-6 chạy nguyên.

### Chained path (DBF + encryption trên 1 đường)

Cần Acra keystore trước (`make acra-keys`). Sau đó:

```bash
make chain-up        # ProxySQL -> Acra -> MySQL, nạp deny rules
make chain-verify    # DROP bị chặn ở ProxySQL; secure_cards mã hóa qua Acra
make chain-down      # về default ProxySQL -> MySQL
```

### High Availability (3-node Group Replication + failover)

```bash
make ha-bootstrap    # tạo 3 node GR + ProxySQL GR-router (~vài phút, cần ~1.5GB RAM)
make ha-verify       # 3/3 ONLINE, đúng 1 primary, round-trip qua router
make ha-failover     # kill primary -> bầu primary mới -> router reroute -> data còn
make ha-rw-demo      # writes -> primary, reads + SHOW -> secondaries (R/W split)
make ha-down         # gỡ cluster + router (volume HA bị xóa, base stack giữ nguyên)
```

HA router endpoint: `127.0.0.1:6450` (R/W, qua dbfuser). Group Replication cần số node lẻ (≥3) để có quorum; cụm 3 node chịu được 1 node chết.

**R/W split** dùng đúng 3 node cho cả scale lẫn availability: 1 writer + 2 reader. Demo `make ha-rw-demo` đọc thẳng `stats_mysql_query_digest` của ProxySQL — đó là **audit log nội bộ của routing decisions**, không phải đoán mò: in từng digest_text + hostgroup nó được route tới. Sống sót qua failover (writer hostgroup tự cập nhật primary mới).

### Full integrated path

```bash
make full-up         # ProxySQL(DBF) -> Acra(encrypt) -> ha-router(GR) -> Cluster
make full-verify     # chứng minh cả 4 lớp cùng hoạt động trên 1 chain
```

### Regression (đảm bảo Phase 1-6 không vỡ)

```bash
make regression      # revert default mode + chạy lại toàn bộ check Phase 1-6
```

## Web demo UI (Phase 7 — "Same data, 4 eyes")

Một trang Flask đơn giản, click là thấy ngay — không cần đọc terminal output. Dùng để demo với người chấm/khán giả.

Yêu cầu: stack chained đang chạy (`make classify-apply` đã chạy 1 lần). HA cluster (`make ha-bootstrap`) optional — chỉ cần thiết nếu bạn muốn bấm nút **Kill Primary**.

```bash
pip install -r requirements.txt   # nếu chưa cài Flask
make demo-up                      # http://127.0.0.1:5000
```

UI có 3 section:

1. **4 role button** (Customer / Support / Fraud / DBA) → bấm là chạy `SELECT … FROM users WHERE id=1` qua chain với credential của role đó → panel hiện query, các tầng đã đi qua (highlight ProxySQL/Acra/MySQL trên sơ đồ kiến trúc), bảng dữ liệu trả về (masked/denied/cipher/plain dùng màu khác nhau), và 1 đoạn giải thích "vì sao thấy thế".
2. **4 attack button** (SQL Injection / IDOR Bump / Insider DBA Dump / Kill Primary) → mỗi nút mô phỏng 1 mối đe dọa thật, hiển thị tầng nào chặn, evidence cụ thể từ stack (error code, ciphertext hex, primary mới sau bầu cử…).
3. **Architecture banner** ở header tự highlight tầng đang được dùng trong mỗi action (xanh = pass, đỏ = blocked, xám = không đi qua).

Convincing hơn `bash scripts/*` vì khán giả tự đọc evidence trong UI, không cần tin lời người demo.

## Chạy Phase 7.5 - Data Classification (3-tier)

Phase 7.5 chồng lên chained path của Phase 7. Cần `make acra-keys` trước. Sau đó:

```bash
make classify-apply       # migrate schema, recreate Acra+ProxySQL với config mới,
                          # nạp DBF rules, encrypt 1000 row existing trong place
make classify-verify      # support=masked, fraud=decrypted, self-service=own-row, DBA=ciphertext
make self-service-demo    # 4 trường hợp riêng cho self-service (IDOR resistance)
```

Cả 4 role đều đi qua **cùng 1 chain** `ProxySQL → Acra → MySQL` (cổng `6033`); ProxySQL pass-through username nên MySQL apply đúng grant/view/procedure cho từng người. DBA chỉ là cảnh đối chứng — kết nối thẳng MySQL `3307`, không có Acra trong đường, nên thấy ciphertext at rest → chứng minh **separation of duties** (DBA giữ DB, không giữ key).

`make classify-apply` idempotent: gọi lại sẽ skip row đã encrypted (detect prefix `25 25 25` của AcraStruct).

## Endpoint Local

Các service chỉ bind vào `127.0.0.1`:

| Service | URL |
|---|---|
| MySQL | `127.0.0.1:${MYSQL_HOST_PORT}` mặc định `3307` |
| ProxySQL (client/DBF) | `127.0.0.1:${PROXYSQL_CLIENT_HOST_PORT}` mặc định `6033` |
| ProxySQL (admin) | `127.0.0.1:${PROXYSQL_ADMIN_HOST_PORT}` mặc định `6032` |
| acra-server (optional) | `127.0.0.1:${ACRA_SERVER_HOST_PORT}` mặc định `9393` |
| mysqld_exporter | `http://127.0.0.1:${MYSQLD_EXPORTER_HOST_PORT}/metrics` mặc định `9104` |
| Prometheus | `http://127.0.0.1:${PROMETHEUS_HOST_PORT}` mặc định `9090` |
| Alertmanager | `http://127.0.0.1:${ALERTMANAGER_HOST_PORT}` mặc định `9093` |
| Grafana | `http://127.0.0.1:${GRAFANA_HOST_PORT}` mặc định `3000` |
| HA router (Phase 7, profile `ha`) | `127.0.0.1:6450` R/W, admin `127.0.0.1:6452` |

Grafana mặc định:

- User: giá trị `GRAFANA_ADMIN_USER` trong `.env`.
- Password: giá trị `GRAFANA_ADMIN_PASSWORD` trong `.env`.

Dashboard được provision sẵn trong folder **Database Security**:

- **Database Security - Phase 1 Overview**: trạng thái cơ bản (MySQL up, connections, QPS, slow queries, scrape targets).
- **Database Security - Phase 5 Performance**: dashboard chi tiết (connections vs max, command breakdown, slow query rate, InnoDB metrics, network traffic, table locks).

## Ghi Chú Bảo Mật

- `.env` không được commit.
- Mật khẩu trong `.env.example` chỉ dùng cho demo local.
- Không public MySQL trực tiếp ra Internet.
- Nếu chạy trên DigitalOcean VPS, chỉ mở port cần thiết bằng cloud firewall/UFW; ưu tiên truy cập Grafana qua SSH tunnel hoặc allowlist IP.

## Dọn Dẹp

Dừng container:

```bash
docker compose down
```

Dừng và xóa dữ liệu volume:

```bash
docker compose down -v
```

Lệnh `down -v` sẽ xóa dữ liệu MySQL, Prometheus và Grafana đã lưu trong named volumes.
