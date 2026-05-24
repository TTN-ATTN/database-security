# Database Security Course Project

Đồ án môn học về Database Security, triển khai theo từng phase trong [proposal.md](proposal.md).

Trạng thái hiện tại của source code:

- **Phase 1 - Môi Trường Nền**: hoàn thành.
- **Phase 2 - Database, Seed Data, RBAC/Masking**: hoàn thành.
- **Phase 3 - Active Monitor**: hoàn thành (MySQL general log + slow log, audit trail, evidence parser).
- **Phase 4 - Database Firewall + Acra Encryption**: hoàn thành (ProxySQL DBF làm enforcement chính; Acra transparent encryption ở evaluation path).
- **Phase 5 - Performance Monitoring**: hoàn thành (Grafana dashboard nâng cao, alert rules, load test, connection stress test).
- **Phase 6 - Sensitive Data Discovery**: hoàn thành (schema scan theo tên cột + data pattern scan email/phone/card/SSN, phát hiện PII rò rỉ trong free-text, xuất JSON/CSV kèm remediation).

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

> Giá trị PII trong report luôn được mask (vd `***-**-1234`, `************1032`), nên file bằng chứng an toàn để commit/đính kèm báo cáo (mặc dù `.gitignore` đã loại nội dung log mặc định).

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
