# Database Security Course Project

Đồ án môn học về Database Security, triển khai theo từng phase trong [proposal.md](proposal.md).

Trạng thái hiện tại của source code:

- **Phase 1 - Môi Trường Nền**: hoàn thành.
- **Phase 2 - Database, Seed Data, RBAC/Masking**: hoàn thành.
- **Phase 3 - Active Monitor**: hoàn thành (MySQL general log + slow log, audit trail, evidence parser).

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
- Script [scripts/generate_audit_queries.py](scripts/generate_audit_queries.py) sinh các query có chủ đích (normal app traffic, root đọc PII, appuser bị deny PII, abnormal `DELETE/TRUNCATE/DROP` trên bảng scratch, slow query) và gắn tag `/* phase3:<category> */` vào từng query để dễ truy lùng trong log.
- Script [scripts/parse_audit_log.py](scripts/parse_audit_log.py) parse `general.log` + `slow.log` thành `audit_report.json` và `audit_summary.csv` làm bằng chứng audit (user, timestamp, command, query, query_time).
- Script [scripts/check_phase3.sh](scripts/check_phase3.sh) xác nhận log đang ghi, chạy traffic generator, flush log, parse và in các dòng evidence quan trọng (denied PII access, abnormal operations).

Các phần Acra/DBF, performance load test, sensitive discovery, HA database cluster và Kubernetes sẽ được triển khai ở các phase sau.

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
bash scripts/check_phase1.sh
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
3. Chạy [scripts/generate_audit_queries.py](scripts/generate_audit_queries.py) để sinh traffic.
4. `FLUSH LOGS` để file phản ánh buffer hiện tại.
5. Xác nhận `logs/mysql/general.log` và `logs/mysql/slow.log` không rỗng.
6. Parse log bằng [scripts/parse_audit_log.py](scripts/parse_audit_log.py) → `audit_report.json` + `audit_summary.csv`.
7. In các dòng evidence quan trọng: appuser bị deny truy cập bảng `users` raw, root thực hiện `DELETE/TRUNCATE/DROP`.

Các target Make rời:

| Lệnh | Mô tả |
|---|---|
| `make audit-traffic` | Chỉ sinh traffic, không parse |
| `make parse-audit` | Chỉ parse log đã có sẵn |
| `make tail-general` | `tail -f` general log |
| `make tail-slow` | `tail -f` slow log |

Bằng chứng Phase 3 sau khi chạy:

- `logs/mysql/general.log` - mọi query, kèm `user@host` và timestamp.
- `logs/mysql/slow.log` - query vượt `long_query_time = 0.5s`.
- `logs/mysql/audit_report.json` - structured per-event records.
- `logs/mysql/audit_summary.csv` - đếm theo phase3 tag và theo command.

## Endpoint Local

Các service chỉ bind vào `127.0.0.1`:

| Service | URL |
|---|---|
| MySQL | `127.0.0.1:${MYSQL_HOST_PORT}` mặc định `3307` |
| mysqld_exporter | `http://127.0.0.1:${MYSQLD_EXPORTER_HOST_PORT}/metrics` mặc định `9104` |
| Prometheus | `http://127.0.0.1:${PROMETHEUS_HOST_PORT}` mặc định `9090` |
| Alertmanager | `http://127.0.0.1:${ALERTMANAGER_HOST_PORT}` mặc định `9093` |
| Grafana | `http://127.0.0.1:${GRAFANA_HOST_PORT}` mặc định `3000` |

Grafana mặc định:

- User: giá trị `GRAFANA_ADMIN_USER` trong `.env`.
- Password: giá trị `GRAFANA_ADMIN_PASSWORD` trong `.env`.

Dashboard được provision sẵn trong folder **Database Security** với tên **Database Security - Phase 1 Overview**.

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
