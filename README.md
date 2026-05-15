# Database Security Course Project

Đồ án môn học về Database Security, triển khai theo từng phase trong [proposal.md](proposal.md).

Trạng thái hiện tại của source code: **hoàn thành Phase 1 - Môi Trường Nền**.

Phase 1 cung cấp baseline chạy bằng Docker Compose:

- MySQL 8.4.
- mysqld_exporter.
- Prometheus.
- Alertmanager.
- Grafana với datasource và dashboard được provision sẵn.
- Alert rules cơ bản cho trạng thái target và connection count.
- Script kiểm tra endpoint sau khi khởi động stack.

Các phần schema, seed data, RBAC, masking, Acra, HA database cluster và Kubernetes sẽ được triển khai ở các phase sau.

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
