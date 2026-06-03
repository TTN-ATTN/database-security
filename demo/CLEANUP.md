# Hướng dẫn Cleanup Demo

Sau khi demo xong, làm theo các bước dưới để free tài nguyên (RAM, disk) và đưa stack về trạng thái ban đầu.

---

## TL;DR — 1 lệnh dọn sạch

```bash
# Ctrl+C ở terminal đang chạy `make demo-up`, rồi:
make demo-clean-all
```

Trong ~60s sẽ:
- Stop Flask
- Xóa `__pycache__`
- Xóa demo rows trong DB (orders `rw-demo-*`, secure_cards test, ha_demo + ha_pulse tables, demo users)
- Truncate `logs/mysql/general.log` (~16MB) + `audit_report.json`
- Tear down HA cluster (3 MySQL node + ha-router) → **free ~1.5GB RAM**
- Tear down base stack (MySQL + ProxySQL + Acra + Grafana + Prometheus + Alertmanager)

Volumes (`mysql_data`, `acra_keys`, `prometheus_data`, `grafana_data`) **vẫn giữ** → lần sau `make demo-up` bootstrap nhanh (không phải re-encrypt 1000 row, Acra keystore còn nguyên).

---

## Cleanup theo mức (chọn theo nhu cầu)

| Mục đích | Lệnh |
|---|---|
| Chỉ xóa pycache + stop Flask (an toàn nhất) | `bash scripts/cleanup_demo_artifacts.sh` |
| Trên + xóa demo rows trong DB | `make demo-clean` |
| Trên + truncate `logs/mysql/` | `bash scripts/cleanup_demo_artifacts.sh --logs` |
| Trên + tear down HA cluster | `bash scripts/cleanup_demo_artifacts.sh --ha` |
| Trên + tear down base stack (volumes giữ) | `bash scripts/cleanup_demo_artifacts.sh --base` |
| **Tất cả ở trên** | `make demo-clean-all` |
| Nuclear: tear down **toàn bộ stack + xóa volume** (sẽ mất encrypted ssn/cc + keystore) | `make clean-volumes` |

Xem `bash scripts/cleanup_demo_artifacts.sh --help` để biết flag chi tiết.

---

## Thứ tự manual (khi không tin script)

Nếu muốn dọn từng bước có kiểm soát:

### 1. Dừng Flask

Có 2 cách:

```bash
# Cách 1 — Ctrl+C trên terminal đang chạy `make demo-up`
# Cách 2 — Kill từ terminal khác
pkill -f 'demo/app.py'
```

### 2. Tear down HA cluster (free 1.5GB RAM)

```bash
make ha-down
```

→ Stops + removes 3 node `dbsec-mysql-1/2/3` + `dbsec-ha-router` + volumes của riêng HA. Base stack **không bị động đến**.

### 3. (Optional) Reset demo data trong DB

```bash
docker exec -i dbsec-mysql mysql -uroot -prootpass testdb <<EOF
DELETE FROM secure_cards WHERE holder LIKE 'phase%-demo';
DELETE FROM orders WHERE product LIKE 'rw-demo-%' OR product LIKE 'phase5-load-%';
DROP TABLE IF EXISTS ha_demo;
DROP TABLE IF EXISTS ha_pulse;
EOF
```

### 4. (Optional) Reset MySQL audit log

```bash
truncate -s 0 logs/mysql/general.log logs/mysql/slow.log
rm -f logs/mysql/audit_report.json logs/mysql/audit_summary.csv
docker exec dbsec-mysql mysqladmin -uroot -prootpass flush-logs
```

`mysqladmin flush-logs` cần thiết để MySQL release file descriptor cũ và cấp phát block mới — không có nó, WSL2 vẫn báo file size cũ dù `ls` hiển thị 0 bytes.

### 5. (Optional) Dừng cả base stack

```bash
make down                # giữ volume → restart lại data còn nguyên
# HOẶC:
make clean-volumes       # ⚠️ xóa volume → mất encrypted data
```

---

## Cái gì được giữ vs xóa

| | `demo-clean` | `demo-clean-all` | `clean-volumes` |
|---|---|---|---|
| Flask process | ❌ stop | ❌ stop | ❌ stop |
| `__pycache__` | ❌ xóa | ❌ xóa | ❌ xóa |
| Demo rows trong DB | ❌ xóa | ❌ xóa | ❌ (volume xóa hết) |
| `logs/mysql/general.log` | ✓ giữ | ❌ truncate | ❌ |
| HA cluster | ✓ giữ | ❌ tear down | ❌ |
| Base stack (MySQL, ProxySQL, Acra, Prom, Grafana) | ✓ chạy | ❌ down | ❌ down |
| Encrypted `users.ssn/cc` (mysql_data volume) | ✓ giữ | ✓ giữ | ❌ **mất** |
| Acra keystore (`acra_keys` volume) | ✓ giữ | ✓ giữ | ❌ **mất** |
| `.env` (chứa ACRA_MASTER_KEY) | ✓ giữ | ✓ giữ | ✓ giữ |

→ **Quy tắc**: sau `make demo-clean-all`, lần sau `make demo-up` tự bootstrap lại (~3-5 phút từ cold). Sau `make clean-volumes` thì cũng `make demo-up` lo được nhưng tốn thêm thời gian re-encrypt 1000 row.

---

## Troubleshooting cleanup

### `make demo-clean-all` báo lỗi tear down HA

```bash
# Force remove containers thẳng tay:
docker rm -f dbsec-mysql-1 dbsec-mysql-2 dbsec-mysql-3 dbsec-ha-router

# Force remove volumes:
docker volume rm -f \
  database-security_mysql_ha_1_data \
  database-security_mysql_ha_2_data \
  database-security_mysql_ha_3_data
```

### `logs/mysql/general.log` vẫn lớn sau truncate

WSL2 bind-mount từ Windows NTFS giữ block cũ đến khi MySQL release fd. Chạy:

```bash
docker exec dbsec-mysql mysqladmin -uroot -prootpass flush-logs
```

→ MySQL đóng + mở lại file → Windows free block.

### Flask không stop bằng Ctrl+C

```bash
# WSL2 đôi khi không forward signal đúng. Force kill:
pkill -9 -f 'demo/app.py'
# Hoặc kill theo PID:
ps -ef | grep 'demo/app.py'
kill -9 <PID>
```

### Lần sau `make demo-up` báo lỗi connect MySQL

Stack có thể đã bị compose down. Chạy lại setup:

```bash
make phase7_part2   # idempotent — bỏ qua bước đã có
make demo-up
```

---

## Lần demo tiếp theo

Sau `make demo-clean-all`, lần demo tiếp theo chỉ cần:

```bash
make ha-bootstrap    # ~2-3 phút bring HA lại (1.5GB RAM)
make demo-up         # Flask
```

Hoặc gọn hơn:

```bash
make phase7_part2    # idempotent: skip bước đã xong, chỉ làm bước còn thiếu
make demo-up
```
