# QA Review — Database Security Project

Tài liệu trả lời 4 câu hỏi review architecture/operations của project.

---

## 1. Đường đi data theo 3 role

Stack hiện tại (chained mode, Phase 7 + 7.5 bật) trên một path **duy nhất** ở cổng `6033`:

```
Client → ProxySQL (DBF, port 6033) → Acra (encrypt/decrypt, port 9393) → MySQL (port 3306 nội bộ)
                                                                              ↑
                                                            DBA direct port 3307 (bypass app stack)
```

Mỗi role có một MySQL identity riêng. ProxySQL **pass-through** username (chỉ re-auth, không terminate auth), nên MySQL nhận đúng tên user và áp đúng grant + view masking cho từng người.

### 1.1 User thường (app account `appuser`)

**Request đi:**
1. App connect tới `127.0.0.1:6033` với username `appuser` / password.
2. **ProxySQL**:
   - Match query với deny rules (`query_rules.sql`): chặn `DROP`, `TRUNCATE`, `SELECT * FROM users` (regex toàn bảng), và injection tautology `OR '1'='1'` → trả `(1148, 'DBF: ... blocked')` ngay, không xuống Acra.
   - Nếu qua được rule: forward xuống backend `dbsec-acra-server:9393`.
3. **Acra**: parse SQL, không thấy `ssn`/`credit_card` trong query (vì app chỉ đụng `users_masked`), nên pass-through, forward xuống `dbsec-mysql:3306`.
4. **MySQL**: re-auth `appuser`, check grants. `appuser` chỉ có `SELECT` trên view `users_masked` + `orders` + `activity_logs`. SELECT trực tiếp `users` → bị deny `(1142)`.

**Response trả về:**
- `users_masked` chạy CONCAT/LEFT/RIGHT trên `email`/`phone`/`address` ngay tại MySQL, **không kèm `ssn`/`credit_card`** (vì 2 cột này không có trong view).
- Bytes trả về MySQL → Acra: Acra thấy chỉ là chuỗi đã masked (không phải AcraStruct), pass-through nguyên.
- Acra → ProxySQL → app: app nhận `j***@example.net` / `***-***-3890` / `265**********...`.

→ User thường **không bao giờ thấy PII thật**; firewall đã chặn trước; key encryption không liên quan tới đường này vì cột bị mask đã clear ngay tại MySQL.

### 1.2 Support team (`support` / `supportpass`)

Giống y hệt đường của `appuser` về mặt physical: `6033 → ProxySQL → Acra → MySQL`. Khác **một chỗ** — đây là identity riêng trong MySQL, dùng để separation of duties và audit per-user.

**Request đi:**
1. Support staff (ví dụ qua CRM tool) connect `127.0.0.1:6033` với username `support`.
2. ProxySQL: pass-through `support` xuống Acra.
3. Acra: pass-through xuống MySQL (query không đụng cột encrypt).
4. MySQL re-auth `support`:
   - `SELECT FROM users_masked` → OK.
   - `SELECT FROM users` (cố đọc raw) → `(1142, SELECT command denied to user 'support'@... for table 'users')`.

**Response:**
- Masked view trả về cùng dạng như mục 1.1.
- Vì `support` có MySQL identity riêng, **mọi query của họ được phân biệt trong `general.log` + `stats_mysql_query_digest` của ProxySQL** → audit trail biết "support X đã đọc của khách Y vào lúc nào".

→ Cùng đường, cùng kết quả masked, **khác audit identity**. Đó là điểm khiến `support` không phải clone của `appuser`.

### 1.3 Admin / DBA

Có 2 nhánh tùy theo loại admin:

**(a) DBA operations — direct MySQL port `3307`:**

1. DBA connect thẳng `127.0.0.1:3307` (cổng MySQL host), **không qua ProxySQL, không qua Acra**.
2. MySQL nhận `root` (hoặc user DBA), có toàn quyền DML/DDL trên DB.
3. SELECT `ssn`, `credit_card` từ `users` → trả về **VARBINARY 161-169 byte** (AcraStruct ciphertext, hex head `25 25 25 a1…`).
4. DBA **không có Acra master key** → không decrypt được. Họ thấy ciphertext.

→ Separation of duties: **DBA giữ DB nhưng không giữ key**. Nếu DBA cố `mysqldump`, output cũng là ciphertext → exfiltrate không trộm được PII.

**(b) "Privileged staff với need-to-know" — `fraud` / `fraudpass` (compliance/fraud investigator):**

1. Connect `127.0.0.1:6033` với username `fraud` → đi qua **toàn bộ chain** như support.
2. ProxySQL deny rules vẫn áp dụng (firewall không nương nhẹ).
3. Acra forward xuống MySQL.
4. MySQL re-auth `fraud`: có `SELECT` đầy đủ trên `users` (kể cả raw `ssn`/`cc`).
5. MySQL trả ciphertext VARBINARY về.
6. **Acra** trên đường về thấy 2 cột nằm trong `encryptor_config.yaml` dưới `client_id=dbsec_client`, có key → decrypt thành plaintext.
7. ProxySQL → client: `fraud` nhận `792-38-1308` / `3581618495931032` plaintext.

→ Người duy nhất "đọc PII đầy đủ" phải đi đường chính (firewall + Acra), không có cửa hậu. Mọi query của `fraud` cũng được log Phase 3.

### 1.4 So sánh nhanh

| Role     | Endpoint        | Firewall | Encrypt layer | Thấy `email`/`phone`     | Thấy `ssn`/`cc`            |
|----------|-----------------|----------|---------------|--------------------------|----------------------------|
| user thường (`appuser`) | `6033` (chain) | ✓ ProxySQL | ✓ Acra (pass-through) | masked qua view  | không (deny + không có trong view) |
| support  | `6033` (chain) | ✓ ProxySQL | ✓ Acra (pass-through) | masked qua view  | không (deny)               |
| fraud (privileged staff) | `6033` (chain) | ✓ ProxySQL | ✓ Acra **decrypt**    | raw email/phone  | **plaintext** (Acra decrypt) |
| DBA      | `3307` direct  | ✗        | ✗ (không có Acra)     | raw plaintext    | **ciphertext** (không có key) |

---

## 2. Alert — khi nào và như thế nào

### 2.1 Stack quan sát

```
MySQL  ──metrics──►  mysqld_exporter (port 9104)
                         │
                         ▼
ProxySQL  ──stats──►  Prometheus (port 9090)  ──evaluate rules──►  fires alert  ──►  Alertmanager (port 9093)
                         │                                                                │
                         └─────────────────►  Grafana dashboards (port 3000)               │
                                                                                          ▼
                                                                          (route → email/slack/webhook)
                                                                          *demo: hiển thị tại Alertmanager UI*
```

### 2.2 Khi nào alert kích hoạt

Alert rules nằm ở `config/prometheus/rules/phase5-alerts.yml`. **7 rule chính** (Phase 5):

1. **Slow query rate cao** — `rate(mysql_global_status_slow_queries[5m]) > threshold` trong N phút → cảnh báo query chậm tăng đột biến (có thể bị tấn công SQLi-based DoS hoặc query bị regression).
2. **Threads_running tăng** — backlog query → DB sắp nghẽn.
3. **Aborted_connects spike** — burst kết nối hỏng → có thể brute-force auth hoặc misconfig client.
4. **InnoDB row lock waits** — deadlock/lock contention.
5. **Buffer pool hit ratio thấp** — cache thrashing, performance degrade.
6. **Connection usage > 70% max** — sắp hết connection slot.
7. **QPS rơi về 0** — DB ngừng nhận query (down hoặc deadlock toàn phần).

Cộng thêm alert nền của Phase 1: `up{job=...}` = 0 trong 1 phút → service xuống.

### 2.3 Diễn ra như thế nào

1. **Prometheus scrape** mysqld_exporter mỗi 15s → tích lũy time series.
2. **Rule evaluator** chạy mỗi 15s, đánh giá biểu thức PromQL của mỗi rule.
3. Khi biểu thức đúng liên tục trong `for: Nm` → alert chuyển trạng thái `PENDING` → `FIRING`.
4. **Prometheus push alert sang Alertmanager** (HTTP POST `/api/v2/alerts`).
5. **Alertmanager**:
   - Gom alert theo `group_by` (đỡ spam khi 1 sự cố trigger nhiều rule).
   - Apply silencing/inhibit nếu cần.
   - Route tới receiver theo `routes:` trong `alertmanager.yml`.
6. Trong demo của project, **receiver chỉ log + hiển thị tại UI `http://127.0.0.1:9093`** (chưa hook Slack/email/PagerDuty thật) — đây là điểm cần làm trong future work.

### 2.4 Quan sát thực tế

- Alert có thể trigger bằng `make stress-conn` (mở 100 connection cùng lúc → kích Connection usage + Aborted_connects).
- `make load-test` chạy 60s mixed load có chứa slow query → kích Slow_query_rate.
- Verify bằng `phase5_check.sh`: script này tự pre-flight Prometheus rules đã loaded chưa, rồi chạy load và in alert state.

---

## 3. HA trong architecture này

### 3.1 Cách thể hiện

Phase 7 thêm một stack **opt-in** chồng lên base stack (bật bằng `--profile ha`):

```
Client → ProxySQL HA-router (port 6450)
              │ (tự track primary bằng read_only + replication_group_members)
              ▼
         ┌────┬────┬────┐
         │ n1 │ n2 │ n3 │   MySQL 8.4 Group Replication (single-primary)
         └────┴────┴────┘
            sync replication, auto-elect primary
```

**Các quyết định kiến trúc đáng ghi:**

- **Group Replication 3-node single-primary**: đồng bộ certify trên đa số node, mọi commit đều phải được majority chấp nhận → giảm split-brain.
- **ProxySQL-GR thay cho MySQL Router**: Router chỉ auto-failover được nếu metadata được MySQL Shell tạo, nhưng image MySQL Shell **không pull công khai** (`container-registry.oracle.com/mysql/community-shell:*` báo `Auth failed`). Theo nguyên tắc fallback §4.3 của proposal, swap sang ProxySQL cấu hình GR-aware — vẫn track primary qua `read_only` flag và `performance_schema.replication_group_members`, vai trò giống Router (HA endpoint ổn định, auto-reroute).
- **Quorum**: 3 node chịu được 1 chết. Nếu một node bị tách khỏi group (network partition) → group còn 2/3, vẫn ghi được; nếu mất thêm 1 nữa → mất quorum → cluster dừng ghi để tránh inconsistency. Đây là behavior đúng của GR.
- **Bootstrap manual** vì không có MySQL Shell: script `phase7_ha_bootstrap.sh` chạy `RESET BINARY LOGS AND GTIDS` → tạo `repl` user với `SQL_LOG_BIN=0` → `CHANGE REPLICATION SOURCE … FOR CHANNEL 'group_replication_recovery'` → `START GROUP_REPLICATION` (bootstrap trên node 1, join trên 2/3).

### 3.2 Có hiệu quả không?

**Hiệu quả ở những mặt:**

- ✓ **Đã chứng minh được**: `phase7_ha_failover.py` kill primary → cluster bầu primary mới → ProxySQL HA-router tự reroute → write tiếp tục thành công → node cũ rejoin → data intact.
- ✓ Synchronous replication ⇒ RPO ≈ 0 trên các commit đã majority-acked.
- ✓ Tách hoàn toàn khỏi base stack (port 6450 vs 6033) nên không động chạm Phase 1-6.

**Hạn chế (phải nói thẳng):**

- ✗ **ProxySQL HA-router là single point of failure**: nếu chính router chết, client mất endpoint. Production cần 2 router + virtual IP (keepalived/HAProxy/cloud LB).
- ✗ **Acra cũng SPOF**: trong full integrated path, chỉ có 1 acra-server. Acra chết → toàn bộ chain mất Tier 1 read/write. Production cần Acra-HA (multi-instance + key sync).
- ✗ **MySQL Shell vắng mặt** → InnoDB Cluster bonuses (cluster.status() JSON, cluster.rescan(), member-state metadata table chuẩn) đều không có. Phải vận hành GR bằng SQL trực tiếp.
- ✗ **Không multi-region DR**: cluster trong cùng 1 host Docker → host chết → toàn bộ chết. Production cần async replica ở region khác (delayed slave / Group Replication multi-primary cross-region).
- ✗ **Không backup automation**: không có `xtrabackup`/`mysqldump` job định kỳ; chưa test restore.
- ✗ **Không chaos test**: chỉ kill primary, chưa test network partition, IO hang, slow disk.
- ✗ **RTO chưa đo**: failover demo "thấy là chạy" nhưng chưa đo đúng "X giây từ kill đến write thành công lại". Production cần SLO cụ thể.

**Tóm gọn**: HA ở project này **đủ để chứng minh nguyên lý** (auto-failover, no data loss khi mất 1 node) và đủ để demo trên đồ án; **chưa đủ cho production**. Đường mở rộng đã rõ — chỉ là chưa làm.

---

## 4. Done well vs Future work

### 4.1 Đã làm tốt

**Architecture / Security:**
- Defense in depth chia tầng rõ ràng: ProxySQL DBF (Phase 4) + Acra encrypt (Phase 4/7) + RBAC + view masking (Phase 2) + 3-tier classification (Phase 7.5) + active monitor (Phase 3) + discovery (Phase 6) + HA (Phase 7).
- **Một path duy nhất** sau Phase 7.5: tất cả role đều đi `ProxySQL → Acra → MySQL`, không có lỗ "support bypass firewall" hay "privileged client connect thẳng Acra". Firewall enforce trước cho cả admin.
- **Separation of duties**: DBA giữ DB nhưng không giữ Acra master key → exfiltrate dữ liệu cũng chỉ được ciphertext. Đây là kiểm soát chống insider threat cụ thể, không phải chỉ slogan.
- **Per-user audit identity** ở MySQL (`appuser` / `support` / `fraud`) → ai đọc PII đầy đủ có chữ ký trong `general.log` + ProxySQL digest.

**Code quality / vận hành:**
- Script Phase 7.5 **idempotent**: re-apply không double-encrypt (detect prefix `25 25 25` của AcraStruct và skip).
- Migration SQL **clean idempotency**: `DROP USER IF EXISTS + CREATE` thay vì `CREATE + REVOKE + GRANT` (REVOKE trên user mới CREATE báo `ER_NONEXISTING_GRANT`).
- Regression script (`phase7_regression.sh`) tự revert default mode rồi rerun Phase 1-6 → kiểm tra "không vỡ phase trước".
- Makefile mapping tất cả flow chính (`make classify-apply`, `make ha-failover`, …).

**Documentation / evidence:**
- Phase 6 discovery thực sự **chỉ ra điểm thủng**: `activity_logs.notes` chứa PII rò rỉ trong free-text mà view-masking-theo-cột không bắt được. Discovery không chỉ "tìm PII" mà còn nối với Phase 2 ("masking chưa đủ chỗ nào").
- `problem.md` ghi lại 11 sự cố Acra (đặc biệt AcraCensor không parse được binary protocol MySQL 8.4) → giải trình được lý do ProxySQL đứng làm DBF chính thay vì AcraCensor.
- README + proposal cập nhật theo từng phase, có sơ đồ ASCII rõ ràng.

**Observability:**
- Grafana dashboards Phase 1 + Phase 5 provisioned sẵn.
- 7 alert rules có ý nghĩa thực tế (slow query / lock wait / connection usage / QPS drop).
- Active Monitor pipeline thu cả MySQL general.log + ProxySQL digest + Acra audit log → audit trail có per-client attribution kể cả khi ProxySQL ở giữa.

### 4.2 Future work

**HA / Availability:**
- ProxySQL/Acra HA (hiện là SPOF): chạy ≥2 instance + virtual IP hoặc cloud LB.
- Multi-region DR: async replica ở region khác để chịu host/region chết.
- Backup automation: `xtrabackup` định kỳ + test restore (PCI-DSS Req 10).
- Chaos testing: network partition giữa GR node, IO hang, slow disk, kill ProxySQL.
- Đo RTO/RPO thật, gắn SLO.

**Security / Compliance:**
- Acra master key đang nằm trong `.env` → cần đẩy vào HSM (Vault / AWS KMS / Azure Key Vault).
- Key rotation procedure cho Acra (rotate `dbsec_client` storage key + re-encrypt batch).
- TLS end-to-end: hiện một số đường có `ssl_disabled=True` để dễ debug, production phải bắt buộc TLS từ client → ProxySQL → Acra → MySQL.
- Per-row audit log của "ai đọc cột nào của khách nào lúc nào" (compliance evidence pack PCI Req 10).
- Secret rotation cho password app/DB (hiện hard-code trong `.env` + ProxySQL config).
- TDE ở MySQL data file (in case ai đó copy raw datadir) — bổ sung lớp transparent thêm dưới Acra.

**Application boundary:**
- Tier 1 hiện chỉ `ssn`/`credit_card`. Cần review thêm: `phone`, `address`, `dob` (nếu có) nên lên Tier 1 không, hay Tier 2 mask là đủ?
- Format-preserving encryption (FPE) cho card → giữ được last4 mà vẫn encrypt — hiện Acra dùng full encrypt nên cần thêm cột "last4 plaintext" nếu cần search.
- Tokenization layer ngoài database — cho phép app cầm token (không phải PAN) → giảm scope PCI.

**Kubernetes / Cloud (Phase 8 từ proposal):**
- StatefulSet MySQL + PVC.
- ConfigMap/Secret cho ProxySQL/Acra config thay cho compose file.
- Cloud LB cho front ProxySQL.
- mTLS giữa các service trong cluster.

**Quality of life:**
- CI: chạy `make regression` + `make classify-verify` trên PR.
- Migration framework chuẩn (Flyway/Liquibase) thay cho SQL file thủ công.
- Alertmanager hook thật (Slack/email/PagerDuty) thay cho UI-only.
- Per-environment config (dev/staging/prod overlay).
- Đo benchmark latency của chained path so với direct (đo cost của Acra).
