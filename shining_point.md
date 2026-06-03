# Shining Points — những điểm project thật sự làm tốt

Document đối xứng với [future_work.md](future_work.md). Mỗi mục: **điều gì làm**, **vì sao đó không phải tầm thường**, **bằng chứng ở đâu trong repo** (để khi viva được hỏi thì show code/UI thật, không phải kể chay).

> Spirit: project demo nguyên lý **defense in depth** với chiều sâu thực — không phải bê 5 buzzword vào docker compose. Mỗi layer phòng thủ đều có thể chứng minh độc lập bằng query thật + lỗi thật + log thật.

---

## 1. Single data path cho mọi role — không có "trusted bypass"

### Điều gì làm
4 role app (customer / support / fraud / self_service) đi qua **đúng 1 đường**: `ProxySQL :6033 → Acra :9393 → MySQL :3306`. Chỉ MySQL identity khác nhau. Không có shortcut cho "trusted" role.

### Vì sao đó không phải tầm thường
Pattern phổ biến trong project học là: "app dùng user thường qua firewall, admin/internal tool nối thẳng DB bỏ qua firewall". Cái đó **vỡ ngay khi compromised internal tool** — kẻ tấn công lấy được internal account = không có firewall = chơi cờ tự do.

Project mình **firewall enforce mọi role**, kể cả `fraud` (privileged). Compromise account `fraud` → firewall vẫn chặn `DROP TABLE`. Chỉ DBA direct là bypass (đường vận hành thật sự khác — không qua app).

### Bằng chứng
- Code: `demo/app.py` — `SUPPORT`, `FRAUD`, `SELF_SERVICE` configs đều `port=CHAIN_PORT (6033)`.
- UI: support page → search `' OR '1'='1` → DBF chặn (1148). Carol có thể là "trusted internal" nhưng vẫn không bypass được.
- Sequence diagram: [data_flow.md §2 (Support)](data_flow.md#2-support-carol--support).

---

## 2. Separation of duties cụ thể (DBA giữ DB, không giữ key)

### Điều gì làm
DBA có toàn quyền MySQL (root, port 3307 direct). Nhưng **không có Acra master key**. Mở bảng users → ssn/cc là VARBINARY 161 bytes ciphertext, hex prefix `252525A1…`. Mang dump file đi → không decrypt được.

### Vì sao đó không phải tầm thường
"Separation of duties" thường bị đề cập như slogan policy. Project mình hiện thực hoá nó bằng kiến trúc cụ thể: **key vật lý nằm ở process khác** (Acra) với người vận hành khác. Mặc dù trong demo cùng admin chạy cả 2, **rào cản kỹ thuật để tách 2 người là 1 file `.env` move khỏi DBA host**.

Nói cách khác: không phải "tin DBA tốt", mà là **"DBA tốt cũng chỉ thấy ciphertext"**.

### Bằng chứng
- Admin page → panel "Storage sample": render trực tiếp `SELECT id, ssn, HEX(LEFT(ssn,16))` ra `0x252525A1…`.
- Admin page → panel "SQL playground": user gõ `SELECT id, ssn FROM users LIMIT 5` → kết quả `<binary 161 bytes; head=0x252525a1…>` — chứng minh root cũng không thấy plaintext.
- Code: `demo/app.py` — `admin_query()` connect `port=3307` (direct MySQL), không qua Acra. So sánh với `customer_query()` connect `port=6033` (qua Acra) → cùng query SSN ra 2 kết quả khác.

---

## 3. IDOR defense ở tầng DB (không phải app-only)

### Điều gì làm
Stored procedure `get_my_profile(p_customer_id, p_self_token)` check:
```sql
expected = SHA2(CONCAT(p_customer_id, ':', 'self_service_secret'), 256);
IF p_self_token <> expected THEN SIGNAL SQLSTATE '45000' ...
```

App tính token dùng `session.user_id`. User đổi URL `?id=2` → app gửi `(2, token_for(session=1))` → procedure thấy token không match id → từ chối với 1644.

### Vì sao đó không phải tầm thường
**OWASP API Security Top 1 (2019 + 2023)** là Broken Object Level Authorization — tức IDOR. Pattern thường thấy:
```python
@app.get("/api/profile/<id>")
def profile(id):
    return db.query("SELECT * FROM users WHERE id=?", id)  # ← KHÔNG check ownership
```
App dev quên check `session.user_id == id` → IDOR.

Trong project mình, **ngay cả khi app dev quên check**, DB vẫn refuse. Đây là "defense in depth ngược": phòng thủ tầng DB cover lỗi tầng app. Vụ Parler (2021), Optus (2022), T-Mobile, Peloton… đều dính cùng pattern và **đều có thể chặn được bằng pattern này**.

### Bằng chứng
- SQL: [mysql/phase7_5_classification.sql](mysql/phase7_5_classification.sql) — định nghĩa proc với `SQL SECURITY DEFINER` + token check.
- UI: customer page → click "Switch: 2" hoặc playground "Try IDOR" → render 403 page với error `(1644, 'Self-service: invalid or missing self-auth token')`.
- Sequence diagram: [data_flow.md §1 — Customer IDOR](data_flow.md#khi-alice-thử-idor-id2).

---

## 4. 3-tier data classification — đúng kỹ thuật cho đúng cột

### Điều gì làm
| Tier | Cột | Kỹ thuật | Vì sao |
|---|---|---|---|
| 1 — Encrypt @ Acra | `ssn`, `credit_card` | AcraStruct ciphertext VARBINARY(512) | Nhạy nhất, không cần search/sort, app rarely cần đọc |
| 2 — Mask @ MySQL | `email`, `phone`, `address` | View `users_masked` với CONCAT/LEFT/RIGHT | PII nhưng dùng hằng ngày, cần partial display |
| 3 — Clear | `id`, `first_name`, `last_name`, `created_at` | Không bảo vệ | Identifier business cần, không nhạy |

### Vì sao đó không phải tầm thường
**"Encrypt mọi cột PII"** là pattern naive — kill performance, kill search, kill mask use case. **"Mask mọi cột"** là pattern khác kém — không bảo vệ khi attacker đọc raw bytes. Project mình **phân loại theo risk profile cụ thể của từng cột** + áp đúng kỹ thuật:
- Cột nguy cao + ít dùng → encrypt cứng.
- Cột vừa nguy + dùng nhiều → mask tại view.
- Cột identifier → clear.

Đây là **data classification taxonomy** thật sự, không phải "encrypt = security".

### Bằng chứng
- Schema migration: [mysql/phase7_5_classification.sql](mysql/phase7_5_classification.sql) — ALTER `ssn`/`cc` → VARBINARY, DROP+CREATE `users_masked` view bỏ ssn/cc.
- Acra config: [config/acra/encryptor_config.yaml](config/acra/encryptor_config.yaml) — chỉ ssn/cc nằm trong `encrypted:` list.
- UI demo: Carol detail page → SSN/CC = "restricted" (Tier 1 không có trong view), email/phone = `j***@…` (Tier 2 masked), name = clear (Tier 3).

---

## 5. Per-user MySQL identity → audit trail có per-user attribution

### Điều gì làm
4 MySQL user thực: `appuser`, `support`, `fraud`, `self_service`. ProxySQL pass-through username (không terminate auth). MySQL `general.log` ghi đúng tên user cho mọi query.

### Vì sao đó không phải tầm thường
Pattern phổ biến: app dùng 1 MySQL account share cho mọi end-user. Lúc đó:
- MySQL log chỉ thấy "appuser thực hiện X" → không biết end-user nào.
- Bị breach → không thể truy ai đọc PII của khách nào.

Project mình **mỗi role app = 1 MySQL user** + ProxySQL không terminate auth. Hệ quả:
- MySQL general.log có column `user` = `support`/`fraud`/...
- ProxySQL `stats_mysql_query_digest` cũng break down theo frontend user.
- Phase 3 audit pipeline gom cả 2 → per-user attribution không mất qua proxy.

→ Forensic: "Carol đọc profile của khách nào lúc nào" là **truy được**.

### Bằng chứng
- Config: [config/proxysql/proxysql.cnf](config/proxysql/proxysql.cnf) + [proxysql.chained.cnf](config/proxysql/proxysql.chained.cnf) — `mysql_users` list 4 user.
- Verify: Phase 7.5 verify script chạy `support` qua chain → MySQL log line ra `support@…` chứ không phải `appuser@…`.
- Sequence diagram: [data_flow.md](data_flow.md) — `re-auth as support` được call ra rõ ở mọi diagram.

---

## 6. Khi gặp tooling block, pivot thay vì handwave

### Điều gì làm
2 lần dính tooling vấn đề thật, document và pivot:

**6a. AcraCensor không parse MySQL 8.4 binary protocol**
- Phát hiện: thử dùng AcraCensor làm DBF → query prepared statement (binary) không match rule.
- Document: [problem.md](problem.md) §11.
- Pivot: chọn ProxySQL — native MySQL protocol parser. Acra giữ vai trò encryption gateway (điểm mạnh thật của Acra).

**6b. MySQL Shell image không pullable**
- Phát hiện: MySQL Router cần InnoDB Cluster metadata do Shell tạo. `container-registry.oracle.com/mysql/community-shell:*` trả `Auth failed`.
- Pivot: thay MySQL Router bằng ProxySQL cấu hình GR-aware. Cùng vai trò (track primary qua read_only + members table, auto-reroute), dùng image có sẵn.
- Setup GR manual qua SQL (RESET BINARY LOGS, CHANGE REPLICATION SOURCE, START GROUP_REPLICATION) thay vì auto qua Shell.

### Vì sao đó không phải tầm thường
Project học thường gặp 2 phản ứng kém:
- (a) Giả vờ không có vấn đề (chạy thử 1 lần, không reproduce, ghi "AcraCensor works ✓").
- (b) Bỏ feature ("không làm được DBF, skip").

Project mình chọn **(c) acknowledge + pivot** — vẫn deliver chức năng tương đương bằng tool khác. Đây là **engineering thực sự**, không phải checkbox.

### Bằng chứng
- [problem.md](problem.md) — 11 sự cố cụ thể với root cause + fix.
- proposal §4.3 — "Nguyên tắc fallback" được vạch sẵn để justify pivot.
- HA bootstrap script: [scripts/phase7_ha_bootstrap.sh](scripts/phase7_ha_bootstrap.sh) — manual GR với RESET BINARY LOGS, không phải `cluster.create()` đơn giản của Shell.

---

## 7. Phase 6 discovery: tìm PII + đánh giá đủ tiêu chuẩn hay chưa

### Điều gì làm
Scanner regex match PII patterns (SSN, credit card, email, phone) trên mọi cột text. **Kèm cross-check grants**: cùng pattern, finding `access_verdict = EXPOSED` nếu low-priv user (`appuser`) có grant SELECT đến bảng raw chứa PII.

Output cụ thể: `activity_logs.notes` chứa SSN (PII rò rỉ trong free-text). View masking + RBAC trên `users` không bắt được vì SSN không ở column `users.ssn` mà ở `activity_logs.notes` — chỗ admin **không nghĩ là cần mask**.

### Vì sao đó không phải tầm thường
Discovery tool thường stop ở "tìm PII". Project mình **đẩy thêm 1 bước**: PII tìm được có thực sự đang bị ai đọc không? Đây là **discovery → action pipeline** chứ không phải just-find-and-report.

Cụ thể giá trị:
- Tìm PII trong cột `users.ssn` (tên gợi) → ai cũng biết, ai cũng mask. Boring.
- Tìm PII trong cột `activity_logs.notes` (tên vô tội) → **đây mới là cái value của tool**.

Real-world: vụ Equifax (2017), Capital One (2019)… đều rò qua "cột không ai nghĩ tới". Project mình bắt được pattern này.

### Bằng chứng
- Scanner: [scripts/phase6_scan_data_patterns.py](scripts/phase6_scan_data_patterns.py).
- Output: [logs/discovery/data_findings.json](logs/discovery/data_findings.json) — 6 finding, có `activity_logs.notes` với `pattern_type=SSN`, `access_verdict=EXPOSED`, `exposed_to=["appuser"]`.
- UI dedicated page: `/admin/discovery` render finding cards với stat 4 ô + table.

---

## 8. HA pulse — chứng minh sống, không phải claim "có HA"

### Điều gì làm
Admin page có panel auto-INSERT mỗi 2s qua ha-router :6450, ghi node nào thực hiện write (`@@report_host`). Render timeline 30 dot xanh/đỏ + history. User bấm Stop primary ở panel cluster → vài giây pulse đỏ → resume xanh ở node khác.

### Vì sao đó không phải tầm thường
"Có HA" thường được claim bằng config + 1 screenshot 3 node ONLINE. **Khán giả không thấy được service bị kill mà vẫn hoạt động.**

Pulse panel **rendere proof realtime**: 
- Trước kill: dots xanh liên tục, node = mysql-1.
- Lúc kill: 3-4 dot đỏ.
- Sau election: dots xanh tiếp, node = mysql-2.
- ID pulse tăng liên tục (1, 2, 3, ..., 89, 90, 91) — không có gap → không mất write.

Visual proof writes survive, không phải logical claim.

### Bằng chứng
- Backend: `demo/app.py` → `admin_ha_pulse()` — INSERT + SELECT FOR UPDATE để confirm writer.
- UI: admin page → panel "HA pulse" với timeline 12px dot xanh/đỏ + history table.
- Sequence diagram: [data_flow.md §5](data_flow.md#5-ha-pulse--chứng-minh-writes-survive-failover) — diagram chi tiết cycle kill → election → recover.

---

## 9. R/W split với layer hiện có (không thêm component)

### Điều gì làm
ProxySQL HA-router đã đứng đó để route writer/reader. Thêm 3 query rule (1010/1020/1030) tận dụng cùng router cho R/W split:
- `^SELECT.*FOR (UPDATE|SHARE)` → writer (giữ lock)
- `^SELECT` → reader
- `^SHOW` → reader
- Còn lại → default writer

### Vì sao đó không phải tầm thường
Pattern phổ biến: 1 layer cho HA, 1 layer khác cho R/W split. Tăng surface area, tăng latency, tăng SPOF.

Project mình **dùng đúng 1 ProxySQL** cho cả 2 chức năng (vì ProxySQL hỗ trợ multi-rule routing native). Đây là **architectural minimalism** — không over-engineer.

Demo: 3 reader/writer load thật → đọc `stats_mysql_query_digest` của chính ProxySQL → in ra digest_text + hostgroup nó được route. **Self-audit từ proxy, không phải đoán.**

### Bằng chứng
- Config: [config/proxysql/proxysql-ha.cnf](config/proxysql/proxysql-ha.cnf) §`mysql_query_rules` — 3 rule với apply=1.
- Demo script: [scripts/phase7_ha_rw_demo.py](scripts/phase7_ha_rw_demo.py) — query stats_mysql_query_digest, in ra (rule_id, hostgroup, count, digest_text).
- Verify R/W split sống sót failover: stop primary → R/W split tự cập nhật vì writer hostgroup là chính cluster monitor result.

---

## 10. Audit pipeline gom 3 nguồn → per-client attribution không mất

### Điều gì làm
Phase 3 Active Monitor thu log từ:
1. **MySQL general.log** — per-query timestamp + user + statement.
2. **ProxySQL `stats_mysql_query_digest`** — per-frontend-user breakdown + deny rule hits.
3. **Acra audit log** — mỗi dòng có `integrity=<sha256>` chain (chống tamper).

Script parse thành JSON/CSV evidence.

### Vì sao đó không phải tầm thường
Khi MySQL ở sau ProxySQL, MySQL `general.log` chỉ thấy **1 connection backend duy nhất từ ProxySQL** → mất per-client attribution. Đây là gotcha phổ biến của proxy-based architecture.

Project mình **fix bằng cách thu ProxySQL stats** riêng — ProxySQL biết end-user nào gửi query (vì auth ở frontend). Combine MySQL log (timestamp + actual SQL) + ProxySQL stats (frontend user) = full attribution.

Acra audit log thêm 1 lớp **tamper-evident** (hash chain) — log không sửa lén được.

### Bằng chứng
- Scripts: [scripts/phase3_parse_audit_log.py](scripts/phase3_parse_audit_log.py), [scripts/phase3_collect_proxysql_audit.py](scripts/phase3_collect_proxysql_audit.py).
- Config Acra: `--audit_log_enable=true` → mỗi log line có `integrity=<hash>`.
- Phase 3 check tự động gom cả 3 nguồn nếu có, skip gọn nếu nguồn nào chưa lên.

---

## 11. Idempotent everything

### Điều gì làm
- `make demo-up` — re-run an toàn, skip bước đã có.
- `phase7_5_apply.sh` — re-run thấy "encrypted 0, skipped 1000" thay vì double-encrypt.
- Schema migration — `ALTER COLUMN VARBINARY` no-op nếu đã đúng type; `DROP USER IF EXISTS + CREATE` thay vì REVOKE rồi GRANT.
- HA bootstrap — check cluster đã chạy thì skip.
- Encrypt-in-place — detect AcraStruct prefix `25 25 25` thì skip.

### Vì sao đó không phải tầm thường
Hầu hết demo code chỉ chạy 1 lần. Re-run = fail hoặc corrupt data (double-encrypt, double-grant, ALTER on wrong type, …). Production code phải idempotent vì:
- Deployment retry (Kubernetes restart, CI rerun).
- Disaster recovery (rebuild từ backup).
- Drift correction (config management like Terraform/Ansible).

Project mình **đã thiết kế idempotency từ đầu** — không phải patch sau khi pain. Re-run `make demo-up` 5 lần liên tiếp → vẫn cùng kết quả.

### Bằng chứng
- Test thực tế: chạy `make demo-up` lần 2 trong vòng 10s sau lần 1 → Stage 1 báo "skip generation" (ACRA_MASTER_KEY đã có), Stage 4 báo "encrypted 0, skipped 1000", Stage 5 báo "HA cluster already running".

---

## 12. Documentation as a feature, not afterthought

### Điều gì làm
Project có 6 doc trong root (không kể CLEANUP trong demo/):
- [README.md](README.md) — entry point, phase status, demo flow
- [proposal.md](proposal.md) — academic design, 1027 dòng (bám sát đề bài)
- [problem.md](problem.md) — 11 sự cố đã gặp + root cause + fix
- [data_flow.md](data_flow.md) — 13 sequence diagram per role per scenario
- [future_work.md](future_work.md) — limitation + production roadmap (~530 dòng)
- [shining_point.md](shining_point.md) — file này
- [demo/CLEANUP.md](demo/CLEANUP.md) — cleanup procedure

### Vì sao đó không phải tầm thường
Project học thường có 1 file README ngắn + maybe a slide deck. Project mình **doc theo concern** (design / sequence diagram / problem / roadmap / cleanup) — mỗi audience đọc đúng file mình cần:
- Người chấm muốn nắm tổng quan → README.
- Người chấm muốn check tư duy thiết kế → proposal.
- Người chấm chất vấn "vì sao không X" → future_work + shining_point.
- Người chấm muốn xác minh chi tiết → data_flow.
- Engineer làm continue → problem + CLEANUP.

Đây là **knowledge architecture**, không phải just-write-stuff.

### Bằng chứng
- 7 file MD, total ~3500 dòng.
- Mọi file link cross-reference với nhau (README link tới proposal, proposal link tới future_work, etc.).

---

## 13. CIA Triad mapping cụ thể

### Điều gì làm
Mỗi tầng phòng thủ map vào CIA principles:

| | Confidentiality | Integrity | Availability |
|---|---|---|---|
| **Encryption** | Acra encrypt ssn/cc at rest | Acra audit log với integrity hash chain | — |
| **Access control** | RBAC per-user + view masking | RBAC chống unauthorized modification | — |
| **Application defense** | Stored proc token check (IDOR) | Stored proc validates input | — |
| **Network defense** | — | ProxySQL DBF chặn SQLi | — |
| **Replication** | — | GR synchronous (majority ack before commit) | 3-node tolerate 1 failure |
| **Routing** | — | — | ProxySQL HA-router auto-failover + R/W split |
| **Observability** | — | Tamper-evident audit log | mysqld_exporter + alerts catch degradation early |
| **Discovery** | Find PII rò rỉ + verdict EXPOSED | — | — |

### Vì sao đó không phải tầm thường
"Security" thường được nói chung chung. **CIA triad** là khung phân tích chuẩn — buộc phải nghĩ "phòng thủ này chống mất confidentiality, integrity, hay availability?".

Project mình có defense ở **cả 3 trục** của CIA, không phải chỉ encrypt (C) hay chỉ HA (A). Đây là **defense in depth balanced**.

### Bằng chứng
Mỗi ô trong bảng có file/feature tương ứng đã document ở §1-12 trên.

---

## 14. Một số gotcha kỹ thuật đã giải quyết (engineering log)

Đây không phải bug, mà là **những vấn đề thật sự xảy ra khi implement và phải solve cụ thể**. Có file riêng [problem.md](problem.md) nhưng nêu ngắn 5 cái ấn tượng nhất:

1. **AcraStruct magic là `25 25 25` chứ không phải `22 22 22 22`** — idempotent detection trong `phase7_5_encrypt_users_pii.py`. Initial summary của tôi từ session trước sai → reproduce thấy hex thật là `252525A1…` → fix → idempotent guaranteed.
2. **`REVOKE on freshly CREATEd user` = ER_NONEXISTING_GRANT (1141)** — fix bằng `DROP USER IF EXISTS + CREATE + GRANT` pattern.
3. **WSL2 bind-mount world-writable (0777) → MySQL ignore config files** — fix bằng command-line flag thay vì mount `.cnf`.
4. **mysql-connector prepends query attributes `\x00\x01…` break Acra SQL parser** — fix bằng PyMySQL trên chain, mysql-connector chỉ trên direct path.
5. **`docker stop` ≠ `docker kill` cho GR** — SIGTERM = graceful leave-group message → election ngay. SIGKILL = đợi heartbeat timeout, đôi khi stall. UI dùng stop để demo ổn định.

### Vì sao đó không phải tầm thường
Mỗi cái đều là **một buổi debug 1-2 tiếng** nếu gặp lần đầu. Đã document → người clone về **không phải repeat pain**.

---

## 15. Lưu ý cuối — ăn theo nhau

Các điểm trên **không tách rời** — chúng tăng cường nhau:

- IDOR defense (§3) chỉ work vì có per-user MySQL identity (§5) — nếu app dùng shared account, stored proc không phân biệt được caller nào.
- Discovery (§7) chỉ value vì có per-user grants để verdict EXPOSED (§5).
- HA pulse (§8) chỉ proof được vì R/W split (§9) ép write tới writer hostgroup (FOR UPDATE forces writer routing → confirm node).
- Audit pipeline (§10) chỉ keep attribution nhờ ProxySQL passthrough (§5).
- Single data path (§1) chỉ tốt vì có separation of duties tách key (§2) — không thì tách path để làm gì.

→ Đây là **systems thinking**: design choice không phải isolated, mà reinforce nhau.

---

## Sử dụng file này khi viva

Khi thầy hỏi:
- **"Đặc sản của project là gì?"** → §1 (single path) + §3 (IDOR at DB).
- **"Defense in depth thực sự là gì?"** → §13 (CIA mapping).
- **"Thiết kế có thể dùng production không?"** → §11 (idempotent) + §4 (classification taxonomy) + future_work.md cho gap.
- **"Engineering quyết định khó nhất?"** → §6 (AcraCensor + MySQL Shell pivot).
- **"Gì không trivial trong project này?"** → §7 (discovery → action) + §10 (per-user attribution through proxy).
- **"Visualization có ý nghĩa hay just nice?"** → §8 (HA pulse là evidence-based, không phải UI candy).
- **"Học được gì kỹ thuật cụ thể?"** → §14 (engineering log).

Cặp với [future_work.md](future_work.md) — file kia thừa nhận limitation, file này khẳng định strength. Cả 2 tạo balance: **không khoe, không khiêm tốn quá**.
