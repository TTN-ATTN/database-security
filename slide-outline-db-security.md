# Slide Outline: Bảo Vệ Đồ Án — Database Security
> **Thời lượng:** 10–15 phút | **Số slide:** 11 slide | **Stack:** MySQL 8.4 · ProxySQL · InnoDB Cluster · Prometheus · Grafana

---

## SLIDE 1 — TITLE SLIDE
**Tiêu đề:** Triển Khai Hệ Thống Database Security Đa Lớp Trên Nền Container

**Key Points:**
- Đề tài 2: Tìm Hiểu và Triển Khai Database Security
- Stack: MySQL 8.4 · ProxySQL DBF · InnoDB Cluster HA · Prometheus/Grafana · Python
- Môi trường: Docker Compose (WSL2/Ubuntu) → Kubernetes-ready Architecture

**Visual / Sơ đồ đề xuất:**
> Logo stack: MySQL + ProxySQL + Prometheus + Grafana xếp hàng ngang. Background tối, tone xanh kỹ thuật.



---

## SLIDE 2 — BỐI CẢNH & VẤN ĐỀ
**Tiêu đề:** App Security ≠ Database Security — Khoảng Trống Nguy Hiểm

**Key Points:**
- Tầng ứng dụng bảo vệ **giao tiếp** — tầng database bảo vệ **tài sản thật**
- 6 nhóm rủi ro thực tế:
  - **Insider Threat** — query vượt phạm vi công việc
  - **SQL Injection** — payload độc hại đến thẳng DB
  - **Data Breach** — lộ PII: email, phone, SSN, credit card
  - **Privilege Misuse** — tài khoản app có quyền quá rộng
  - **Operational Risk** — slow query, spike connection, không có alert
  - **Lack of Auditability** — không biết ai truy vấn gì, khi nào

**Visual / Sơ đồ đề xuất:**
> Sơ đồ 2 tầng: **App Layer** (có shield) → **Database Layer** (không có shield, có dấu đỏ). Mũi tên tấn công đi thẳng xuống DB. Ghi chú "Blind Spot" ở tầng DB.

**🎤 Speaker Notes:**
> "Câu hỏi trung tâm của đồ án: nếu đã có WAF, HTTPS và auth ở tầng ứng dụng, tại sao database vẫn là điểm yếu? Lý do là toàn bộ cơ chế bảo vệ phía trên không thể thay thế ba thứ mà DB cần có riêng: giám sát truy vấn độc lập, kiểm soát phân quyền ở cấp dữ liệu và cơ chế phát hiện dữ liệu nhạy cảm. Đây là khoảng trống mà đồ án này lấp đầy."

---

## SLIDE 3 — MỤC TIÊU & HƯỚNG TIẾP CẬN
**Tiêu đề:** Từ Rủi Ro Đến Năng Lực Bảo Mật — Mapping Toàn Diện

**Key Points:**
| Yêu cầu Đề Tài | Giải Pháp Trong Đồ Án |
|---|---|
| Active Monitor | MySQL log + ProxySQL stats |
| Database Firewall | ProxySQL Query Rules (+ Acra evaluation) |
| Data Masking | MySQL View + RBAC (`appuser` vs `root`) |
| Performance Monitoring | mysqld_exporter → Prometheus → Grafana → Alertmanager |
| Sensitive Data Discovery | Python scanner: schema + pattern scan |
| *(Nâng cao)* High Availability | MySQL InnoDB Cluster 3-node + MySQL Router |

- Nguyên tắc: **Baseline ổn định → từng phase → bằng chứng kiểm chứng**
- Acra/AcraCensor: khảo sát đúng topic gốc; ProxySQL là DBF enforcement chính

**Visual / Sơ đồ đề xuất:**
> Bảng mapping 2 cột, mỗi dòng có icon check ✅. Phần HA cluster đánh dấu "⭐ Advanced" nổi bật.

**🎤 Speaker Notes:**
> "Đồ án không chỉ chọn một tool rồi cài xong. Mỗi yêu cầu của đề tài được ánh xạ sang một giải pháp kỹ thuật cụ thể, và mỗi giải pháp đó phải có kịch bản demo và bằng chứng. Điều quan trọng là các tool này không hoạt động độc lập — chúng tạo thành một kiến trúc có mạch logic rõ ràng giữa Data Plane và Observability Plane."

---

## SLIDE 4 — KIẾN TRÚC TỔNG THỂ
**Tiêu đề:** Hai Mặt Phẳng — Data Plane & Observability Plane

**Key Points:**
```
[Client / App / Test Scripts]
        ↓
[ProxySQL DBF — Query Rules / Deny Rules / Stats]
        ↓
[Optional: Acra Security/Evaluation Layer]
        ↓
[MySQL Router — HA Entry Point]
        ↓
[MySQL InnoDB Cluster: Primary + 2 Secondary]
        |
        ├──→ mysqld_exporter → Prometheus → Grafana
        |                           ↓
        |                      Alertmanager
        ├──→ Logs / Audit Trail
        └──→ Python: Sensitive Data Discovery Scripts
```
- **Data Plane**: Client → ProxySQL → (Acra) → MySQL Router → Cluster
- **Observability Plane**: metrics, log, alert, scan — độc lập, không chặn traffic chính
- Multi-container = Single Responsibility per service

**Visual / Sơ đồ đề xuất:**
> Sơ đồ kiến trúc hệ thống có màu sắc phân tầng: Data Plane (màu xanh dương) bên trái dọc xuống, Observability Plane (màu cam/vàng) bên phải. Kết nối bằng mũi tên có nhãn.

**🎤 Speaker Notes:**
> "Đây là slide quan trọng nhất về mặt kiến trúc. Tư duy thiết kế ở đây là tách rõ hai mặt phẳng: Data Plane là nơi câu lệnh SQL đi qua và có thể bị enforce policy; Observability Plane là nơi thu thập bằng chứng, metrics và alert. Tách như vậy đảm bảo monitoring stack không gây latency cho giao dịch chính, và mỗi component có một trách nhiệm duy nhất — đây là nền tảng tự nhiên để scale lên Kubernetes sau này."

---

## SLIDE 5 — NĂNG LỰC 1: DATABASE FIREWALL
**Tiêu đề:** ProxySQL DBF — Policy Enforcement Trước Khi Vào Database

**Key Points:**
- ProxySQL hiểu **MySQL protocol** — intercept ở L7, không phải L3/L4
- Query Rules engine: match → action (DENY / REWRITE / REDIRECT)
- Rule demo kiểm chứng được:
  - ❌ Block `DROP TABLE`, `TRUNCATE TABLE`
  - ❌ Block `SELECT * FROM users` (mass data dump)
  - ❌ Block SQL Injection: `' OR '1'='1`
  - ✅ Allow SELECT có WHERE clause cụ thể
- ProxySQL stats/logs = **audit trail tích hợp**
- Acra/AcraCensor: thử nghiệm theo topic gốc → ghi nhận limitation với MySQL 8.4

**Visual / Sơ đồ đề xuất:**
> Trái: screenshot terminal "Query: DROP TABLE users" → "ERROR 1148: Command not allowed". Phải: ProxySQL stats table hiển thị `rule_hits`, `query_count`, `blocked_queries`.

**🎤 Speaker Notes:**
> "ProxySQL đóng vai trò enforcement chính vì nó hiểu MySQL wire protocol — tức là nó intercept truy vấn ở tầng ứng dụng, trước khi bytes SQL đến được storage engine. Rule engine của ProxySQL hoạt động theo cơ chế pattern match và action, tương tự WAF nhưng dành riêng cho SQL. Đồ án cũng thử nghiệm AcraCensor theo đúng chủ đề gốc; nếu parser của Acra không ổn định với MySQL 8.4, đây là một kết quả kỹ thuật có giá trị — không phải failure mà là finding."

---

## SLIDE 6 — NĂNG LỰC 2: DATA MASKING & ACTIVE MONITOR
**Tiêu đề:** Dữ Liệu Đúng Người — Masking + Audit Không Thể Tắt

**Key Points:**
**Data Masking (View + RBAC):**
- `root` → bảng gốc `users` → raw PII
- `appuser` → view `users_masked` → dữ liệu che:
  - `n***@domain.com` | `*** *** **89` | `**** **** **** 1234`
- `appuser` SELECT trực tiếp base table → **ACCESS DENIED**

**Active Monitor:**
- MySQL general log / slow log (bật theo phase)
- ProxySQL query log: `user`, `timestamp`, `query_digest`, `duration`
- Optional: Acra audit log (evaluation path)
- Output: **ai truy vấn gì, khi nào, qua đường nào**

**Visual / Sơ đồ đề xuất:**
> Bảng so sánh 2 cột: cột trái "root SELECT users" → bảng có full PII; cột phải "appuser SELECT users_masked" → bảng có dữ liệu che. Bên dưới: snippet log ProxySQL có `user=appuser`, `query_digest=SELECT...`, `timestamp`.

**🎤 Speaker Notes:**
> "Masking ở đây được thực hiện theo nguyên tắc kinh điển trong access control: không deny quyền đọc mà deny quyền thấy. appuser vẫn có thể query bình thường, nhưng view trả về dữ liệu đã được transform theo policy. Kết hợp với Active Monitor, hệ thống có thể trả lời câu hỏi kiểm toán quan trọng nhất: ai đã đọc dữ liệu gì, từ source nào, vào lúc mấy giờ — đây là yêu cầu tối thiểu của bất kỳ framework compliance nào."

---

## SLIDE 7 — NĂNG LỰC 3: PERFORMANCE MONITORING & ALERTING
**Tiêu đề:** Observability Stack — Từ Metric Đến Alert Trong Vòng Giây

**Key Points:**
- Pipeline: `mysqld_exporter` → `Prometheus` → `Grafana` → `Alertmanager`
- Metrics quan trọng:
  - `mysql_up` (0/1) — DB còn sống không?
  - `mysql_global_status_threads_connected` — connection spike
  - `mysql_global_status_slow_queries` — slow query
  - `mysql_global_status_questions` — QPS
  - `mysql_exporter_scrape_duration_seconds` — exporter health
- Kịch bản kích hoạt:
  - `stress_connections.py` → connection spike → alert trigger
  - `generate_load.py` → slow query → Grafana panel thay đổi real-time
  - Stop container → `mysql_up = 0` → Alertmanager fire

**Visual / Sơ đồ đề xuất:**
> Screenshot Grafana dashboard thực tế: panel "Threads Connected" có đường tăng vọt đúng lúc chạy stress script. Góc trên phải: badge FIRING đỏ từ Alertmanager.

**🎤 Speaker Notes:**
> "Monitoring stack này không phải add-on — nó là một phần cốt lõi của kiến trúc bảo mật. Trong security context, performance anomaly thường là dấu hiệu đầu tiên của một cuộc tấn công: connection spike có thể là brute force, slow query đột ngột có thể là data exfiltration qua cartesian join. Alertmanager cho phép rule-based routing: khi DB down, cảnh báo ngay lập tức, không cần ai ngồi nhìn dashboard."

---

## SLIDE 8 — NĂNG LỰC 4: SENSITIVE DATA DISCOVERY
**Tiêu đề:** Tìm Dữ Liệu Nhạy Cảm Trước Khi Attacker Tìm Thấy

**Key Points:**
- **Phương pháp dual-scan:**
  - Schema scan: query `INFORMATION_SCHEMA` → tìm tên cột chứa `email`, `phone`, `ssn`, `card`, `password`, `token`
  - Pattern scan: sample rows → regex detect PII trong free-text (`activity_logs.notes`)
- **Output:** JSON/CSV report → `table`, `column`, `pattern_matched`, `sample_count`
- **Cross-check RBAC:**
  - `PROTECTED` — appuser chỉ thấy qua masked view ✅
  - `EXPOSED` — appuser đọc được raw từ base table ❌ → gap cần xử lý
- Remediation suggestion: MASK / RESTRICT / ENCRYPT / REMOVE

**Visual / Sơ đồ đề xuất:**
> Terminal output: JSON report 2 dòng — một dòng `"status": "PROTECTED"` màu xanh, một dòng `"status": "EXPOSED"` màu đỏ với `table: activity_logs, column: notes`. Mũi tên chỉ sang box "Remediation: Apply RBAC + View Masking".

**🎤 Speaker Notes:**
> "Sensitive Data Discovery giải quyết một vấn đề thực tế: trong các hệ thống lớn, DBA không thể biết hết mọi cột nào đang chứa PII, đặc biệt là các cột free-text như notes hay description. Script Python của đồ án scan theo hai chiều: chiều schema và chiều dữ liệu. Kết quả quan trọng nhất là cross-check — phát hiện ra rằng activity_logs.notes chứa PII nhưng appuser vẫn đọc được raw — đây chính xác là loại gap mà audit compliance yêu cầu phải đóng."

---

## SLIDE 9 — ĐIỂM NHẤN NÂNG CAO: HIGH AVAILABILITY CLUSTER
**Tiêu đề:** MySQL InnoDB Cluster — Loại Bỏ Single Point of Failure Ở Tầng DB

**Key Points:**
- **Kiến trúc:** 3 MySQL nodes (1 Primary + 2 Secondary) + MySQL Router
- **Cơ chế:** Group Replication — consensus-based, auto-failover
- **Kịch bản kiểm thử failover (7 bước):**
  1. Cluster healthy → ghi dữ liệu qua Router
  2. Xác nhận replication sang Secondary
  3. `docker stop mysql-primary`
  4. Cluster bầu Primary mới (consensus ≥ 2/3 nodes)
  5. Client query qua Router → **không bị gián đoạn**
  6. Khởi động lại node cũ → auto rejoin cluster
  7. Cluster trở lại trạng thái 3-node healthy
- **Bằng chứng:** `cluster.status()` output trước/sau + Grafana node-down alert

**Visual / Sơ đồ đề xuất:**
> Sơ đồ trước/sau song song: Trái "Before: mysql-1=PRIMARY, mysql-2=SECONDARY, mysql-3=SECONDARY". Phải "After: mysql-1=OFFLINE, mysql-2=PRIMARY⭐, mysql-3=SECONDARY". Giữa: mũi tên với nhãn "docker stop mysql-1". MySQL Router hiển thị ở trên cùng, kết nối liên tục.

**🎤 Speaker Notes:**
> "Đây là phần nâng cao của đồ án và cũng là điểm kỹ thuật đáng chú ý nhất. InnoDB Cluster không chỉ là replication đơn thuần — nó dùng Paxos-based consensus, nghĩa là cluster tự quyết định primary mới khi quorum đủ, không cần DBA can thiệp. MySQL Router là thành phần then chốt ở đây: nó abstract hóa topology của cluster ra khỏi client — client luôn connect vào một endpoint cố định, Router tự biết chuyển hướng đến Primary hiện tại. Đây là mô hình availability được dùng trong production thực tế."

---

## SLIDE 10 — KỊCH BẢN DEMO THỰC TẾ
**Tiêu đề:** Demo Live — 6 Kịch Bản, 6 Bằng Chứng

**Key Points:**
| # | Kịch Bản | Công Cụ | Kết Quả Quan Sát |
|---|---|---|---|
| 1 | DBF chặn `DROP TABLE` | ProxySQL + terminal | ERROR + rule_hits log |
| 2 | DBF chặn SQL Injection | `test_sqli.py` | Deny response + stats |
| 3 | Masking: root vs appuser | MySQL CLI | Raw PII vs Masked |
| 4 | Active Monitor log query | ProxySQL query log | User + time + digest |
| 5 | Performance: connection spike | `stress_connections.py` + Grafana | Dashboard spike + ALERT FIRING |
| 6 | HA Failover | `test_failover.py` + `cluster.status()` | Primary thay đổi, query không ngắt |
| *(Extra)* | Sensitive Discovery report | `scan_data_patterns.py` | JSON: EXPOSED vs PROTECTED |

**Visual / Sơ đồ đề xuất:**
> Bảng 6 hàng, mỗi hàng có icon tương ứng: 🔥(DBF), 💉(SQLi), 🎭(Masking), 👁(Monitor), 📊(Perf), 🔄(HA). Tô màu xen kẽ cho dễ đọc.

**🎤 Speaker Notes:**
> "Mỗi kịch bản demo đều có script tự động hóa — không thực hiện bằng tay mà chạy bằng Python scripts để kết quả tái tạo được và nhất quán. Điều này quan trọng vì trong môi trường thực nghiệm, reproducibility chính là tiêu chí đánh giá độ tin cậy của bằng chứng kỹ thuật. Hội đồng có thể yêu cầu chạy lại bất kỳ kịch bản nào trong số này."

---

## SLIDE 11 — KẾT LUẬN & HƯỚNG MỞ RỘNG
**Tiêu đề:** Từ Thực Nghiệm Đến Kiến Trúc Production-Ready

**Key Points:**
**Đã đạt được:**
- ✅ 5 nhóm năng lực DB Security có kịch bản + bằng chứng
- ✅ Kiến trúc Data Plane / Observability Plane rõ ràng
- ✅ InnoDB Cluster 3-node HA với failover test
- ✅ Multi-container → Kubernetes-ready design
- ✅ Môi trường tái tạo hoàn toàn: `docker compose up`

**Giới hạn thành thật:**
- Môi trường single-site (không phải multi-region DR)
- Acra/AcraCensor: limitation với MySQL 8.4 được ghi nhận như technical finding
- Chưa đạt compliance đầy đủ PCI-DSS/HIPAA/GDPR

**Hướng mở rộng:**
- **Kubernetes:** StatefulSet MySQL + PVC + Liveness/Readiness Probe
- **Cloud Deployment:** DigitalOcean VPS + cloud firewall + SSH hardening
- **Acra Encryption:** transparent column encryption khi Acra ổn định hơn
- **Multi-region HA:** MySQL async replication cross-datacenter
- **Compliance Layer:** audit log theo chuẩn PCI-DSS Row 10

**Visual / Sơ đồ đề xuất:**
> Trái: checklist "Completed" 5 items màu xanh. Phải: roadmap mũi tên lên cao "Local Docker → Kubernetes → Cloud Multi-region". Tone màu: blue/green gradient.

**🎤 Speaker Notes:**
> "Để tổng kết: đồ án này không chỉ là một tập công cụ bảo mật được cài cạnh nhau — đó là một kiến trúc có tư duy về separation of concerns, về observability, và về đường nâng cấp lên production. Mỗi thành phần đều có lý do tồn tại trong thiết kế tổng thể. Những giới hạn được ghi nhận không phải là điểm yếu mà là minh chứng cho sự hiểu biết về khoảng cách giữa demo kỹ thuật và hệ thống thực tế. Em sẵn sàng nhận câu hỏi từ hội đồng."

---

## PHỤ LỤC — GỢI Ý THIẾT KẾ VISUAL

### Bảng màu đề xuất
| Yếu tố | Màu |
|---|---|
| Data Plane | `#1E3A5F` (Navy Blue) |
| Observability Plane | `#E67E22` (Amber) |
| Blocked / Threat | `#E74C3C` (Red) |
| Protected / OK | `#27AE60` (Green) |
| Neutral / Text | `#2C3E50` (Dark Gray) |
| Background slide | `#F8F9FA` hoặc `#0D1117` (dark mode) |

### Font đề xuất
- Tiêu đề: **Inter Bold** hoặc **Roboto Bold** — 32–40pt
- Body: **Inter Regular** — 18–22pt
- Code/Log: **JetBrains Mono** — 14–16pt

### Công cụ làm slide
- **PowerPoint / Google Slides** — dùng template kỹ thuật tối màu
- **Marp** (Markdown → Slides) — phù hợp nếu muốn dùng ngay file .md này
- **Canva (Dark Tech template)** — nhanh và đẹp nếu ưu tiên thẩm mỹ

---

## PHỤ LỤC — TIMELINE THUYẾT TRÌNH

| Thời Gian | Slide | Nội Dung |
|---|---|---|
| 0:00 – 0:30 | Slide 1 | Title, giới thiệu nhanh |
| 0:30 – 1:30 | Slide 2 | Bối cảnh & vấn đề |
| 1:30 – 2:30 | Slide 3 | Mục tiêu & mapping |
| 2:30 – 4:00 | Slide 4 | Kiến trúc tổng thể (**điểm nhấn**) |
| 4:00 – 5:30 | Slide 5–6 | DBF + Masking + Active Monitor |
| 5:30 – 6:30 | Slide 7 | Performance Monitoring |
| 6:30 – 7:30 | Slide 8 | Sensitive Data Discovery |
| 7:30 – 9:30 | Slide 9 | HA Cluster (**điểm nhấn**) |
| 9:30 – 11:00 | Slide 10 | Demo plan |
| 11:00 – 12:00 | Slide 11 | Kết luận & Q&A mở đầu |
