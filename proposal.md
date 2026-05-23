     # Đồ Án Môn Học - Proposal
# Đề Tài 2: Tìm Hiểu và Triển Khai Database Security

## 1. Tổng Quan Đề Tài

### 1.1 Bối Cảnh

Bảo mật cơ sở dữ liệu (Database Security) là tập hợp các cơ chế kỹ thuật và quy trình vận hành nhằm bảo vệ dữ liệu khỏi truy cập trái phép, rò rỉ thông tin, SQL Injection, lạm dụng đặc quyền, mất khả năng quan sát và các rủi ro hiệu năng. Trong thực tế, dữ liệu quan trọng thường nằm ở tầng database, nhưng nhiều hệ thống chỉ tập trung bảo mật ở tầng ứng dụng, khiến database thiếu cơ chế giám sát, phân quyền, masking và cảnh báo độc lập.

Đồ án này xây dựng một môi trường thực nghiệm có thể tái tạo bằng container để nghiên cứu và mô phỏng các năng lực chính của Database Security:

- Active Monitor.
- Database Firewall (DBF).
- Data Masking.
- Performance Monitoring.
- Sensitive Data Discovery.

### 1.2 Vấn Đề Đặt Ra

Một hệ thống cơ sở dữ liệu thông thường có thể gặp các rủi ro sau:

- **Insider Threat**: người dùng nội bộ truy vấn dữ liệu vượt quá phạm vi công việc.
- **SQL Injection**: input độc hại tạo ra câu lệnh SQL nguy hiểm.
- **Data Breach**: lộ dữ liệu nhạy cảm như email, số điện thoại, địa chỉ, số thẻ, SSN.
- **Privilege Misuse**: tài khoản ứng dụng bị dùng sai mục đích hoặc có quyền quá rộng.
- **Operational Risk**: slow query, quá nhiều kết nối, thiếu index, service down nhưng không có cảnh báo.
- **Lack of Auditability**: thiếu log đủ rõ để biết ai truy vấn gì, khi nào, qua đường nào.

### 1.3 Hướng Tiếp Cận

Đề tài có nhắc đến các công cụ như DataSunrise, DBHawk và Acra. Trong đồ án này:

- **DataSunrise và DBHawk** được dùng làm đối tượng tìm hiểu, đối chiếu tính năng và rút ra mô hình kiến trúc Database Security thường gặp.
- **Acra** được giữ trong đồ án như một database security stack open-source để khảo sát và thử nghiệm các hướng audit/encryption/masking/IDS/DBF.
- **ProxySQL** được dùng làm lớp DBF enforcement chính nếu AcraCensor không ổn định với MySQL 8.4, vì ProxySQL là database proxy hỗ trợ MySQL protocol và query rules.
- **MySQL + ProxySQL + Prometheus + Grafana + Alertmanager + Python scripts** tạo thành stack thực nghiệm để demo đầy đủ các nhóm tính năng.

Nguyên tắc thực hiện:

- Dựng baseline ổn định trước, sau đó mới thêm lớp DBF và Acra evaluation khi cần.
- Mỗi tính năng phải có kịch bản giả lập và bằng chứng kiểm chứng.
- Không đặt mục tiêu production-grade, nhưng kiến trúc phải có đường mở rộng lên multi-container, Kubernetes, availability và scalability.

---

## 2. Mục Tiêu

### 2.1 Mục Tiêu Học Thuật

- Hiểu các nhóm tính năng chính trong Database Security.
- Hiểu vị trí của Database Firewall, audit log, masking, monitoring và discovery trong một kiến trúc bảo mật dữ liệu.
- So sánh định hướng của các công cụ DataSunrise, DBHawk, Acra và stack open-source.
- Nhận biết giới hạn giữa demo kỹ thuật, staging và production deployment.

### 2.2 Mục Tiêu Thực Hành

- Dựng môi trường thực nghiệm của đồ án bằng Docker Compose.
- Tạo database mẫu chứa dữ liệu nhạy cảm giả lập.
- Mô phỏng truy vấn hợp lệ, truy vấn nguy hiểm và truy vấn gây tải.
- Demo masking bằng view/RBAC và optional bằng Acra layer nếu phù hợp.
- Thu thập metrics, log, alert, screenshot và output script làm bằng chứng.
- Viết báo cáo cuối kỳ kèm nhận xét về kiến trúc, rủi ro và hướng mở rộng.

### 2.3 Mục Tiêu Nâng Cao

- Thiết kế kiến trúc multi-container có thể chuyển sang Kubernetes.
- Mô tả availability: healthcheck, restart policy, liveness/readiness probe, persistent storage.
- Thiết kế và triển khai **High Availability database cluster hoàn chỉnh** ở mức đồ án bằng MySQL InnoDB Cluster/Group Replication.
- Mô tả scalability: scale ProxySQL/Acra layers, tách monitoring, load balancing, giới hạn scale của database.
- Hỗ trợ triển khai môi trường đồ án trên WSL2 thay cho VM truyền thống nếu máy cá nhân dùng Windows.
- Optional: triển khai một phần stack trên DigitalOcean VPS/cloud VM hoặc Kubernetes local/minikube/kind nếu thời gian cho phép.

---

## 3. Mapping Yêu Cầu Đề Tài Sang Thiết Kế

| Yêu cầu đề tài | Thiết kế trong đồ án | Bằng chứng demo dự kiến |
|---|---|---|
| Active Monitor | MySQL log, ProxySQL stats/logs, optional Acra audit log, truy vấn test có timestamp/user/source | Log query, screenshot terminal/Grafana |
| Database Firewall (DBF) | ProxySQL query rules làm DBF chính; AcraCensor được khảo sát/thử nghiệm và ghi nhận limitation nếu không ổn định | Query `DROP`, `TRUNCATE`, injection pattern bị deny |
| Data Masking | MySQL view `users_masked` + RBAC; optional Acra encryption/masking | Root thấy raw data, `appuser` chỉ thấy masked data |
| Performance Monitoring | mysqld_exporter + Prometheus + Grafana + Alertmanager | Dashboard connection/QPS/slow query, alert khi vượt ngưỡng |
| Sensitive Data Discovery | Python schema scan + pattern scan trong free-text | JSON/CSV phát hiện cột/giá trị chứa PII |
| High Availability database cluster | MySQL InnoDB Cluster/Group Replication 3 node + MySQL Router | Kill primary node, cluster tự bầu primary mới, client kết nối lại qua router |
| Advanced container/cloud | WSL2/local environment, Docker Compose hardening, DigitalOcean VPS optional, Kubernetes extension design | Sơ đồ K8s/cloud, manifest/notes optional, healthcheck/probe demo |

---

## 4. Phạm Vi Thực Hiện

### 4.1 Trong Phạm Vi

- Dùng **MySQL 8.4** làm target database.
- Dùng dữ liệu giả lập có PII trong các bảng `users`, `orders`, `activity_logs`.
- Dùng **view + RBAC** làm baseline cho data masking.
- Dùng **mysqld_exporter + Prometheus + Grafana + Alertmanager** cho performance monitoring và alert.
- Dùng script Python để seed dữ liệu, tạo tải, test query và scan dữ liệu nhạy cảm.
- Tích hợp **ProxySQL** trong phase DBF để minh họa query filtering/deny rules ở mức đồ án.
- Khảo sát và thử nghiệm **Acra/AcraCensor** như một database security stack đúng với topic gốc; nếu AcraCensor không ổn định, ghi nhận limitation và dùng ProxySQL làm fallback DBF chính.
- Triển khai **High Availability database cluster hoàn chỉnh** ở phần advanced, gồm 3 MySQL nodes, MySQL Router, replication health check và failover test.
- Cho phép triển khai môi trường local trên Ubuntu VM, WSL2 Ubuntu hoặc Linux host.
- Optional: triển khai baseline hoặc monitoring stack trên DigitalOcean VPS để minh họa cloud deployment.
- Thiết kế kiến trúc có khả năng mở rộng sang Kubernetes, nhưng không bắt buộc production deployment.

### 4.2 Ngoài Phạm Vi

- Production deployment thật.
- So sánh chuyên sâu nhiều DBMS.
- AD/LDAP/SSO.
- Pentest nâng cao hoặc bypass firewall chuyên sâu.
- Multi-region disaster recovery hoặc HA ở nhiều datacenter.
- Compliance audit theo chuẩn PCI-DSS/HIPAA/GDPR ở mức đầy đủ.

### 4.3 Nguyên Tắc Fallback

- Nếu AcraCensor không parse được query hoặc rule firewall của Acra không ổn định, chuyển DBF enforcement sang ProxySQL query rules và giữ Acra ở vai trò khảo sát/đánh giá limitation.
- Nếu rule DBF phức tạp, thu hẹp rule về các mẫu dễ kiểm chứng như `DROP`, `TRUNCATE`, `SELECT * FROM users`, SQL injection cơ bản.
- Nếu dynamic masking/encryption của Acra tốn thời gian, dùng MySQL view + RBAC làm bằng chứng chính, Acra encryption ghi là hướng mở rộng.
- Nếu InnoDB Cluster khó tự động hóa hoàn toàn, vẫn giữ kiến trúc đầy đủ và demo theo từng bước: bootstrap cluster, kiểm tra replication, dừng primary, xác nhận failover qua MySQL Router.
- Nếu WSL2 gặp vấn đề systemd/network/Docker, chuyển sang Docker Desktop WSL integration hoặc Ubuntu VM.
- Nếu DigitalOcean VPS/cloud/Kubernetes quá tải so với thời gian, giữ ở mức thiết kế kiến trúc và optional demo bằng minikube/kind.
- Nếu GUI không thuận tiện, dùng CLI hoặc script để demo.

---

## 5. Kiến Trúc Tổng Thể

### 5.1 Tư Duy Kiến Trúc

Kiến trúc đồ án được tách thành hai mặt phẳng:

- **Data Plane**: luồng truy vấn từ client/app đi qua lớp DBF và lớp security/evaluation tùy phase trước khi đến database.
- **Control/Observability Plane**: luồng metrics, log, alert, scan và bằng chứng audit.

Cách tách này giúp đồ án không chỉ là một tập container chạy cạnh nhau, mà thể hiện rõ nơi enforce policy, nơi lưu dữ liệu, nơi quan sát và nơi sinh bằng chứng bảo mật.

### 5.2 Sơ Đồ High-Level

```text
User / Admin / Test Scripts
          |
          v
ProxySQL DBF
(Query Rules / Deny Rules / Stats)
          |
          v
Optional Acra Security/Evaluation Layer
(Audit / Encryption / Masking / IDS / AcraCensor Attempt)
          |
          v
MySQL Router / HA Entry Point
          |
          v
MySQL InnoDB Cluster
(Primary + 2 Secondary Nodes)
          |
          +--> mysqld_exporter --> Prometheus --> Grafana
          |                              |
          |                              v
          |                         Alertmanager
          |
          +--> Logs / Audit Trail
          |
          +--> Sensitive Data Discovery Scripts
```

### 5.3 Data Plane

Data Plane mô tả đường đi của truy vấn:

1. Người dùng, ứng dụng hoặc script gửi SQL query.
2. Query đi qua ProxySQL ở phase DBF.
3. ProxySQL kiểm tra query rules, block query nguy hiểm và ghi stats/logs.
4. Query hợp lệ có thể đi tiếp qua Acra security/evaluation layer.
5. Acra được dùng để khảo sát audit/encryption/masking/IDS và ghi nhận limitation của AcraCensor nếu có.
6. Query hợp lệ được chuyển tiếp đến MySQL Router.
7. MySQL Router định tuyến query đến primary node hiện tại trong cluster.
8. MySQL trả kết quả về client; khi primary lỗi, cluster bầu primary mới và router chuyển hướng traffic.

Ở phase baseline, client có thể truy cập MySQL trực tiếp để đảm bảo môi trường chạy ổn định. Ở phase DBF/security, client sẽ truy cập qua ProxySQL và optional Acra layer để chứng minh deny/allow, audit và các giới hạn kỹ thuật.

### 5.4 Control và Observability Plane

Control/Observability Plane gồm các thành phần không trực tiếp xử lý giao dịch chính, nhưng phục vụ giám sát, phân tích và bằng chứng:

- `mysqld_exporter` thu thập metrics từ MySQL.
- Prometheus scrape metrics theo chu kỳ.
- Grafana hiển thị dashboard.
- Alertmanager nhận alert từ Prometheus.
- Python scripts tạo dữ liệu, tạo tải, test injection, scan schema và scan pattern.
- ProxySQL stats/logs và optional Acra audit trail dùng để chứng minh Active Monitor và DBF.

### 5.5 Kiến Trúc Multi-Container

Mỗi thành phần chạy trong container riêng:

| Container | Vai trò | Lý do tách riêng |
|---|---|---|
| MySQL node 1/2/3 | Lưu dữ liệu chính trong HA cluster | Stateful, cần volume riêng cho từng node |
| MySQL Router | Entry point cho database cluster | Giúp client không phụ thuộc trực tiếp vào một DB node |
| ProxySQL | DBF enforcement bằng query rules | Hiểu MySQL protocol, có thể block query trước khi vào DB |
| Acra evaluation layer | Security/evaluation layer: audit, encryption, masking, IDS, AcraCensor attempt | Giữ đúng topic gốc và ghi nhận limitation nếu AcraCensor không ổn định |
| mysqld_exporter | Xuất metrics MySQL | Tách quyền đọc metrics khỏi app |
| Prometheus | Thu thập metrics | Control plane độc lập |
| Grafana | Dashboard | UI quan sát riêng |
| Alertmanager | Điều phối cảnh báo | Tách alert routing khỏi metrics |
| Python scripts | Seed/test/scan/load | Automation, không chạy thường trực |

Thiết kế multi-container là bước trung gian hợp lý trước khi chuyển sang Kubernetes, vì mỗi service đã có trách nhiệm rõ ràng, network riêng và cấu hình riêng.

---

## 6. Kiến Trúc Theo Giai Đoạn

### 6.1 Phase 1 - Baseline Docker Compose

```text
Client / Python Scripts
          |
          v
MySQL 8.4
          |
          +--> mysqld_exporter --> Prometheus --> Grafana
                                      |
                                      v
                                 Alertmanager
```

Mục tiêu:

- Chạy ổn định MySQL và monitoring stack.
- Kiểm tra container healthcheck, volume và network.
- Xác nhận Prometheus scrape được MySQL metrics.
- Xác nhận Grafana truy cập được và có datasource Prometheus.

### 6.2 Phase 2 - Schema, Seed Data, Masking Baseline

```text
Root/Admin Client --> MySQL raw tables
App User          --> MySQL masked views
```

Mục tiêu:

- Tạo bảng `users`, `orders`, `activity_logs`.
- Seed dữ liệu giả lập có PII.
- Tạo view `users_masked`.
- Cấp quyền để `appuser` chỉ đọc dữ liệu đã mask.
- Chứng minh phân quyền bằng output query.

### 6.3 Phase 3 - Active Monitor

```text
MySQL / ProxySQL / Acra Logs --> Evidence
Test Queries                 --> Audit Trail
```

Mục tiêu:

- Bật nguồn log cần thiết ở MySQL, ProxySQL và/hoặc Acra evaluation path.
- Tạo truy vấn bất thường để audit.
- Ghi nhận user, thời điểm và nội dung query.
- Thu thập log/screenshot làm bằng chứng Active Monitor.

### 6.4 Phase 4 - Database Firewall / ProxySQL + Acra Evaluation

```text
Client / App
     |
     v
ProxySQL DBF
     |
     v
Optional Acra Security/Evaluation Layer
     |
     v
MySQL
```

Mục tiêu:

- Đưa query đi qua ProxySQL trước khi vào database.
- Áp dụng rule deny/allow đơn giản bằng ProxySQL query rules.
- Demo query hợp lệ được allow và query nguy hiểm bị block.
- Thử nghiệm Acra/AcraCensor theo đúng topic gốc, ghi lại limitation nếu AcraCensor không parse được query ổn định.
- Nếu Acra gây bất ổn runtime, tách thành evaluation path riêng thay vì đặt trên main demo path.

### 6.5 Phase 5 - Performance Monitoring

```text
MySQL Metrics --> Prometheus --> Grafana --> Alertmanager
```

Mục tiêu:

- Tạo load/slow query để quan sát metrics.
- Theo dõi connection, throughput, slow query và target health.
- Tạo alert cơ bản khi service down, connection tăng hoặc exporter mất scrape.

### 6.6 Phase 6 - Sensitive Data Discovery

```text
Python Scanner --> INFORMATION_SCHEMA
Python Scanner --> Sample rows / free-text columns
```

Mục tiêu:

- Scan tên bảng/cột có khả năng chứa PII.
- Scan pattern như email, phone, credit card, SSN trong dữ liệu.
- Xuất kết quả JSON/CSV.
- Đề xuất remediation: mask, remove, encrypt, restrict access.

### 6.7 Phase 7 - High Availability Database Cluster

```text
Client / ProxySQL / Optional Acra Layer
          |
          v
MySQL Router
          |
          v
MySQL InnoDB Cluster
  ├── mysql-1: Primary
  ├── mysql-2: Secondary
  └── mysql-3: Secondary
```

Mục tiêu:

- Triển khai cluster gồm 3 MySQL nodes để tránh single point of failure ở tầng database.
- Dùng MySQL Group Replication/InnoDB Cluster để đồng bộ dữ liệu và tự động bầu primary mới khi node chính lỗi.
- Dùng MySQL Router làm endpoint ổn định cho client, ProxySQL và optional Acra layer.
- Kiểm tra cluster status, replication health và vai trò từng node.
- Demo failover bằng cách dừng primary node, xác nhận primary mới được bầu và client vẫn truy cập qua router.
- Ghi lại giới hạn của đồ án: chưa triển khai multi-region DR, backup automation production-grade hoặc chaos testing nâng cao.

### 6.8 Phase 8 - Advanced Kubernetes / Cloud Extension

```text
Local WSL2 / Ubuntu VM / DigitalOcean VPS
          |
          v
Docker Compose Baseline
```

```text
Kubernetes Ingress / Port-forward
          |
          v
Service: ProxySQL DBF
          |
          v
Optional Service: Acra Evaluation Layer
          |
          v
Service: MySQL Router
          |
          v
StatefulSet: MySQL InnoDB Cluster
          |
          +--> Service: mysqld_exporter
          +--> Prometheus / Grafana / Alertmanager
```

Mục tiêu:

- Cho phép dùng WSL2 Ubuntu thay VM truyền thống cho môi trường local.
- Dùng DigitalOcean VPS như môi trường cloud optional để demo deploy từ xa, firewall rule, SSH access và monitoring endpoint.
- Không nhất thiết triển khai production K8s đầy đủ.
- Mô tả cách chuyển từ Docker Compose sang Kubernetes.
- Ánh xạ HA cluster sang StatefulSet, PersistentVolumeClaim, Secret, ConfigMap và Service.
- Nếu đủ thời gian, demo tối thiểu bằng kind/minikube hoặc DigitalOcean VPS.

---

## 7. Kubernetes, Availability và Scalability

### 7.1 Kubernetes Extension Design

Khi chuyển sang Kubernetes, các thành phần có thể được ánh xạ như sau:

| Thành phần Compose | Thành phần Kubernetes đề xuất |
|---|---|
| MySQL InnoDB Cluster nodes | StatefulSet + PersistentVolumeClaim |
| MySQL Router | Deployment + Service |
| ProxySQL | Deployment + Service |
| Acra evaluation layer | Deployment + Service |
| Prometheus | Deployment hoặc Helm chart |
| Grafana | Deployment + PersistentVolumeClaim |
| Alertmanager | Deployment hoặc Prometheus stack |
| Config files | ConfigMap |
| Password/secret | Secret |
| Internal network | ClusterIP Services |
| UI access | Port-forward hoặc Ingress |

### 7.2 Availability

Availability trong phạm vi đồ án được thiết kế theo nhiều mức:

- **Docker Compose**: dùng `restart: unless-stopped`, healthcheck, named volume cho dữ liệu.
- **Database cluster**: dùng 3 MySQL nodes, Group Replication/InnoDB Cluster và MySQL Router để giảm rủi ro single point of failure.
- **Monitoring**: Prometheus phát hiện target down, Grafana hiển thị trạng thái, Alertmanager nhận rule cảnh báo.
- **Kubernetes extension**: dùng liveness probe, readiness probe, restart policy, PersistentVolume và rolling update cho service stateless.
- **Giới hạn đồ án**: tập trung HA trong một môi trường single-site; multi-region DR và backup policy production-grade không thuộc trọng tâm.

### 7.3 Scalability

Scalability được chia theo loại service:

- **Acra/security evaluation layer**: có thể scale ngang nếu cấu hình stateless hoặc dùng shared config/secret.
- **ProxySQL**: có thể chạy nhiều replica nếu cấu hình đồng bộ và client có endpoint/load balancer phía trước.
- **MySQL Router**: có thể chạy nhiều replica phía trước cluster để tăng availability cho endpoint kết nối.
- **Monitoring UI**: Grafana/Prometheus có thể tách khỏi database node, nhưng Prometheus scale nâng cao không thuộc trọng tâm.
- **Python scripts**: chạy theo job/on-demand, không ảnh hưởng service chính.
- **MySQL**: dùng InnoDB Cluster để tăng availability; read scaling có thể khai thác secondary/read-only endpoint, nhưng write scaling vẫn bị giới hạn bởi mô hình single-primary.

### 7.4 Vì Sao Multi-Container Quan Trọng

Multi-container giúp:

- Tách trách nhiệm của database, firewall/proxy, monitoring, alerting và automation.
- Dễ bật/tắt từng phase khi demo.
- Giảm rủi ro một service lỗi làm hỏng toàn bộ hệ thống thực nghiệm.
- Tạo nền tảng tự nhiên để chuyển sang Kubernetes.
- Thể hiện được tư duy kiến trúc thay vì chỉ cài tool trên một máy.

### 7.5 Thiết Kế High Availability Database Cluster Hoàn Chỉnh

HA database cluster trong đồ án được thiết kế theo mô hình **MySQL InnoDB Cluster single-primary**:

| Thành phần | Số lượng | Vai trò |
|---|---:|---|
| MySQL node | 3 | Một primary nhận ghi, hai secondary đồng bộ dữ liệu |
| MySQL Group Replication | 1 cluster | Đồng bộ trạng thái giữa các node và hỗ trợ failover |
| MySQL Router | 1-2 replicas | Endpoint ổn định cho client/ProxySQL/Acra khi cluster failover |
| MySQL Shell | On-demand | Bootstrap, kiểm tra và quản trị cluster |
| mysqld_exporter | Mỗi node hoặc một endpoint đại diện | Thu thập metrics phục vụ monitoring |

Luồng kết nối:

```text
Client / ProxySQL / Optional Acra Layer
        |
        v
MySQL Router
        |
        v
Current Primary Node
        |
        +--> Secondary Node 1
        +--> Secondary Node 2
```

Kịch bản kiểm thử HA:

1. Khởi tạo cluster với 3 node và xác nhận trạng thái healthy.
2. Ghi dữ liệu qua MySQL Router.
3. Kiểm tra dữ liệu được replicate sang secondary nodes.
4. Dừng primary node hiện tại.
5. Xác nhận cluster tự bầu primary mới.
6. Client tiếp tục query qua MySQL Router mà không cần biết node nào là primary.
7. Khởi động lại node cũ và xác nhận node đó join lại cluster.

Bằng chứng cần thu thập:

- Output cluster status trước và sau failover.
- Log hoặc screenshot cho thấy primary node thay đổi.
- Query qua router vẫn đọc/ghi được sau khi primary cũ bị dừng.
- Metrics/alert thể hiện một DB node down và cluster vẫn còn khả dụng.

### 7.6 Main Demo Path và Acra Evaluation Path

Để vừa bám topic gốc vừa đảm bảo DBF demo hoạt động ổn định, đồ án tách rõ hai đường triển khai:

```text
Main demo path:
Client -> ProxySQL DBF -> MySQL
```

```text
Acra evaluation path:
Client -> Acra / AcraCensor -> MySQL
```

Ở main demo path, ProxySQL là database proxy được cấu hình query rules để thực hiện chức năng DBF. Vai trò chính của ProxySQL trong đồ án là **policy enforcement**, không phải load balancing.

Ở Acra evaluation path, Acra được khảo sát và thử nghiệm đúng theo đề tài. Nếu AcraCensor không parse được query hoặc không evaluate rule ổn định trong môi trường MySQL 8.4, kết quả này được ghi nhận như một limitation kỹ thuật thay vì bỏ Acra khỏi đồ án.

Khi cần trình bày kiến trúc mở rộng, có thể đặt Acra sau ProxySQL:

```text
Client -> ProxySQL DBF -> Acra Security/Evaluation Layer -> MySQL
```

Nếu Acra layer gây bất ổn runtime, demo chính vẫn dùng:

```text
Client -> ProxySQL DBF -> MySQL
```

### 7.7 Môi Trường Local và Cloud

Đồ án có thể triển khai theo ba mức môi trường:

| Môi trường | Vai trò | Ghi chú |
|---|---|---|
| WSL2 Ubuntu | Môi trường local chính nếu dùng Windows | Thay thế VM được nếu Docker chạy ổn định |
| Ubuntu VM | Phương án local truyền thống | Dễ cô lập, phù hợp khi WSL2 gặp lỗi network/systemd |
| DigitalOcean VPS | Cloud extension optional | Demo deploy từ xa, firewall, SSH, monitoring endpoint |

WSL2 có thể thay VM cho phần Docker Compose vì môi trường đồ án chủ yếu chạy container và script. Khi dùng WSL2 cần lưu ý:

- Dùng Docker Desktop WSL integration hoặc Docker Engine cài trực tiếp trong WSL2.
- Cấp đủ CPU/RAM cho Docker, đặc biệt khi chạy HA cluster 3 MySQL nodes.
- Kiểm tra port binding `127.0.0.1` giữa Windows, WSL2 và container.
- Với systemd/service nội bộ, cần xác nhận bản WSL2 đang bật systemd hoặc dùng Docker Desktop để tránh lỗi daemon.

DigitalOcean VPS có thể đưa vào phần cloud ở mức optional:

- Cài Docker Engine và Docker Compose v2 trên VPS Ubuntu.
- Deploy baseline stack hoặc monitoring stack để chứng minh cloud deployment.
- Chỉ mở port cần thiết bằng firewall; ưu tiên SSH, Grafana qua tunnel/VPN hoặc allowlist IP.
- Không public MySQL trực tiếp ra Internet.
- Dùng password/secret riêng cho cloud, không dùng password demo trong `.env.example`.
- Ghi lại khác biệt giữa môi trường local và cloud: network public, firewall, resource quota, chi phí, backup/snapshot.

---

## 8. Công Nghệ và Công Cụ

### 8.1 Nền Tảng

| Thành phần | Định hướng | Vai trò |
|---|---|---|
| WSL2 Ubuntu | Local Windows environment | Môi trường local của đồ án thay thế VM |
| Ubuntu 22.04 LTS | VM/local host/DigitalOcean VPS | Môi trường chạy đồ án |
| Docker Engine | Stable | Container runtime |
| Docker Compose v2 | `docker compose` | Orchestration local |
| Python 3.10+ | Script automation | Seed/test/scan/load |
| Git | Version control | Quản lý source và báo cáo |
| DigitalOcean VPS | Cloud optional | Demo cloud deployment và hardening cơ bản |

### 8.2 Database và Security

| Công cụ | Vai trò |
|---|---|
| MySQL 8.4 | Target database |
| MySQL InnoDB Cluster / Group Replication | HA database cluster |
| MySQL Router | Entry point ổn định cho client khi cluster failover |
| MySQL Shell | Bootstrap và quản trị InnoDB Cluster |
| ProxySQL | DBF enforcement bằng MySQL proxy và query rules |
| Acra / AcraCensor | Security/evaluation layer: audit, optional encryption/masking/IDS, attempted DBF |
| MySQL View + RBAC | Baseline data masking |
| DataSunrise | Công cụ tham khảo/tìm hiểu tính năng DAM/DBF/masking |
| DBHawk | Công cụ tham khảo/tìm hiểu web-based database access/governance |

### 8.3 Monitoring và Alerting

| Công cụ | Vai trò |
|---|---|
| mysqld_exporter | Export MySQL metrics |
| Prometheus | Metrics collection và alert rules |
| Grafana | Dashboard trực quan |
| Alertmanager | Điều phối cảnh báo |

### 8.4 Development và Testing

| Công cụ/thư viện | Vai trò |
|---|---|
| Faker | Sinh dữ liệu giả lập |
| mysql-connector-python | Kết nối MySQL từ Python |
| python-dotenv | Đọc cấu hình `.env` |
| requests | Kiểm tra endpoint/health API |

---

## 9. Thiết Kế Chi Tiết Các Tính Năng

### 9.1 Active Monitor

Mục tiêu:

- Ghi nhận truy vấn theo thời gian.
- Biết user/source nào thực hiện truy vấn.
- Có audit trail để đối chiếu khi xảy ra truy vấn bất thường.

Triển khai:

- Baseline: MySQL general log/slow log khi cần demo.
- Security phase: ProxySQL stats/logs; optional audit log từ Acra evaluation path.
- Script test tạo các truy vấn có chủ đích để dễ đối chiếu log.

Kịch bản demo:

1. Người dùng chạy truy vấn đọc PII ngoài giờ giả lập.
2. Người dùng chạy thao tác nguy hiểm như `DELETE` hoặc `DROP` trong môi trường test.
3. Log/audit trail ghi lại được thời điểm, user và nội dung query.

### 9.2 Database Firewall (DBF)

Mục tiêu:

- Chặn các query nguy hiểm hoặc trái chính sách.
- Minh họa allow/deny policy ở tầng trước database.

Triển khai:

- Dùng ProxySQL query rules làm DBF enforcement chính.
- Dùng AcraCensor như hướng thử nghiệm/đánh giá theo topic gốc; nếu parser không ổn định, ghi rõ limitation và không dùng làm DBF chính.
- Tập trung rule dễ kiểm chứng, không đặt mục tiêu parser đầy đủ.

Rule demo dự kiến:

- Block `DROP`.
- Block `TRUNCATE`.
- Block `SELECT * FROM users`.
- Block payload injection cơ bản như `' OR '1'='1`.

Bằng chứng:

- Query hợp lệ trả kết quả.
- Query bị cấm trả lỗi/deny.
- ProxySQL stats/logs ghi nhận rule hit hoặc action deny.
- Nếu có Acra evaluation path, log Acra ghi nhận kết quả thử nghiệm và limitation.

### 9.3 Data Masking

Mục tiêu:

- Người dùng ứng dụng không nhìn thấy raw PII.
- Admin/root vẫn có khả năng kiểm tra dữ liệu gốc trong môi trường thực nghiệm.

Triển khai baseline:

- Tạo bảng gốc `users` chứa email, phone, address, credit card, SSN giả lập.
- Tạo view `users_masked`.
- Cấp quyền cho `appuser` chỉ được `SELECT` view, không được đọc bảng gốc.

Ví dụ masking:

- Email: `n***@domain.com`.
- Phone: chỉ hiện 3-4 số cuối.
- Credit card: `**** **** **** 1234`.
- SSN: `***-**-1234`.

Bằng chứng:

- Root query bảng gốc thấy raw data.
- `appuser` query view thấy masked data.
- `appuser` query bảng gốc bị denied.

### 9.4 Performance Monitoring

Mục tiêu:

- Quan sát sức khỏe database.
- Phát hiện dấu hiệu bất thường về connection, throughput và slow query.

Triển khai:

- `mysqld_exporter` thu thập metrics.
- Prometheus scrape metrics.
- Grafana hiển thị dashboard.
- Alertmanager nhận alert rule cơ bản.

Metrics quan tâm:

- MySQL up/down.
- Threads connected.
- Questions/QPS.
- Slow queries.
- InnoDB metrics cơ bản.
- Exporter scrape status.

Kịch bản demo:

1. Tạo nhiều connection đồng thời.
2. Tạo slow query hoặc query thiếu index.
3. Quan sát dashboard thay đổi.
4. Trigger alert đơn giản nếu target down hoặc connection vượt ngưỡng.

### 9.5 Sensitive Data Discovery

Mục tiêu:

- Phát hiện nơi có khả năng chứa dữ liệu nhạy cảm.
- Phát hiện PII bị lưu sai chỗ trong free-text.

Triển khai:

- Schema scan qua `INFORMATION_SCHEMA`.
- Pattern scan trên dữ liệu mẫu.
- Xuất kết quả JSON/CSV.

Pattern demo:

- Email.
- Phone number.
- Credit card-like number.
- SSN-like value.
- Từ khóa nhạy cảm trong tên cột: `email`, `phone`, `address`, `ssn`, `card`, `password`, `token`.

Bằng chứng:

- Report liệt kê bảng/cột đáng nghi.
- Report liệt kê dòng trong `activity_logs.notes` chứa PII.
- Đề xuất xử lý cho từng phát hiện.

### 9.6 High Availability Database Cluster

Mục tiêu:

- Loại bỏ single point of failure ở tầng database trong phạm vi đồ án.
- Cho thấy database vẫn khả dụng khi primary node bị dừng.
- Kết hợp HA với monitoring để phát hiện node lỗi và quan sát trạng thái cluster.

Triển khai:

- Dùng 3 MySQL nodes chạy Group Replication/InnoDB Cluster.
- Dùng MySQL Router làm endpoint kết nối duy nhất cho client, ProxySQL và optional Acra layer.
- Dùng MySQL Shell để bootstrap cluster và kiểm tra trạng thái.
- Mỗi node có volume riêng để mô phỏng stateful service.
- Monitoring scrape metrics theo node hoặc qua exporter đại diện.

Kịch bản demo:

1. Ghi dữ liệu qua router khi cluster healthy.
2. Dừng container/node primary.
3. Kiểm tra cluster bầu primary mới.
4. Ghi/đọc dữ liệu tiếp qua router.
5. Khởi động lại node cũ và xác nhận node join lại cluster.

Bằng chứng:

- Cluster status trước failover.
- Cluster status sau failover.
- Query vẫn thành công qua router.
- Grafana/Prometheus thể hiện node down hoặc exporter target down.

---

## 10. Dữ Liệu Thử Nghiệm

### 10.1 Schema Chính

| Bảng | Vai trò |
|---|---|
| `users` | Chứa PII chính |
| `orders` | Dữ liệu giao dịch |
| `activity_logs` | Log/free-text phục vụ sensitive discovery |

### 10.2 Quy Mô Seed

| Bảng | Số bản ghi dự kiến |
|---|---:|
| `users` | 1000 |
| `orders` | 3000 |
| `activity_logs` | 200 |

### 10.3 Yêu Cầu Dữ Liệu

- Dữ liệu phải là giả lập, không dùng dữ liệu cá nhân thật.
- Có email, phone, address, credit card-like value, SSN-like value.
- Một phần PII được cố tình đưa vào `activity_logs.notes` để demo discovery.
- Có dữ liệu đủ lớn để dashboard và load test có thay đổi nhìn thấy được.

---

## 11. Kịch Bản Demo Chính

| Nhóm tính năng | Kịch bản | Kết quả mong đợi |
|---|---|---|
| Active Monitor | Chạy query đọc PII và query nguy hiểm | Log ghi lại user/query/time |
| DBF | Gửi query `DROP`, `TRUNCATE`, injection pattern | Query bị block và ProxySQL stats/logs ghi nhận deny |
| Data Masking | So sánh root với `appuser` | Root thấy raw, appuser thấy masked |
| Performance | Tạo connection spike/slow query | Grafana hiển thị thay đổi, alert có thể trigger |
| Sensitive Discovery | Chạy schema scan và pattern scan | Report phát hiện PII trong schema/data |
| High Availability | Dừng primary MySQL node trong InnoDB Cluster | Cluster bầu primary mới, client vẫn query qua Router |
| Advanced | Trình bày mapping Compose -> Kubernetes | Giải thích được availability/scalability |

Mỗi kịch bản cần có:

- Bước thực hiện.
- Command hoặc script dùng để test.
- Kết quả mong đợi.
- Bằng chứng: screenshot, log, output JSON/CSV hoặc dashboard.

---

## 12. Cấu Trúc Thư Mục Dự Kiến

```text
database-security/
├── README.md
├── proposal.md
├── topic.txt
├── compose.yaml
├── .env.example
├── config/
│   ├── acra/
│   ├── proxysql/
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   └── rules.yml
│   ├── alertmanager/
│   │   └── alertmanager.yml
│   ├── grafana/
│   │   ├── datasources/
│   │   └── dashboards/
│   └── mysqld-exporter/
│       └── .my.cnf
├── mysql/
│   ├── init.sql
│   ├── my.cnf
│   ├── cluster/
│   │   ├── mysql-node.cnf
│   │   └── init-cluster.sql
│   ├── schema.sql
│   ├── masking.sql
│   └── rbac.sql
├── scripts/
│   ├── seed_all.py
│   ├── scan_schema.py
│   ├── scan_data_patterns.py
│   ├── test_sqli.py
│   ├── generate_load.py
│   ├── stress_connections.py
│   ├── test_failover.py
│   └── test_masking.sh
├── screenshots/
│   ├── active_monitor/
│   ├── dbf/
│   ├── data_masking/
│   ├── ha_cluster/
│   ├── performance/
│   └── sensitive_discovery/
├── logs/
├── k8s/
│   ├── README.md
│   ├── mysql-innodb-cluster-statefulset.yaml
│   ├── mysql-router-deployment.yaml
│   ├── proxysql-deployment.yaml
│   ├── acra-evaluation-deployment.yaml
│   ├── monitoring-notes.md
│   └── secrets-example.yaml
└── report/
    └── final_report.md
```

---

## 13. Security Hardening Cho Môi Trường Đồ Án

Các biện pháp hardening dự kiến:

- Bind port public vào `127.0.0.1` trong Docker Compose.
- Không commit file `.env` thật.
- Dùng user riêng cho exporter với quyền tối thiểu.
- Dùng user app riêng thay vì root.
- Tách network nội bộ cho các service.
- Dùng named volume cho dữ liệu.
- Bật healthcheck cho service quan trọng.
- Hạn chế quyền container khi có thể.
- Ghi rõ password trong môi trường đồ án chỉ là demo, không dùng cho production.
- Nếu triển khai trên DigitalOcean VPS, dùng cloud firewall/UFW, SSH key, allowlist IP và không expose MySQL trực tiếp ra Internet.

---

## 14. Rủi Ro và Hướng Xử Lý

| Rủi ro | Mức độ | Hướng xử lý |
|---|---|---|
| Tích hợp Acra với MySQL tốn thời gian hoặc AcraCensor không ổn định | Cao | Tách Acra thành evaluation path; dùng ProxySQL làm DBF enforcement chính |
| Rule DBF không ổn định | Trung bình | Dùng ProxySQL query rules đơn giản, tập trung deny/allow có log/stats |
| Exporter không scrape được | Trung bình | Kiểm tra user exporter, config `.my.cnf`, network, log container |
| Dashboard Grafana thiếu dữ liệu | Trung bình | Tạo load test và import dashboard tối giản |
| HA cluster nhiều container, tốn RAM và khó bootstrap | Cao | Tách thành phase advanced; dùng 3 node tối thiểu, script hóa bootstrap và failover test |
| WSL2/VM thiếu RAM | Trung bình | Chạy từng phase, giảm container optional, tăng resource cho Docker |
| WSL2 lỗi network hoặc Docker daemon | Trung bình | Dùng Docker Desktop WSL integration hoặc chuyển sang Ubuntu VM |
| Kubernetes vượt phạm vi | Trung bình | Trình bày architecture + manifest mẫu, demo optional |
| Dữ liệu nhạy cảm giả lập bị hiểu nhầm là dữ liệu thật | Thấp | Ghi rõ dùng Faker và synthetic data |
| DigitalOcean VPS hết quota, tốn chi phí hoặc network phức tạp | Thấp | Giữ cloud là optional, ưu tiên môi trường local dễ tái tạo |

---

## 15. Deliverables

Sản phẩm cuối cùng gồm:

- Source code và cấu hình môi trường thực nghiệm.
- Docker Compose chạy được baseline.
- Script seed/test/scan/load.
- Dashboard hoặc screenshot monitoring.
- Log/audit evidence cho Active Monitor và DBF, gồm ProxySQL stats/logs và optional Acra evaluation logs.
- Kết quả masking và sensitive discovery.
- HA database cluster demo: cluster status, failover test, query qua MySQL Router.
- Ghi chú triển khai WSL2 và optional DigitalOcean VPS/cloud deployment.
- Báo cáo cuối kỳ.
- Video demo ngắn.
- Phần phân tích architecture: multi-container, Kubernetes extension, availability, scalability.

---

## 16. Todolist Theo Phase

### Phase 1 - Môi Trường Nền

- [ ] Chuẩn bị WSL2 Ubuntu, Ubuntu VM hoặc Linux host.
- [ ] Cài Docker Engine và Docker Compose v2.
- [ ] Tạo `.env`, `compose.yaml`, network, volume.
- [ ] Dựng MySQL, mysqld_exporter, Prometheus, Grafana, Alertmanager.
- [ ] Kiểm tra container health và endpoint.

### Phase 2 - Database, Seed Data, RBAC

- [ ] Tạo schema `users`, `orders`, `activity_logs`.
- [ ] Seed dữ liệu giả lập.
- [ ] Tạo view `users_masked`.
- [ ] Cấu hình quyền `root`, `appuser`, `exporter`.
- [ ] Test masking bằng CLI/script.

### Phase 3 - Active Monitor

- [ ] Bật nguồn log cần thiết.
- [ ] Tạo query test có chủ đích.
- [ ] Thu thập log và screenshot.
- [ ] Ghi lại nhận xét về khả năng audit.

### Phase 4 - Database Firewall / ProxySQL + Acra Evaluation

- [ ] Tạo config ProxySQL.
- [ ] Viết rule deny/allow đơn giản bằng ProxySQL query rules.
- [ ] Demo query hợp lệ và query bị block qua ProxySQL.
- [ ] Thu thập ProxySQL stats/logs làm bằng chứng deny.
- [ ] Thử nghiệm Acra/AcraCensor ở evaluation path và ghi nhận limitation nếu có.

### Phase 5 - Performance Monitoring

- [ ] Cấu hình dashboard Grafana.
- [ ] Tạo load test.
- [ ] Tạo connection spike.
- [ ] Tạo alert rule cơ bản.
- [ ] Chụp bằng chứng dashboard/alert.

### Phase 6 - Sensitive Data Discovery

- [ ] Viết schema scanner.
- [ ] Viết pattern scanner.
- [ ] Export kết quả JSON/CSV.
- [ ] Đề xuất remediation cho dữ liệu nhạy cảm phát hiện được.

### Phase 7 - High Availability Database Cluster

- [ ] Chuẩn bị cấu hình 3 MySQL nodes.
- [ ] Bootstrap MySQL InnoDB Cluster bằng MySQL Shell.
- [ ] Thêm MySQL Router làm endpoint kết nối.
- [ ] Kiểm tra replication và cluster status.
- [ ] Dừng primary node để test failover.
- [ ] Xác nhận client vẫn đọc/ghi qua router sau failover.
- [ ] Thu thập screenshot/log/metrics làm bằng chứng.

### Phase 8 - Kubernetes / Advanced

- [ ] Viết tài liệu mapping Compose sang Kubernetes.
- [ ] Tạo manifest mẫu cho MySQL InnoDB Cluster StatefulSet, MySQL Router Deployment, ProxySQL Deployment và Acra evaluation Deployment.
- [ ] Mô tả Secret, ConfigMap, Service, PVC.
- [ ] Mô tả availability và scalability.
- [ ] Optional demo cloud bằng DigitalOcean VPS.
- [ ] Optional demo Kubernetes bằng kind/minikube.

---
