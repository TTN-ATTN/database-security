# Future Work — Limitations + Production Roadmap

Tài liệu này **acknowledge thẳng** mọi giới hạn của project hiện tại và vẽ đường đi production-grade. Mỗi mục: vấn đề hiện tại → tại sao chấp nhận trong scope đồ án → con đường mở rộng cụ thể (công nghệ, cost magnitude, effort).

> Spirit: project demo nguyên lý **defense in depth** ở mức compose-on-laptop. Production cần tách 3 trục: (1) **availability** chống mất dịch vụ, (2) **security posture** chống insider + supply-chain, (3) **operational maturity** chống tự bắn vào chân.

---

## 1. Single Points of Failure (SPOFs) còn lại

### 1.1 ProxySQL HA-router là SPOF

**Hiện trạng**: chỉ 1 container `dbsec-ha-router`. Nó chết → app mất endpoint → cluster MySQL vẫn sống nhưng vô dụng.

**Tại sao chấp nhận**: demo project muốn show GR cluster availability. ProxySQL HA bản thân nó là chủ đề riêng + tốn thêm 1 layer.

**Production fix**:
- **Active-passive**: 2 ProxySQL container + `keepalived` quản 1 Virtual IP (VRRP). Master chết → standby cướp VIP trong ~3s. Setup ~1 ngày.
- **Active-active**: 2+ ProxySQL sau cloud LB (AWS NLB / GCP TCP LB / Azure Standard LB). Connection draining khi tear down. Setup ~2 ngày + LB cost.
- **Cloud-native**: trên K8s thì 2+ Pod + Service type LoadBalancer; trên ECS thì Task + ALB. Cost: NLB ~$22/month + data transfer.
- **Sync state**: ProxySQL có native cluster mode đồng bộ runtime config qua riêng MySQL backend dùng làm config store. Tránh drift giữa 2 ProxySQL.

### 1.2 Acra server là SPOF

**Hiện trạng**: 1 `dbsec-acra-server`. Chết → chained path dừng → mọi role qua chain mất dịch vụ.

**Production fix**:
- **Multi-instance**: ≥2 Acra server share cùng keystore. Stateless với respect to query session.
- **Keystore options**:
  - Shared volume (NFS/EFS) — đơn giản nhưng NFS đôi khi lag.
  - HashiCorp Vault Transit — Acra hỗ trợ KMS plugin; centralize key.
  - AWS KMS / GCP CloudKMS — Acra fetch key qua KMS API. Trade-off: dependency on cloud.
- **Health check**: thêm `/healthz` ở Acra (Acra 0.96 chưa có natively, cần wrap bằng tiny HTTP sidecar).
- Effort: ~3-5 ngày tích hợp + test failover.

### 1.3 Acra master key trong `.env`

**Hiện trạng**: `ACRA_MASTER_KEY=<base64>` plaintext trong `.env`, file gitignored nhưng vẫn nằm trên disk.

**Tại sao chấp nhận**: scope đồ án, không có HSM thật.

**Production fix theo độ chín**:
- **Mức tối thiểu**: SOPS encrypt `.env` với age/PGP key; deploy time decrypt. Effort: 1 ngày.
- **Mức tốt**: Vault Transit hoặc cloud KMS — Acra fetch key on boot qua API, không lưu trên disk container. Effort: 3-5 ngày.
- **Mức enterprise**: dedicated HSM (Thales nShield / AWS CloudHSM / YubiHSM2) — key never leaves HSM. Cost: $1.6/h cho AWS CloudHSM (~$1170/month minimum). Effort: 2-3 tuần + tích hợp PKCS#11.
- **Key rotation**: project chưa có procedure. Production cần (a) generate new key (b) re-encrypt batch background (c) cutover (d) revoke old. Cossack Labs có doc cho quy trình này nhưng chưa automate.

### 1.4 Token secret cho self_service hardcoded

**Hiện trạng**: `'self_service_secret'` literal trong cả `mysql/phase7_5_classification.sql` (stored proc) lẫn `demo/app.py` (Flask). Compromise 1 trong 2 → có thể forge token.

**Production fix**:
- Token thực ra nên là **JWT signed bằng key trong vault** chứ không phải SHA2 với secret static. App có private key, MySQL có public key (qua extension như `mysql-jwt`).
- Hoặc dùng **HMAC với secret từ Vault** — secret rotate được, project hiện tại không.
- Hoặc đơn giản hơn: stored proc gọi external authz service (Open Policy Agent / Cerbos) qua MySQL UDF.

---

## 2. Multi-region / Disaster Recovery

### 2.1 Single-region, single-AZ

**Hiện trạng**: 3 GR node trong cùng 1 Docker host. Host chết → toàn bộ cluster chết. Không có node ở vùng địa lý khác.

**Tại sao chấp nhận**: GR cross-region cần network latency thấp (< 100ms RTT for sync replication). Demo trên 1 laptop.

**Production fix bậc thang**:

| Mức | Cấu hình | RPO | RTO | Cost magnitude |
|---|---|---|---|---|
| **Single-AZ** (hiện tại) | 3 node 1 host | data lost on host failure | ∞ (manual rebuild) | minimal |
| **Multi-AZ** | 3 GR node trên 3 AZ cùng region | ≈0 (sync replication majority) | <10s (GR auto-elect) | 3× compute + cross-AZ traffic |
| **Multi-region active-passive** | 1 GR cluster region A + async slave ở region B | seconds (async lag) | minutes (DNS cutover) | 2× compute + cross-region traffic |
| **Multi-region active-active** | 2 GR cluster, sync conflict resolution | complex | <1min | 2× compute + complex conflict logic |

**Recommend cho fintech-grade**: Multi-AZ là phase tiếp theo realistic; multi-region active-passive là phase sau nữa.

**Cloud-native picks**:
- AWS: RDS Aurora MySQL multi-AZ (3 AZ tự động, native binlog). Cost: db.r6g.xlarge ~$0.34/h × 3 + storage.
- GCP: Cloud SQL MySQL HA (1 primary + 1 standby cross-zone). Cost: ~$0.50/h cho db-n1-standard-2 HA.
- Azure: Azure Database for MySQL Flexible Server zone-redundant HA.

**Trade-off khi đi managed**: mất Acra (managed RDS không cho install custom proxy bên dưới). Phải thay bằng app-level encryption (ActiveRecord/SQLAlchemy encrypted attribute) hoặc TDE (managed DB encryption, dùng cloud KMS).

### 2.2 Backup automation

**Hiện trạng**: không có backup. `make demo-clean-all` chỉ tear down container, MySQL volume vẫn còn nhưng manual.

**Production fix**:
- **Logical backup**: `mysqldump` cron daily → S3 với retention 30 ngày. Lưu ý dump chứa AcraStruct ciphertext → restore phải có master key Acra cùng phiên bản, nếu không decrypt fail.
- **Physical backup**: `xtrabackup` (Percona) — hot backup không lock, snapshot binlog cho PITR. Đặt ở secondary node để không ảnh hưởng primary.
- **PITR (Point-In-Time Recovery)**: base xtrabackup + binlog stream → restore tới timestamp bất kỳ. RPO = binlog flush interval (1-5 phút thông thường).
- **Snapshot tier**: AWS EBS snapshot per hour (`dlm`) hoặc EFS automatic backup. Effort: 1-2 ngày.
- **Cross-region replication**: S3 CRR cho dump; AWS Backup Vault cho cross-region snapshot.
- **Restore drill**: ≥ quarterly restore test vào staging environment + verify integrity. Đây là phần **hầu hết team bỏ qua** cho đến lúc DR thật.

Effort tổng: 1-2 tuần để có pipeline backup + automated restore drill.

### 2.3 Chaos engineering

**Hiện trạng**: chỉ có demo "Stop node" trong UI. Không có chaos test định kỳ.

**Production fix**:
- **Tier 0**: scripted `docker stop` ngẫu nhiên 1 node 1 lần/tuần trên staging. Verify alert + recovery.
- **Tier 1**: Chaos Mesh / Litmus trên K8s — network partition, IO stall, slow disk. Pod kill schedule.
- **Tier 2**: AWS Fault Injection Simulator hoặc Gremlin (commercial) — RDS failover, AZ outage simulation, network blackhole giữa các microservice.
- **Game days**: 1 lần/quarter, team chạy chaos scenario có scripts, đo MTTR. Document playbook.

Effort: 2-3 tuần để có pipeline + 1 game day xong → ROI cao sau đó.

---

## 3. Cloud-native deployment (Phase 8 trong proposal)

### 3.1 Kubernetes migration

**Hiện trạng**: `docker compose`. Proposal §6.8 đã vẽ mapping compose → K8s primitive nhưng chưa implement.

**Mapping cụ thể**:

| Compose service | K8s | Lưu ý |
|---|---|---|
| `mysql` (3 GR nodes) | StatefulSet `mysql-gr` với 3 replicas + headless Service | Cần stable network identity (mysql-0/1/2), GR config dùng pod DNS |
| MySQL data volume | PVC + StorageClass (gp3 / Premium SSD / pd-ssd) | reclaimPolicy=Retain để tránh mất data nếu PVC bị delete |
| `proxysql` (DBF) | Deployment + Service ClusterIP | 2+ replicas behind Service; cấu hình sync qua ProxySQL cluster mode |
| `dbsec-ha-router` | Deployment + Service LoadBalancer | Chính là cloud LB ở ngoài |
| `acra-server` | StatefulSet (giữ keystore via PVC) hoặc Deployment + Vault CSI | nếu key vault thì stateless được |
| `prometheus` | Operator (Prometheus Operator) | tự gen ServiceMonitor / PodMonitor; ngoài ra dùng Thanos cho long-term storage |
| `grafana` | grafana-operator + ConfigMap dashboards | provision dashboard từ Git |
| `alertmanager` | Operator | route → PagerDuty / Slack |
| `.env` secrets | Sealed Secrets / External Secrets Operator + Vault | không lưu plain trong Git |

**Effort estimate**: 2-3 tuần để setup cluster + migrate full stack + test. Setup bao gồm:
- Kind / k3s cluster trên local cho test
- Real cluster: EKS (~$0.10/h cho control plane + worker cost) hoặc GKE Autopilot (pay per pod) hoặc AKS
- Helm chart hoặc Kustomize cho deploy

**Decisions cần trước khi migrate**:
- Service mesh (Istio / Linkerd) — có cần mTLS giữa các service không? Nếu yes → +1 tuần setup.
- Ingress controller (nginx / Traefik / cloud ALB controller) cho HTTPS từ ngoài.
- CertManager + Let's Encrypt cho cert tự động.
- Network policies (Calico / Cilium) — zero-trust giữa namespace.

### 3.2 IaC (Infrastructure as Code)

**Hiện trạng**: setup là compose file + Makefile + bash script. Chỉ tự động hóa được tới mức Docker host.

**Production fix**:
- **Terraform** modules:
  - `network` — VPC, subnet, security group
  - `data` — RDS / Aurora cluster, parameter group
  - `compute` — EKS cluster, node group
  - `secrets` — KMS key, Secrets Manager secret
  - `observability` — Managed Prometheus / Grafana workspace
- Repo structure: `infrastructure/terraform/{environments,modules}` với separate state per environment (S3 backend + DynamoDB lock).
- **Pulumi** thay thế nếu team Python/TypeScript heavy.

Effort: 1-2 tuần cho 1 module hoàn chỉnh; 6-8 tuần cho full platform module set.

### 3.3 GitOps deployment

**Hiện trạng**: deploy = `make demo-up`. Không có pipeline.

**Production fix**:
- **ArgoCD** / **Flux** cho declarative deploy. Repo Git là source of truth cho cluster state.
- App của Argo: 1 Application per service (proxysql, acra, mysql-gr, …) reference Helm chart hoặc Kustomize overlay.
- **Image build pipeline**: GitHub Actions / GitLab CI / Tekton build + push to registry (ECR / GCR / Harbor).
- **Image signing**: Cosign + Sigstore — chống supply-chain attack (push image giả).
- **Promotion flow**: `dev` → `staging` → `prod` qua PR. ArgoCD watch branch khác cho mỗi env.

### 3.4 Service mesh + mTLS

**Hiện trạng**: traffic giữa app ↔ ProxySQL ↔ Acra ↔ MySQL là plaintext TCP local. Production cần encrypt-in-transit.

**Production fix**:
- **Istio** hoặc **Linkerd** sidecar inject vào mọi Pod → mTLS automatic giữa các Pod.
- **MySQL native TLS**: cấp cert cho mysql-server, force `REQUIRE SSL` ở user grant. ProxySQL config TLS frontend + backend.
- **Acra**: 0.96 hỗ trợ TLS cả phía client lẫn backend. Cert quản qua cert-manager.
- **Zero-trust**: NetworkPolicy chặn mọi traffic trừ allowed (deny-by-default).

Effort: 1 tuần TLS cho MySQL/ProxySQL; +1 tuần cho service mesh setup; +1 tuần cho cert rotation automation.

---

## 4. Observability ở scale

### 4.1 Prometheus là single instance

**Hiện trạng**: 1 Prometheus container. Mất → mất metrics history.

**Production fix**:
- **Prometheus HA pair** + Alertmanager HA — 2 Prometheus scrape song song, Alertmanager cluster gossip để dedupe alert.
- **Thanos / Cortex / Mimir** cho long-term storage (S3 backend), query federation, downsampling.
- **VictoriaMetrics** alternative — single binary, lower cost.
- **Managed**: AWS Managed Prometheus, GCP Managed Service for Prometheus, Grafana Cloud — pay per ingested sample.

Effort: 1 tuần for HA pair; 2-3 tuần cho Thanos full setup.

### 4.2 Logs không tập trung

**Hiện trạng**: log nằm trong `logs/{mysql,proxysql,acra,discovery}/` trên local filesystem. Không ship đi đâu.

**Production fix stack ELK / Loki**:
- **Fluentbit** / **Vector** / **Promtail** as DaemonSet collect log từ container stdout + bind-mounted log files.
- Ship sang **Loki** (cheap, label-based, tích hợp Grafana) hoặc **Elasticsearch** (full-text search, expensive at scale) hoặc **CloudWatch Logs** (managed).
- Cho audit-specific logs (Phase 3 evidence pipeline): ship sang **SIEM** như Splunk / Sumo Logic / Datadog Security — có retention 1 năm cho compliance.
- Log redaction: pre-shipping mask PII (Vector có transform).

Effort: 1-2 tuần cho Loki stack; 3-4 tuần để có Splunk integration.

### 4.3 Tracing chưa có

**Hiện trạng**: không có distributed tracing — khó debug "tại sao request này chậm" khi đi qua nhiều layer.

**Production fix**:
- **OpenTelemetry** SDK trong app (Flask) → emit trace.
- Backend: **Jaeger** (free, self-host), **Tempo** (Grafana stack), **Honeycomb** / **Datadog APM** (commercial).
- Instrument: Flask request → ProxySQL query → Acra → MySQL execute, mỗi hop là 1 span với latency.
- Ích lợi: debug slow query xuyên layer; correlate với log/metric qua trace_id.

### 4.4 Alertmanager chỉ in UI

**Hiện trạng**: alert chạy nhưng route đến UI Alertmanager thôi. Không Slack/email/PagerDuty.

**Production fix**:
- Tích hợp PagerDuty (incident on-call rotation), Slack webhook, email.
- **Routing policy** — alert nào báo cho team nào dựa trên label (`team=db`, `severity=critical`).
- **Silence** + maintenance window automation (Alertmanager + scripts).
- **Runbook link** trong alert annotation — on-call mở alert thấy ngay link wiki "fix step by step".

---

## 5. Security posture

### 5.1 Network — không có zero-trust

**Hiện trạng**: tất cả container cùng Docker network `dbsec_net`, talk được tới nhau tự do.

**Production fix**:
- **NetworkPolicy** (Calico / Cilium) — deny-by-default; chỉ allow Flask → ProxySQL, ProxySQL → Acra, Acra → MySQL.
- **Egress restriction** — Flask không cần Internet access; ProxySQL/Acra/MySQL chỉ Internet để pull image lúc setup, deny sau đó.
- **VPC + private subnet** — chỉ LB public; DB ở private subnet.
- **Bastion / IAP** cho DBA access — không SSH thẳng vào host nào.

### 5.2 Authentication ở app

**Hiện trạng**: demo dùng button-to-login đơn giản; password hardcoded `alice/alice` etc.

**Production fix**:
- **OAuth/OIDC** với provider (Okta / Auth0 / Cognito / Keycloak).
- **MFA** bắt buộc cho support + admin role.
- **Step-up auth** cho fraud team đọc PII — re-MFA mỗi 30 phút.
- **Session timeout** + idle timeout.
- **Audit log** — mọi login + role change + sensitive access đẩy sang SIEM.

### 5.3 Secret management

**Hiện trạng**: `.env` plain. Password DB hardcoded.

**Production fix**:
- **External Secrets Operator** + Vault / AWS Secrets Manager / Azure Key Vault.
- Secret rotation tự động — Vault dynamic credential, rotate mỗi 24h.
- Service-to-service auth qua **workload identity** (IRSA / Workload Identity) thay vì static secret.

### 5.4 PCI-DSS / GDPR / SOC 2 readiness

**Hiện trạng**: design có nét compliance (encryption, RBAC, audit) nhưng chưa **attestation-ready**.

**Production roadmap**:
- **PCI-DSS Req mapping**:
  - Req 3 (encryption of stored cardholder data) → Acra ✓ but cần HSM-backed key (mức thấp 3.6) hoặc key custodian split (mức cao 3.6.6-3.6.7).
  - Req 4 (encryption in transit) → cần mTLS end-to-end (chưa làm).
  - Req 7 (need-to-know) → fraud role ✓.
  - Req 8 (auth + identification) → cần MFA + unique ID per person, hiện app dùng shared account.
  - Req 10 (audit log) → ✓ qua Phase 3 pipeline; cần retention 1 năm minimum + integrity protection (WORM storage).
  - Req 11 (security testing) → cần ASV scan hàng quý, pen test hàng năm.
  - Req 12 (info security policy) → policy document.
- **SAQ (Self-Assessment Questionnaire)** loại D nếu store/process/transmit cardholder data. Hoặc xài tokenization (Stripe / Adyen) để outsource scope.
- **GDPR**: 
  - Right to erasure → cần procedure xóa user khỏi cluster + key rotation.
  - DPO + DPA (Data Protection Agreement) với mọi data processor.
  - Subject access request — endpoint export full data của user.
- **SOC 2 Type II**: 12 tháng audit, cần evidence trail tự động cho mọi control. Vanta / Drata / SecureFrame tự động hóa được phần lớn.

Effort: 6-12 tháng cho 1 đợt audit đầu tiên, có sự đồng hành của auditor.

### 5.5 Supply chain security

**Hiện trạng**: pull docker image từ Docker Hub không verify signature; pip install từ PyPI tự do.

**Production fix**:
- **Image signing** với **Cosign** + Sigstore; admission controller (Kyverno / OPA Gatekeeper) chỉ allow signed image.
- **SBOM** (Software Bill of Materials) — `syft` generate SBOM cho mỗi image; **grype** scan vulnerability mỗi đêm.
- **Trivy** / **Snyk** trong CI block image có CVE critical.
- Python deps: `pip-audit` + lock file với `pip-compile --generate-hashes`.
- **Renovate** / **Dependabot** bump dep tự động.

---

## 6. Operational maturity

### 6.1 Không có SLO/SLI

**Hiện trạng**: project chạy được = ok. Không có định nghĩa "thế nào là chấp nhận được".

**Production fix**:
- **SLI examples**:
  - Availability: % HTTP 2xx + 3xx trong 5 phút sliding window.
  - Latency: p99 response time qua chain.
  - Error rate: 5xx + DBF deny ratio.
  - HA recovery: time-to-elect-new-primary sau kill.
- **SLO**: 99.9% availability/month, p99 < 200ms.
- **Error budget**: 0.1% = ~43min downtime/month. Vượt → freeze feature dev, focus reliability.
- **SLO dashboard** trong Grafana + alert khi burn rate cao (alert "burning budget faster than acceptable").

### 6.2 Capacity planning chưa có

**Hiện trạng**: 1 host, 3 GR node. Tăng load → ai biết khi nào nổ.

**Production fix**:
- **Load testing** định kỳ — k6 / Locust / JMeter; baseline mỗi release.
- **HPA / VPA** trên K8s cho stateless component (ProxySQL, Acra, app).
- MySQL/GR scale-up khó hơn (StatefulSet không HPA được sensibly) → dùng read replica + connection pool tuning.
- **Sharding strategy** cho khi DB outgrow 1 host — Vitess hoặc app-level sharding.

### 6.3 Connection pool tuning

**Hiện trạng**: ProxySQL default config. App dùng PyMySQL không pool.

**Production fix**:
- App side: `SQLAlchemy` pool với `pool_size` + `max_overflow` calibrate per env.
- ProxySQL: `mysql-max_connections_per_host` + `mysql-connection_max_age_ms` to prevent stale connection.
- MySQL: `max_connections` không nên > 5× số core; thêm thì context switch tốn hơn lợi.

### 6.4 Cost monitoring

**Hiện trạng**: chạy laptop, cost = 0.

**Production fix**:
- AWS Cost Explorer + Budget alarm; **per-tag cost allocation**.
- **Kubecost** trên K8s cho cost breakdown per namespace/pod.
- **Spot Instance / Savings Plans** cho stateless workload (Flask, ProxySQL).
- RDS Reserved Instance — 30-50% discount cho 1y commitment.
- **FinOps practice**: monthly review, identify orphan resources (EBS snapshot 6 tháng, idle EIP, …).

---

## 7. Code & test quality

### 7.1 Test coverage thấp

**Hiện trạng**: có `scripts/phase*_check.sh` cho mỗi phase nhưng đó là integration; không có unit test cho `demo/app.py`.

**Production fix**:
- pytest cho Flask endpoint + mock DB.
- Integration test trong CI (GitHub Actions với docker-compose service).
- Mutation testing với `mutmut` để verify test thực sự catch bug.
- End-to-end với Playwright cho UI flow.

### 7.2 CI/CD chưa setup

**Hiện trạng**: commit là push thẳng main qua local git.

**Production fix**:
- GitHub Actions workflow:
  - Lint (`ruff` Python, `shellcheck` bash)
  - Test (pytest)
  - Build image (Docker buildx multi-arch)
  - SBOM + vuln scan (Trivy)
  - Push to ECR/GHCR (only on main/tag)
- Pre-commit hook: `pre-commit-config.yaml` với ruff + shellcheck + yamllint.

### 7.3 Documentation

**Hiện trạng**: README + proposal + data_flow + problem + cleanup + future_work (this file). Khá đủ cho 1 project học.

**Production add**:
- **Runbook** cho mọi alert — what to check, how to fix.
- **Architecture Decision Records (ADR)** — why we picked X over Y.
- **Onboarding doc** — "Day 1 cho engineer mới".
- **Incident postmortem template**.

---

## 8. Acknowledged design choices (defense to teacher questions)

> Phần này là cheat sheet để trả lời câu hỏi "tại sao không X?".

### "Tại sao không dùng RDS / Aurora?"

Trade-off: managed RDS không cho install Acra ở giữa (không có hook injection ở DB engine layer). Phải đổi qua **app-level encryption** (Python `cryptography` + KMS) hoặc **TDE qua KMS** (encrypt-at-rest cho EBS volume, không phải per-column). Project muốn show "transparent encryption gateway" → cần self-managed MySQL.

→ Trong production thật, **dùng RDS Aurora + app-level encryption cho ssn/cc** đơn giản hơn nhiều. Nhưng demo này dạy nguyên lý encryption-gateway, applicable cho on-prem hoặc khi không thể dùng managed DB (PCI-DSS scope concern, data residency, …).

### "Tại sao không Vault thay vì .env?"

Scope đồ án. Vault setup mất nửa ngày — không thuộc Phase 1-7 phạm vi đã định. Production cần Vault hoặc cloud KMS, ghi rõ ở §1.3.

### "Tại sao không multi-region?"

Latency. GR sync replication không workable cross-region (>50ms RTT là bắt đầu painful). Multi-region active-active cần conflict resolution layer riêng (Vitess / Galera with multi-master + custom rules). Out of scope cho 1-host demo.

### "Tại sao Flask thay vì FastAPI / Django?"

Flask đủ cho mục đích demo (thuần render template + vài endpoint JSON). FastAPI tốt hơn cho production API (async, type hints, OpenAPI spec). Django overkill cho 1 demo nhỏ.

→ Production: chuyển sang **FastAPI + SQLAlchemy + Alembic migration**.

### "Tại sao ProxySQL thay vì MySQL Router / HAProxy / MaxScale?"

- MySQL Router cần InnoDB Cluster metadata do MySQL Shell tạo; image Shell không pullable công khai. Ghi ở problem.md.
- HAProxy là L4 TCP — không inspect SQL nên không làm DBF được.
- MaxScale là alternative valid (mature, có DBF natively). Project chọn ProxySQL vì community lớn hơn + tài liệu nhiều hơn.

### "Tại sao không TLS giữa các layer?"

Time scope. Mỗi hop TLS mất ~1 ngày setup + cert rotation procedure. Ghi rõ ở §3.4 future work.

### "Tại sao không có CI/CD?"

Solo project, push thẳng main. Production cần GitHub Actions, ghi ở §7.2.

### "Tại sao password hardcoded?"

Demo accessibility. Real app: OAuth/OIDC, ghi ở §5.2.

### "Backup ở đâu?"

Acknowledged limitation §2.2. Đường mở rộng: xtrabackup + S3 + cross-region replication.

### "Đo gì để biết HA work?"

Demo có HA pulse panel (write mỗi 2s, success vs fail timeline). Production:
- **RTO**: time-to-first-successful-write-after-kill < 10s.
- **RPO**: 0 (sync replication, không lost transaction).
- **Availability**: 99.95% (≈ 22 min downtime/month allowed).
- Đo bằng synthetic test (Datadog Synthetics / Pingdom) ping endpoint mỗi 30s.

### "Compliance attest thế nào?"

Out of scope cho 1 đồ án. Roadmap chi tiết ở §5.4 — quy mô effort là multi-month + auditor external. Project đã có architecture tương thích PCI-DSS Req 3 + 7, còn thiếu Req 4 (mTLS), Req 8 (MFA), Req 12 (policy doc).

### "Scale tới bao nhiêu user?"

Chưa benchmark. Production cần load test → capacity plan, ghi §6.2. Estimate cấp tham khảo (rule of thumb):
- 1 MySQL primary thường handle 1000-5000 QPS với hardware tốt.
- ProxySQL throughput ~10000+ QPS với 4 threads.
- Bottleneck đầu tiên thường là MySQL write (single primary), không phải proxy.

---

## 9. Đường đi đề xuất theo thứ tự ưu tiên

Nếu có 6 tháng + 1 team 3 người, đây là thứ tự:

**Tháng 1-2** — Foundation
- Migrate sang K8s (EKS / GKE managed control plane).
- Terraform IaC cho infra.
- ArgoCD cho deploy.
- mTLS end-to-end (cert-manager + service mesh).

**Tháng 3** — Reliability
- ProxySQL HA pair + cloud LB.
- Acra multi-instance + Vault keystore.
- xtrabackup pipeline + restore drill.

**Tháng 4** — Observability
- Loki + Tempo + OpenTelemetry instrumentation.
- Alertmanager → PagerDuty + Slack + runbook.
- SLO/SLI dashboard.

**Tháng 5** — Security hardening
- OAuth/OIDC + MFA.
- Vault dynamic credentials.
- Cosign + SBOM + Trivy in CI.
- NetworkPolicy zero-trust.

**Tháng 6** — Compliance prep
- PCI-DSS gap assessment với auditor.
- Pen test external + remediation.
- Policy + procedure docs.

Sau 6 tháng: ready for SOC 2 audit window + PCI-DSS SAQ-D submission.

---

## 10. Nguồn tham khảo tin được

- **MySQL Group Replication**: [official docs §18.5](https://dev.mysql.com/doc/refman/8.4/en/group-replication.html) — bible cho GR config.
- **ProxySQL**: [proxysql.com docs](https://proxysql.com/documentation/) + repo issues — config quirks cập nhật ở đó.
- **Acra**: [docs.cossacklabs.com/acra](https://docs.cossacklabs.com/acra/) — đầy đủ nhưng AcraCensor section đã cũ.
- **PCI-DSS v4.0**: [pcisecuritystandards.org](https://www.pcisecuritystandards.org/) — official requirements.
- **SRE Book** (Google): [sre.google/books](https://sre.google/books/) — SLO/SLI, error budget, postmortem culture.
- **CIS Benchmarks**: [cisecurity.org/cis-benchmarks](https://www.cisecurity.org/cis-benchmarks/) — checklist hardening MySQL / Docker / K8s.
- **OWASP API Security Top 10 2023**: [owasp.org/API-Security](https://owasp.org/API-Security/) — IDOR + BFLA + BOLA pattern.
- **Kubernetes Patterns** (O'Reilly): pattern cho StatefulSet + sidecar + operator.
- **Designing Data-Intensive Applications** (Kleppmann): replication theory + tradeoff.
