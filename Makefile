.PHONY: help env up down restart ps logs logs-mysql logs-prom logs-grafana \
       mysql-root mysql-app \
       check-phase1 schema phase2 seed test-masking \
       audit-traffic parse-audit proxysql-audit check-phase3 phase3 tail-general tail-slow \
       proxysql-setup dbf-test acra-keys acra-up acra-down enc-test check-phase4 phase4 \
       load-test stress-conn check-phase5 phase5 \
       scan-schema scan-data check-phase6 phase6 \
       chain-up chain-down chain-verify ha-bootstrap ha-verify ha-failover ha-down \
       full-up full-verify regression \
       classify-apply classify-verify self-service-demo ha-rw-demo \
       demo-up demo-clean demo-clean-all \
       clean clean-volumes \
       venv pip-install

SHELL  := /bin/bash
COMPOSE := docker compose

# ---------- help ----------

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------- environment ----------

env: ## Create .env from .env.example (no-op if .env exists)
	@test -f .env && echo ".env already exists" || (cp .env.example .env && echo ".env created from .env.example")

venv: ## Create Python virtual environment
	python3 -m venv .venv
	@echo "Activate with: source .venv/bin/activate"

pip-install: ## Install Python dependencies from requirements.txt
	pip install -r requirements.txt

# ---------- compose lifecycle ----------

up: env ## Start all services
	$(COMPOSE) up -d

down: ## Stop all services
	$(COMPOSE) down

restart: ## Restart all services
	$(COMPOSE) restart

ps: ## Show service status
	$(COMPOSE) ps

logs: ## Tail all service logs
	$(COMPOSE) logs -f --tail=100

logs-mysql: ## Tail MySQL logs
	$(COMPOSE) logs -f --tail=100 mysql

logs-prom: ## Tail Prometheus logs
	$(COMPOSE) logs -f --tail=100 prometheus

logs-grafana: ## Tail Grafana logs
	$(COMPOSE) logs -f --tail=100 grafana

# ---------- mysql shortcuts ----------

mysql-root: ## Open MySQL CLI as root
	docker exec -it dbsec-mysql mysql -uroot -p"$${MYSQL_ROOT_PASSWORD:-rootpass}"

mysql-app: ## Open MySQL CLI as appuser
	docker exec -it dbsec-mysql mysql -u"$${MYSQL_APP_USER:-appuser}" -p"$${MYSQL_APP_PASSWORD:-apppass}" "$${MYSQL_DATABASE:-testdb}"

# ---------- phase 1 ----------

check-phase1: ## Run Phase 1 baseline verification
	bash scripts/phase1_check.sh

# ---------- phase 2: schema, seed & masking ----------

schema: ## Apply Phase 2 schema, masking view, and RBAC SQL
	docker exec -i dbsec-mysql mysql -uroot -p"$${MYSQL_ROOT_PASSWORD:-rootpass}" < mysql/schema.sql
	docker exec -i dbsec-mysql mysql -uroot -p"$${MYSQL_ROOT_PASSWORD:-rootpass}" < mysql/masking.sql
	docker exec -i dbsec-mysql mysql -uroot -p"$${MYSQL_ROOT_PASSWORD:-rootpass}" < mysql/rbac.sql

phase2: schema seed test-masking ## Run complete Phase 2 setup and verification

seed: ## Seed database with sample data (scripts/phase2_seed_all.py)
	python3 scripts/phase2_seed_all.py

test-masking: ## Test data masking (scripts/phase2_test_masking.sh)
	bash scripts/phase2_test_masking.sh

# ---------- phase 3: active monitor ----------

audit-traffic: ## Generate audit-worthy queries to populate MySQL logs
	python3 scripts/phase3_generate_audit_queries.py

parse-audit: ## Parse general.log + slow.log into JSON/CSV evidence
	python3 scripts/phase3_parse_audit_log.py

proxysql-audit: ## (Phase 4 source) Collect ProxySQL query-digest + rule-hit audit
	python3 scripts/phase3_collect_proxysql_audit.py

check-phase3: ## Run Phase 3 active-monitor verification end-to-end
	bash scripts/phase3_check.sh

phase3: check-phase3 ## Alias for check-phase3

tail-general: ## Tail MySQL general log
	tail -f logs/mysql/general.log

tail-slow: ## Tail MySQL slow query log
	tail -f logs/mysql/slow.log

# ---------- phase 4: database firewall (ProxySQL) + Acra encryption ----------

proxysql-setup: ## Load ProxySQL DBF deny rules into the running ProxySQL
	bash scripts/phase4_proxysql_setup.sh

dbf-test: ## Run the ProxySQL DBF allow/deny behavior test
	python3 scripts/phase4_dbf_test.py

acra-keys: ## Generate the Acra keystore (writes ACRA_MASTER_KEY to .env)
	bash scripts/phase4_acra_keys.sh

acra-up: ## Start the optional acra-server (transparent encryption eval path)
	$(COMPOSE) --profile acra up -d acra-server

acra-down: ## Stop the acra-server
	$(COMPOSE) --profile acra stop acra-server

enc-test: ## Run the Acra transparent encryption round-trip test
	python3 scripts/phase4_encryption_test.py

check-phase4: ## Run Phase 4 verification (DBF mandatory, Acra if running)
	bash scripts/phase4_check.sh

phase4: proxysql-setup check-phase4 ## Set up DBF rules and run Phase 4 verification

# ---------- phase 5: performance monitoring ----------

load-test: ## Run sustained mixed query load (60s default)
	python3 scripts/phase5_generate_load.py

stress-conn: ## Run connection stress test (100 connections default)
	python3 scripts/phase5_stress_connections.py

check-phase5: ## Run Phase 5 performance monitoring verification end-to-end
	bash scripts/phase5_check.sh

phase5: check-phase5 ## Alias for check-phase5

# ---------- phase 6: sensitive data discovery ----------

scan-schema: ## Scan INFORMATION_SCHEMA for sensitive column names
	python3 scripts/phase6_scan_schema.py

scan-data: ## Scan sample rows for PII patterns (email/phone/card/SSN)
	python3 scripts/phase6_scan_data_patterns.py

check-phase6: ## Run Phase 6 sensitive data discovery verification end-to-end
	bash scripts/phase6_check.sh

phase6: check-phase6 ## Alias for check-phase6

# ---------- phase 7: chained data path + High Availability ----------

chain-up: ## Phase 7: chained path Client->ProxySQL->Acra->MySQL (needs acra-keys)
	bash scripts/phase7_chain_up.sh

chain-down: ## Phase 7: revert to default direct path Client->ProxySQL->MySQL
	bash scripts/phase7_chain_down.sh

chain-verify: ## Phase 7: verify chained path (DBF deny + Acra encrypt on one path)
	python3 scripts/phase7_chain_verify.py

ha-bootstrap: ## Phase 7: bootstrap 3-node GR cluster + ProxySQL GR router
	bash scripts/phase7_ha_bootstrap.sh

ha-verify: ## Phase 7: verify HA cluster health + router primary tracking
	bash scripts/phase7_ha_verify.sh

ha-failover: ## Phase 7: kill primary, prove cluster re-elects + router reroutes
	python3 scripts/phase7_ha_failover.py

ha-rw-demo: ## Phase 7: prove R/W split (writes->primary, reads->secondaries) via ha-router
	python3 scripts/phase7_ha_rw_demo.py

ha-down: ## Phase 7: tear down HA cluster + router (base stack untouched)
	bash scripts/phase7_ha_down.sh

full-up: ## Phase 7: full path ProxySQL->Acra->ha-router->Cluster
	bash scripts/phase7_full_up.sh

full-verify: ## Phase 7: verify full integrated path (DBF + encrypt + HA)
	python3 scripts/phase7_full_verify.py

regression: ## Phase 7: confirm Phases 1-6 still pass in default mode
	bash scripts/phase7_regression.sh

# ---------- phase 7.5: data classification (3-tier: encrypt / mask / clear) ----------

classify-apply: ## Phase 7.5: migrate schema + Acra/ProxySQL config + encrypt ssn/cc in place
	bash scripts/phase7_5_apply.sh

classify-verify: ## Phase 7.5: verify support=masked, fraud=decrypted, DBA=ciphertext, self=own-row
	python3 scripts/phase7_5_verify.py

self-service-demo: ## Phase 7: customer reads own raw PII via stored-procedure gate
	python3 scripts/phase7_self_service_demo.py

# ---------- web demo UI ----------

demo-up: ## Launch the web demo UI (Flask) at http://127.0.0.1:5000
	python3 demo/app.py

demo-clean: ## Safe cleanup: kill Flask + remove __pycache__ + truncate demo DB rows
	bash scripts/cleanup_demo_artifacts.sh --demo-data

demo-clean-all: ## Full cleanup: above + truncate logs + tear down HA cluster (~1.5GB freed)
	bash scripts/cleanup_demo_artifacts.sh --all

# ---------- cleanup ----------

clean: down ## Stop services and remove containers
	$(COMPOSE) rm -f

clean-volumes: down ## Stop services and remove containers + volumes
	$(COMPOSE) down -v
