.PHONY: help env up down restart ps logs logs-mysql logs-prom logs-grafana \
       mysql-root mysql-app \
       check-phase1 schema phase2 seed test-masking \
       audit-traffic parse-audit proxysql-audit check-phase3 phase3 tail-general tail-slow \
       proxysql-setup dbf-test acra-keys acra-up acra-down enc-test check-phase4 phase4 \
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

# ---------- cleanup ----------

clean: down ## Stop services and remove containers
	$(COMPOSE) rm -f

clean-volumes: down ## Stop services and remove containers + volumes
	$(COMPOSE) down -v
