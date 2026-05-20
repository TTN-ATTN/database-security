.PHONY: help env up down restart ps logs logs-mysql logs-prom logs-grafana \
       mysql-root mysql-app \
       check-phase1 schema phase2 seed test-masking \
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
	bash scripts/check_phase1.sh

# ---------- phase 2: schema, seed & masking ----------

schema: ## Apply Phase 2 schema, masking view, and RBAC SQL
	docker exec -i dbsec-mysql mysql -uroot -p"$${MYSQL_ROOT_PASSWORD:-rootpass}" < mysql/schema.sql
	docker exec -i dbsec-mysql mysql -uroot -p"$${MYSQL_ROOT_PASSWORD:-rootpass}" < mysql/masking.sql
	docker exec -i dbsec-mysql mysql -uroot -p"$${MYSQL_ROOT_PASSWORD:-rootpass}" < mysql/rbac.sql

phase2: schema seed test-masking ## Run complete Phase 2 setup and verification

seed: ## Seed database with sample data (scripts/seed_all.py)
	python3 scripts/seed_all.py

test-masking: ## Test data masking (scripts/test_masking.sh)
	bash scripts/test_masking.sh

# ---------- cleanup ----------

clean: down ## Stop services and remove containers
	$(COMPOSE) rm -f

clean-volumes: down ## Stop services and remove containers + volumes
	$(COMPOSE) down -v
