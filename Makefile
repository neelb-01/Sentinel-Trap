.DEFAULT_GOAL := help
COMPOSE := docker compose
DB_USER := $(shell grep -E '^POSTGRES_USER=' .env 2>/dev/null | cut -d= -f2 || echo sentinel)
DB_NAME := $(shell grep -E '^POSTGRES_DB=' .env 2>/dev/null | cut -d= -f2 || echo sentineltrap)

.PHONY: help up down restart build logs logs-tailer logs-writer ps psql redis \
        events sessions egress egress-check verify clean nuke lint fmt test

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------ lifecycle

up: ## Build and start the stack
	@test -f .env || { echo "no .env — run: cp .env.example .env"; exit 1; }
	$(COMPOSE) up -d --build
	@echo
	@echo "Decoys listening on 22, 23, 80, 8080."
	@echo "Apply the egress drop before exposing anything: sudo make egress"

down: ## Stop the stack (keeps volumes)
	$(COMPOSE) down

restart: ## Restart without rebuilding
	$(COMPOSE) restart

build: ## Rebuild images
	$(COMPOSE) build

ps: ## Show container status
	$(COMPOSE) ps

# --------------------------------------------------------------------- observe

logs: ## Follow all logs
	$(COMPOSE) logs -f

logs-tailer: ## Follow the tailer only
	$(COMPOSE) logs -f tailer

logs-writer: ## Follow the writer only
	$(COMPOSE) logs -f writer

psql: ## Open a psql shell
	$(COMPOSE) exec timescaledb psql -U $(DB_USER) -d $(DB_NAME)

redis: ## Open a redis-cli shell
	$(COMPOSE) exec redis redis-cli

events: ## Show the 20 most recent events
	@$(COMPOSE) exec -T timescaledb psql -U $(DB_USER) -d $(DB_NAME) -c \
		"SELECT ts, decoy, src_ip, action, payload->>'path' AS path \
		 FROM events ORDER BY ts DESC LIMIT 20;"

sessions: ## Show the 20 most recent sessions
	@$(COMPOSE) exec -T timescaledb psql -U $(DB_USER) -d $(DB_NAME) -c \
		"SELECT session_id, src_ip, decoy, started_at, event_count \
		 FROM sessions ORDER BY started_at DESC LIMIT 20;"

# ------------------------------------------------------------------ isolation

egress: ## Drop egress from the decoy subnet (needs root)
	sudo ./scripts/honeynet-egress.sh

egress-check: ## Show current DOCKER-USER rules
	sudo ./scripts/honeynet-egress.sh --check

verify: ## Assert a decoy cannot reach the internet
	@echo "Expecting this to FAIL (that means containment works):"
	@! $(COMPOSE) exec -T sentinel-web python -c \
		"import socket; socket.create_connection(('1.1.1.1', 53), 3)" 2>/dev/null \
		&& echo "  PASS — egress is blocked" \
		|| { echo "  FAIL — the decoy reached the internet. Run: sudo make egress"; exit 1; }

# ------------------------------------------------------------------- quality

lint: ## Lint Python
	ruff check pipeline/src decoys/sentinel-web/app

fmt: ## Format Python
	ruff format pipeline/src decoys/sentinel-web/app

test: ## Run tests
	pytest -q

# ------------------------------------------------------------------- teardown

clean: ## Remove containers and captured logs (keeps the database)
	$(COMPOSE) down
	find logs -type f ! -name '.gitkeep' -delete

nuke: ## Remove everything including the database volume
	$(COMPOSE) down -v
	find logs -type f ! -name '.gitkeep' -delete
