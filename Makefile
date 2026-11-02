COMPOSE = docker compose
APP_UID ?= $(shell id -u)
APP_GID ?= $(shell id -g)
export APP_UID APP_GID

.PHONY: up init start stop down logs

init:
	mkdir -p data/certificates data/deploy
	@if [ ! -f .env ]; then \
		umask 077; \
		printf 'APP_PASSWORD=%s\nAPP_ENCRYPTION_KEY=%s\n' \
			"$$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
			"$$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')" \
			> .env; \
		chmod 600 .env; \
		printf 'Created .env with a new admin password and encryption key.\n'; \
		printf 'Admin password: '; sed -n 's/^APP_PASSWORD=//p' .env; \
	fi

up: init
	$(COMPOSE) up -d --build

start:
	$(COMPOSE) start

stop:
	$(COMPOSE) stop

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f
