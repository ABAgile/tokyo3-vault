## Vault — build targets
##
## Usage:
##   make build             Build vaultd + vault binaries to ./bin/
##   make run               Start vaultd with dev defaults (starts Postgres + NATS via compose)
##   make run-mtls          Start vaultd with mTLS (cert auth, no password in DSN; starts Postgres + NATS)
##   make keygen            Generate a VAULT_MASTER_KEY
##   make check             Full pre-commit sequence (fmt + test + staticcheck + gopls + govulncheck)
##   make docker-build      Build Docker image
##   make docker-up         Start with docker compose (Postgres + NATS)
##   make docker-up-mtls    Start with docker compose + mTLS overlay (auto-generates certs)
##   make docker-down       Stop docker compose (overlay-aware; safe in any mode)
##   make docker-down-all   Stop docker compose AND remove all volumes (nuclear — wipes DB/NATS state)
##   make gen-certs         Generate mTLS certs in certs/ (manual; auto-run by run-mtls/docker-up-mtls)
##   make clean             Remove ./bin/
##   make clean-all         Remove ./bin/, generated certs, and .env (full reset)
##   make test              Run tests
##   make help              Show this help

# ── Variables ─────────────────────────────────────────────────────────────────

MODULE      := github.com/abagile/tokyo3-vault
CMD_VAULTD  := ./cmd/vaultd
CMD_VAULT   := ./cmd/vault

BIN_DIR     := bin
VAULTD_BIN  := $(BIN_DIR)/vaultd
VAULT_BIN   := $(BIN_DIR)/vault

# Version/Commit/BuildTime are all read from embedded build info — no ldflags needed.
GIT_TAG     := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION     := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

LDFLAGS := -s -w

GO      := go
GOFLAGS :=

IMAGE_NAME    ?= abagile/vault
IMAGE_TAG     ?= $(VERSION)
VAULT_ADDR    ?= :8443
POSTGRES_PORT ?= 35432
NATS_PORT     ?= 34222

# Docker Compose project name (defaults to directory basename, matching Compose behaviour).
# Used to derive the shared named volume name for pre-population via tar pipe (no bind mounts).
COMPOSE_PROJECT := $(notdir $(CURDIR))
SHARED_VOLUME   := $(COMPOSE_PROJECT)_shared_data

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-server build-cli build-linux build-linux-amd64 build-darwin \
        run run-mtls keygen gen-certs \
        _gen-env _sync-pg-scripts _sync-certs \
        test test-verbose tidy vet lint check \
        docker-build docker-build-amd64 docker-push docker-up docker-up-mtls docker-down docker-down-all docker-logs \
        install clean clean-all help

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Compile vaultd + vault into ./bin/
build: build-server build-cli

## build-server: Compile only the vaultd server binary
build-server: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(VAULTD_BIN) $(CMD_VAULTD)
	@echo "  built $(VAULTD_BIN) ($(VERSION))"

## build-cli: Compile only the vault CLI binary
build-cli: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(VAULT_BIN) $(CMD_VAULT)
	@echo "  built $(VAULT_BIN) ($(VERSION))"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Cross-compilation helpers — call as: make build-linux build-darwin
## build-linux: Cross-compile both binaries for Linux arm64 (Graviton, default)
build-linux: $(BIN_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vaultd-linux-arm64 $(CMD_VAULTD)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-linux-arm64  $(CMD_VAULT)
	@echo "  built Linux arm64 binaries"

## build-linux-amd64: Cross-compile both binaries for Linux amd64
build-linux-amd64: $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vaultd-linux-amd64 $(CMD_VAULTD)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-linux-amd64  $(CMD_VAULT)
	@echo "  built Linux amd64 binaries"

## build-darwin: Cross-compile both binaries for macOS arm64 (M-series)
build-darwin: $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vaultd-darwin-arm64 $(CMD_VAULTD)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-darwin-arm64  $(CMD_VAULT)
	@echo "  built macOS arm64 binaries"

# ── Internal helpers ──────────────────────────────────────────────────────────

# Generate .env with dev defaults on first run. Used by run / run-mtls.
# DSNs use password auth; the mTLS run target overrides with cert-auth DSNs at process launch time.
_gen-env: build-server build-cli
	@if [ ! -f .env ]; then \
	    KEY=$$($(VAULT_BIN) keygen); \
	    echo "VAULT_MASTER_KEY=$$KEY"                                                                                                                                 > .env; \
	    echo "VAULT_ADDR=$(VAULT_ADDR)"                                                                                                                              >> .env; \
	    echo "POSTGRES_PORT=$(POSTGRES_PORT)"                                                                                                                        >> .env; \
	    echo "VAULT_ADMIN_DB_PASSWORD=changeme"                                                                                                                      >> .env; \
	    echo "VAULT_DB_PASSWORD=changeme"                                                                                                                            >> .env; \
	    echo "VAULT_ADMIN_DATABASE_URL=postgres://$${VAULT_ADMIN_DB_USERNAME:-vault_admin}:changeme@db.localhost:$(POSTGRES_PORT)/vault?sslmode=disable"             >> .env; \
	    echo "VAULT_DATABASE_URL=postgres://$${VAULT_DB_USERNAME:-vault_app}:changeme@db.localhost:$(POSTGRES_PORT)/vault?sslmode=disable"                          >> .env; \
	    echo "NATS_PORT=$(NATS_PORT)"                                                                                                                                >> .env; \
	    echo "VAULT_NATS_URL=nats://nats.localhost:$(NATS_PORT)"                                                                                                     >> .env; \
	    echo "VAULT_ALLOW_REGISTRATION=true"                                                                                                                         >> .env; \
	    echo ""                                                                                                                                                     >> .env; \
	    echo "# OIDC SSO via auth — paste CLIENT_ID/SECRET from \`authd\`'s /admin/clients (POST) or"                                                               >> .env; \
	    echo "# /portal/admin/clients/new. Leave both blank to keep OIDC disabled. When CLIENT_ID is"                                                               >> .env; \
	    echo "# set, run-mtls auto-defaults VAULT_OIDC_ISSUER + VAULT_OIDC_REDIRECT_URI to the values"                                                              >> .env; \
	    echo "# below — override here if your auth/vault hosts/ports differ."                                                                                      >> .env; \
	    echo "VAULT_OIDC_CLIENT_ID="                                                                                                                                 >> .env; \
	    echo "VAULT_OIDC_CLIENT_SECRET="                                                                                                                             >> .env; \
	    echo "# VAULT_OIDC_ISSUER=https://auth.localhost:8443"                                                                                                       >> .env; \
	    echo "# VAULT_OIDC_REDIRECT_URI=https://vault.localhost:8443/api/v1/auth/oidc/callback"                                                                      >> .env; \
	    echo "VAULT_OIDC_ENFORCE=false"                                                                                                                              >> .env; \
	    echo "  generated .env"; \
	fi

# Push local postgres/ scripts into shared_data:/shared/pg-scripts (no bind mount needed).
# Re-runs on every invoke so changes to init scripts are always picked up.
_sync-pg-scripts:
	@docker volume create $(SHARED_VOLUME) 2>&1 >/dev/null || true
	@tar -cf - -C postgres . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "mkdir -p /shared/pg-scripts && tar -xf - -C /shared/pg-scripts && chmod +x /shared/pg-scripts/*.sh"

# Generate leaf certs if absent, then push local certs/ + mkcert's root CA
# into shared_data:/shared/certs (root CA staged as ca.crt for compose mounts;
# removed locally after the volume copy so certs/ stays free of the CA).
_sync-certs:
	@if [ ! -f certs/vaultd-server.crt ]; then bash certs/gen.sh; fi
	@docker volume create $(SHARED_VOLUME) 2>&1 >/dev/null || true
	@cp $$(mkcert -CAROOT)/rootCA.pem certs/ca.crt
	@tar -cf - -C certs . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "mkdir -p /shared/certs && tar -xf - -C /shared/certs"
	@rm -f certs/ca.crt

# ── Dev ───────────────────────────────────────────────────────────────────────

## run: Build and start vaultd with dev defaults (auto-generates .env on first run)
run: _gen-env _sync-pg-scripts
	@docker compose up -d db nats natsbox --wait 2>/dev/null || true
	@export $$(grep -v '^#' .env | xargs) && $(VAULTD_BIN)

## run-mtls: Build and start vaultd with mTLS (cert auth; overrides DSNs — no password)
run-mtls: _gen-env _sync-pg-scripts _sync-certs
	@docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d db nats natsbox --wait 2>/dev/null || true
	@CA_PEM=$$(mkcert -CAROOT)/rootCA.pem; \
	    export $$(grep -v '^#' .env | xargs) && \
	    if [ -n "$$VAULT_OIDC_CLIENT_ID" ]; then \
	        : "$${VAULT_OIDC_ISSUER:=https://auth.localhost:8443}"; \
	        : "$${VAULT_OIDC_REDIRECT_URI:=https://vault.localhost:8443/api/v1/auth/oidc/callback}"; \
	        export VAULT_OIDC_ISSUER VAULT_OIDC_REDIRECT_URI; \
	    fi; \
	    VAULT_API_CERT=certs/vaultd-server.crt \
	    VAULT_API_KEY=certs/vaultd-server.key \
	    VAULT_API_CLIENT_CA=$$CA_PEM \
	    VAULT_WORKLOAD_CA=$$CA_PEM \
	    VAULT_ADMIN_DB_CERT=certs/vaultd-admin-db-client.crt \
	    VAULT_ADMIN_DB_KEY=certs/vaultd-admin-db-client.key \
	    VAULT_ADMIN_DATABASE_URL=postgres://$${VAULT_ADMIN_DB_USERNAME:-vault_admin}@db.localhost:$(POSTGRES_PORT)/vault?sslmode=verify-full \
	    VAULT_DB_CERT=certs/vaultd-app-db-client.crt \
	    VAULT_DB_KEY=certs/vaultd-app-db-client.key \
	    VAULT_DATABASE_URL=postgres://$${VAULT_DB_USERNAME:-vault_app}@db.localhost:$(POSTGRES_PORT)/vault?sslmode=verify-full \
	    VAULT_NATS_CERT=certs/vaultd-nats-client.crt \
	    VAULT_NATS_KEY=certs/vaultd-nats-client.key \
	    VAULT_NATS_URL=tls://nats.localhost:$(NATS_PORT) \
	    VAULT_SCIM_MTLS_SAN_DNS=$${VAULT_SCIM_MTLS_SAN_DNS:-auth.localhost} \
	    $(VAULTD_BIN)

## keygen: Print a fresh random master key
keygen: build-cli
	@$(VAULT_BIN) keygen

## gen-certs: Generate mTLS certificates for the docker compose overlay
gen-certs:
	@bash certs/gen.sh

# ── Quality ───────────────────────────────────────────────────────────────────

## test: Run all tests
test:
	$(GO) test ./... -count=1

## test-verbose: Run all tests with verbose output
test-verbose:
	$(GO) test ./... -count=1 -v

## tidy: Run go mod tidy
tidy:
	$(GO) mod tidy

## vet: Run go vet
vet:
	$(GO) vet ./...

## lint: Run staticcheck
lint:
	staticcheck ./...

## check: Full pre-commit sequence (gofmt + test + staticcheck + gopls + govulncheck)
check:
	gofmt -s -w .
	$(GO) test ./... -count=1
	staticcheck ./...
	find . -type f -name "*.go" -print0 | xargs -0 -n 100 gopls check -severity=hint
	govulncheck ./...

# ── Docker ────────────────────────────────────────────────────────────────────

## docker-build: Build the Docker image (linux/arm64, default)
docker-build:
	docker build \
	  --platform linux/arm64 \
	  --build-arg TARGETARCH=arm64 \
	  -t $(IMAGE_NAME):$(IMAGE_TAG) \
	  -t $(IMAGE_NAME):latest \
	  .
	@echo "  built $(IMAGE_NAME):$(IMAGE_TAG)"

## docker-build-amd64: Build the Docker image for linux/amd64
docker-build-amd64:
	docker build \
	  --platform linux/amd64 \
	  --build-arg TARGETARCH=amd64 \
	  -t $(IMAGE_NAME):$(IMAGE_TAG)-amd64 \
	  .

## docker-push: Push image to registry (set IMAGE_NAME to your ECR repo)
docker-push: docker-build
	docker push $(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(IMAGE_NAME):latest

## docker-up: Start vaultd with docker compose (Postgres + NATS)
docker-up: _sync-pg-scripts
	docker compose up -d

## docker-up-mtls: Start with docker compose + mTLS overlay (auto-generates certs on first run)
docker-up-mtls: _sync-pg-scripts _sync-certs
	docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d --remove-orphans

## docker-down: Stop all compose services (overlay-aware; safe to run in any mode)
docker-down:
	docker compose -f docker-compose.yml -f docker-compose.mtls.yml down

## docker-down-all: Stop services AND remove named volumes (db, NATS, shared_data)
docker-down-all:
	docker compose -f docker-compose.yml -f docker-compose.mtls.yml down -v --remove-orphans

## docker-logs: Tail vaultd logs
docker-logs:
	docker compose logs -f vaultd

# ── Install ───────────────────────────────────────────────────────────────────

## install: Install both binaries to GOPATH/bin (or ~/go/bin)
install:
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_VAULTD)
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_VAULT)
	@echo "  installed vaultd and vault"

# ── Clean ─────────────────────────────────────────────────────────────────────

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR)

## clean-all: Remove build artifacts, generated certs, and .env (full reset)
clean-all: clean
	rm -f certs/*.crt certs/*.key certs/ca.srl
	rm -f .env
	@echo "  removed certs/* and .env"

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo "vault Makefile targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | awk -F: '{printf "  %-24s %s\n", $$1, $$2}'
