## Vault — build targets
##
## Usage:
##   make build             Build vaultd + vault binaries to ./bin/
##   make run               Start vaultd with dev defaults (Postgres + NATS via compose)
##   make run-mtls          Start vaultd with mTLS (cert auth, no password in DSN)
##   make keygen            Generate a VAULT_MASTER_KEY
##   make check             Full pre-commit sequence (fmt + test + staticcheck + gopls + govulncheck)
##   make docker-build      Build Docker image
##   make docker-up         Bring up the full stack with tokyo3-auth as the IdP (default)
##   make docker-up-authentik  Bring up the full stack with Authentik as the IdP instead
##   make docker-up-mtls    Bring up the full stack + mTLS overlay (auto-generates certs)
##   make docker-down       Stop the stack (overlay-aware; safe in any mode)
##   make docker-down-all   Stop + remove orphan containers AND named volumes (destroys DB/NATS state)
##   make gen-certs         Generate mTLS certs in shared/certs/ (manual; auto-run elsewhere)
##   make clean             Remove ./bin/
##   make clean-all         Remove ./bin/, shared/certs/*.{crt,key,srl}, and .env (full reset)
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

IMAGE_NAME    ?= abagile/tokyo3-vault
IMAGE_TAG     ?= $(VERSION)
# VAULT_PORT is the host-side port `make run` / `run-mtls` listen on. VAULT_ADDR
# is derived so both stay in sync. In compose, vaultd listens on :443 inside
# the container (set inline on the service in docker-compose.yml).
VAULT_PORT    ?= 8443
VAULT_ADDR    ?= :$(VAULT_PORT)
POSTGRES_PORT ?= 35432
NATS_PORT     ?= 34222

# Name of the external named volume populated via tar pipe (no bind mounts).
# Declared `external: true` in docker-compose.yml so compose neither creates
# nor destroys it — `_sync-shared` is the sole owner of its lifecycle.
SHARED_VOLUME := shared_data

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-server build-cli build-linux build-linux-amd64 build-darwin \
        run run-mtls keygen gen-certs \
        _gen-env _sync-shared \
        test test-verbose tidy vet lint check \
        docker-build docker-build-amd64 docker-push docker-up docker-up-authentik docker-up-mtls docker-down docker-down-all docker-logs \
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

# Generate .env with dev defaults on first run. Used by run / run-mtls and the
# compose stack. Notable omissions:
#   - VAULT_ADDR is NOT seeded: compose's container needs :443 (Traefik
#     upstream) while `make run` listens on :$(VAULT_PORT) on the host. Set
#     inline in the run targets, not here.
#   - VAULT_ADMIN_DATABASE_URL / VAULT_DATABASE_URL / VAULT_NATS_URL are
#     likewise NOT seeded — compose builds the container-internal DSN
#     (db:5432 / nats:4222) from the password vars; `make run` / `run-mtls`
#     construct the host-side DSN (db.localhost:POSTGRES_PORT) inline.
_gen-env: build-server build-cli
	@if [ ! -f .env ]; then \
	    KEY=$$($(VAULT_BIN) keygen); \
	    AUTH_KEY=$$($(VAULT_BIN) keygen); \
	    echo "VAULT_MASTER_KEY=$$KEY"                                                                                                                                 > .env; \
	    echo "POSTGRES_PORT=$(POSTGRES_PORT)"                                                                                                                        >> .env; \
	    echo "VAULT_ADMIN_DB_PASSWORD=changeme"                                                                                                                      >> .env; \
	    echo "VAULT_DB_PASSWORD=changeme"                                                                                                                            >> .env; \
	    echo "NATS_PORT=$(NATS_PORT)"                                                                                                                                >> .env; \
	    echo "VAULT_ALLOW_REGISTRATION=true"                                                                                                                         >> .env; \
	    echo ""                                                                                                                                                     >> .env; \
	    echo "# ── OIDC SSO ──────────────────────────────────────────────────────────"                                                                              >> .env; \
	    echo "# Default IdP is tokyo3-auth at https://auth.localhost (started by"                                                                                    >> .env; \
	    echo "# \`make docker-up\`). To switch to Authentik instead, run"                                                                                            >> .env; \
	    echo "# \`make docker-up-authentik\` and override VAULT_OIDC_ISSUER below to"                                                                                >> .env; \
	    echo "# https://authentik.localhost/application/o/vault/ . Fill CLIENT_ID +"                                                                                 >> .env; \
	    echo "# SECRET after creating the OAuth client in the IdP's admin UI (see"                                                                                   >> .env; \
	    echo "# 'First-time setup' headers in docker-compose.yml)."                                                                                                  >> .env; \
	    echo "VAULT_OIDC_CLIENT_ID="                                                                                                                                 >> .env; \
	    echo "VAULT_OIDC_CLIENT_SECRET="                                                                                                                             >> .env; \
	    echo "# VAULT_OIDC_ISSUER=https://authentik.localhost/application/o/vault/"                                                                                  >> .env; \
	    echo "VAULT_OIDC_ENFORCE=false"                                                                                                                              >> .env; \
	    echo ""                                                                                                                                                     >> .env; \
	    echo "# ── tokyo3-auth (default IdP, --profile tokyo3-auth) ─────────────────"                                                                               >> .env; \
	    echo "AUTH_MASTER_KEY=$$AUTH_KEY"                                                                                                                            >> .env; \
	    echo "AUTH_ADMIN_DB_PASSWORD=$$(openssl rand -hex 16)"                                                                                                       >> .env; \
	    echo "AUTH_DB_PASSWORD=$$(openssl rand -hex 16)"                                                                                                             >> .env; \
	    echo ""                                                                                                                                                     >> .env; \
	    echo "# ── Authentik (only consumed by --profile authentik) ─────────────────"                                                                               >> .env; \
	    echo "AUTHENTIK_PG_PASSWORD=$$(openssl rand -hex 16)"                                                                                                        >> .env; \
	    echo "AUTHENTIK_SECRET_KEY=$$(openssl rand -base64 60 | tr -d '\n')"                                                                                         >> .env; \
	    echo "  generated .env"; \
	fi

# Tar-pipe the entire shared/ tree (certs/ + postgres/ + traefik/) into the
# shared_data named volume. Single source of truth for everything containers
# read under /shared. Uses a tar pipe rather than a bind mount so it works
# when `docker compose` itself runs inside a container — the daemon would
# see the OUTER host filesystem, not ours. Leaf certs are generated on first
# run if absent; mkcert's root CA is staged in as ca.crt for the mtls overlay
# mounts and cleaned up locally afterwards so shared/certs/ stays free of
# the CA.
_sync-shared: _gen-env
	@if [ ! -f shared/certs/vaultd-server.crt ]; then bash shared/certs/gen.sh; fi
	@docker volume create $(SHARED_VOLUME) 2>&1 >/dev/null || true
	@cp $$(mkcert -CAROOT)/rootCA.pem shared/certs/ca.crt
	@tar -cf - --exclude='gen.sh' -C shared . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "tar -xf - -C /shared && find /shared/postgres -name '*.sh' -exec chmod +x {} \;"
	@rm -f shared/certs/ca.crt
	@echo "  synced shared/ → /shared"

# ── Dev ───────────────────────────────────────────────────────────────────────

## run: Build and start vaultd with dev defaults (auto-generates .env on first run).
## DSNs, AUTH cert/key paths, and AUTH_ADDR are NOT read from .env — they're
## set inline to target host-side filesystem paths and port mappings
## (db.localhost / nats.localhost / shared/certs/...), so .env stays usable
## as the single source of truth for `docker-up` too (where the container
## sees /shared/certs/... and db:5432).
##
## Without VAULT_API_CERT/KEY here, vaultd would mint an ephemeral self-signed
## cert at startup instead of using the mkcert-issued one — browsers would
## then show a cert warning when hitting https://localhost:$(VAULT_PORT).
run: _sync-shared
	@docker compose up -d db nats natsbox --wait 2>/dev/null || true
	@export $$(grep -v '^#' .env | xargs) && \
	    VAULT_ADDR=$(VAULT_ADDR) \
	    VAULT_API_CERT=shared/certs/vaultd-server.crt \
	    VAULT_API_KEY=shared/certs/vaultd-server.key \
	    VAULT_ADMIN_DATABASE_URL=postgres://$${VAULT_ADMIN_DB_USERNAME:-vault_admin}:$${VAULT_ADMIN_DB_PASSWORD}@db.localhost:$(POSTGRES_PORT)/vault?sslmode=disable \
	    VAULT_DATABASE_URL=postgres://$${VAULT_DB_USERNAME:-vault_app}:$${VAULT_DB_PASSWORD}@db.localhost:$(POSTGRES_PORT)/vault?sslmode=disable \
	    VAULT_NATS_URL=nats://nats.localhost:$(NATS_PORT) \
	    $(VAULTD_BIN)

## run-mtls: Build and start vaultd with mTLS (cert auth; overrides DSNs — no password)
run-mtls: _sync-shared
	@docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d db nats natsbox --wait 2>/dev/null || true
	@CA_PEM=$$(mkcert -CAROOT)/rootCA.pem; \
	    export $$(grep -v '^#' .env | xargs) && \
	    VAULT_ADDR=$(VAULT_ADDR) \
	    VAULT_API_CERT=shared/certs/vaultd-server.crt \
	    VAULT_API_KEY=shared/certs/vaultd-server.key \
	    VAULT_WORKLOAD_CA=$$CA_PEM \
	    VAULT_ADMIN_DB_CERT=shared/certs/vaultd-admin-db-client.crt \
	    VAULT_ADMIN_DB_KEY=shared/certs/vaultd-admin-db-client.key \
	    VAULT_ADMIN_DATABASE_URL=postgres://$${VAULT_ADMIN_DB_USERNAME:-vault_admin}@db.localhost:$(POSTGRES_PORT)/vault?sslmode=verify-full \
	    VAULT_DB_CERT=shared/certs/vaultd-app-db-client.crt \
	    VAULT_DB_KEY=shared/certs/vaultd-app-db-client.key \
	    VAULT_DATABASE_URL=postgres://$${VAULT_DB_USERNAME:-vault_app}@db.localhost:$(POSTGRES_PORT)/vault?sslmode=verify-full \
	    VAULT_NATS_CERT=shared/certs/vaultd-nats-client.crt \
	    VAULT_NATS_KEY=shared/certs/vaultd-nats-client.key \
	    VAULT_NATS_URL=tls://nats.localhost:$(NATS_PORT) \
	    VAULT_SCIM_MTLS_SAN_DNS=$${VAULT_SCIM_MTLS_SAN_DNS:-auth.localhost} \
	    $(VAULTD_BIN)

## keygen: Print a fresh random master key
keygen: build-cli
	@$(VAULT_BIN) keygen

## gen-certs: Generate mTLS certificates for the docker compose overlay
gen-certs:
	@bash shared/certs/gen.sh

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

## docker-up: Bring up the full stack with tokyo3-auth as the IdP (default).
## Activates the `tokyo3-auth` profile so auth-db + auth come up; the
## `authentik` profile services stay defined-but-stopped.
docker-up: _sync-shared
	docker compose --profile tokyo3-auth up -d --build --wait --remove-orphans

## docker-up-authentik: Bring up the full stack with Authentik as the IdP instead.
## Switch flow: `make docker-down && make docker-up-authentik` (compose does
## not stop tokyo3-auth services when you flip the active profile).
docker-up-authentik: _sync-shared
	docker compose --profile authentik up -d --build --wait --remove-orphans

## docker-up-mtls: Bring up the full stack + mTLS overlay with tokyo3-auth (auto-generates certs on first run)
docker-up-mtls: _sync-shared
	docker compose --profile tokyo3-auth -f docker-compose.yml -f docker-compose.mtls.yml up -d --build --wait --remove-orphans

## docker-down: Stop all compose services (overlay- and profile-aware; safe to run in any mode)
docker-down:
	docker compose --profile tokyo3-auth --profile authentik -f docker-compose.yml -f docker-compose.mtls.yml down

## docker-down-all: Stop services AND remove named volumes (db, NATS, auth-db, authentik); shared_data is external and preserved
docker-down-all:
	docker compose --profile tokyo3-auth --profile authentik -f docker-compose.yml -f docker-compose.mtls.yml down -v --remove-orphans

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
	rm -f shared/certs/*.crt shared/certs/*.key shared/certs/ca.srl
	rm -f .env
	@echo "  removed shared/certs/*.{crt,key}, shared/certs/ca.srl, and .env"

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo "vault Makefile targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | awk -F: '{printf "  %-24s %s\n", $$1, $$2}'
