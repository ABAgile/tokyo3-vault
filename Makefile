## Vault — build targets
##
## Usage:
##   make build           Build all three binaries to ./bin/
##   make run-server      Start the server with dev defaults
##   make keygen          Generate a VAULT_MASTER_KEY
##   make docker-build    Build Docker image
##   make docker-up       Start with docker compose (Postgres + NATS)
##   make docker-up-mtls  Start with docker compose + mTLS overlay
##   make docker-down     Stop docker compose
##   make gen-certs       Generate mTLS certs in certs/
##   make clean           Remove ./bin/
##   make test            Run tests
##   make help            Show this help

# ── Variables ─────────────────────────────────────────────────────────────────

MODULE      := github.com/abagile/tokyo3-vault
CMD_VAULTD  := ./cmd/vaultd
CMD_VAULT   := ./cmd/vault
CMD_AUDIT   := ./cmd/vault-audit

BIN_DIR     := bin
VAULTD_BIN  := $(BIN_DIR)/vaultd
VAULT_BIN   := $(BIN_DIR)/vault
AUDIT_BIN   := $(BIN_DIR)/vault-audit

# Version/Commit/BuildTime are all read from embedded build info — no ldflags needed.
GIT_TAG     := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION     := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

LDFLAGS := -s -w

GO      := go
GOFLAGS :=

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-server build-cli build-audit clean test tidy keygen run-server help

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Compile vaultd, vault, and vault-audit into ./bin/
build: build-server build-cli build-audit

## build-server: Compile only the vaultd server binary
build-server: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(VAULTD_BIN) $(CMD_VAULTD)
	@echo "  built $(VAULTD_BIN) ($(VERSION))"

## build-cli: Compile only the vault CLI binary
build-cli: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(VAULT_BIN) $(CMD_VAULT)
	@echo "  built $(VAULT_BIN) ($(VERSION))"

## build-audit: Compile only the vault-audit pipeline binary
build-audit: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AUDIT_BIN) $(CMD_AUDIT)
	@echo "  built $(AUDIT_BIN) ($(VERSION))"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Cross-compilation helpers — call as: make build-linux build-darwin
## build-linux: Cross-compile all binaries for Linux arm64 (Graviton, default)
build-linux: $(BIN_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vaultd-linux-arm64      $(CMD_VAULTD)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-linux-arm64       $(CMD_VAULT)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-audit-linux-arm64 $(CMD_AUDIT)
	@echo "  built Linux arm64 binaries"

## build-linux-amd64: Cross-compile all binaries for Linux amd64
build-linux-amd64: $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vaultd-linux-amd64      $(CMD_VAULTD)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-linux-amd64       $(CMD_VAULT)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-audit-linux-amd64 $(CMD_AUDIT)
	@echo "  built Linux amd64 binaries"

## build-darwin: Cross-compile all binaries for macOS arm64 (M-series)
build-darwin: $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vaultd-darwin-arm64      $(CMD_VAULTD)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-darwin-arm64       $(CMD_VAULT)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-audit-darwin-arm64 $(CMD_AUDIT)
	@echo "  built macOS arm64 binaries"

# ── Dev ───────────────────────────────────────────────────────────────────────

## run-server: Start vaultd with dev defaults (auto-generates key if .dev.env absent)
run-server: build-server
	@if [ ! -f .dev.env ]; then \
	    KEY=$$($(VAULT_BIN) keygen 2>/dev/null || $(BIN_DIR)/vault keygen); \
	    echo "VAULT_MASTER_KEY=$$KEY" > .dev.env; \
	    echo "VAULT_DB_PATH=vault.db" >> .dev.env; \
	    echo "VAULT_ADDR=:8443" >> .dev.env; \
	    echo "  generated .dev.env (add to .gitignore!)"; \
	fi
	@export $$(cat .dev.env | xargs) && $(VAULTD_BIN)

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

# ── Install ───────────────────────────────────────────────────────────────────

# ── Docker ────────────────────────────────────────────────────────────────────

IMAGE_NAME  ?= abagile/vault
IMAGE_TAG   ?= $(VERSION)

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
docker-up:
	docker compose up -d

## docker-up-mtls: Start with docker compose + mTLS overlay (run gen-certs first)
docker-up-mtls:
	docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d

## docker-down: Stop all compose services
docker-down:
	docker compose down

## docker-logs: Tail vaultd logs
docker-logs:
	docker compose logs -f vaultd

# ── Install ───────────────────────────────────────────────────────────────────

## install: Install all three binaries to GOPATH/bin (or ~/go/bin)
install:
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_VAULTD)
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_VAULT)
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_AUDIT)
	@echo "  installed vaultd, vault, and vault-audit"

# ── Clean ─────────────────────────────────────────────────────────────────────

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR)

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo "Vault Makefile targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | awk -F: '{printf "  %-22s %s\n", $$1, $$2}'
