## Vault — build targets
##
## Usage:
##   make build           Build both binaries to ./bin/
##   make run-server      Start the server with dev defaults
##   make keygen          Generate a VAULT_MASTER_KEY
##   make docker-build    Build Docker image
##   make docker-up       Start with docker compose (SQLite + Litestream)
##   make docker-down     Stop docker compose
##   make clean           Remove ./bin/
##   make test            Run tests
##   make help            Show this help

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

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-server build-cli clean test tidy keygen run-server help

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Compile both vaultd and vault into ./bin/
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

# Cross-compilation helpers — call as: make build-linux build-darwin build-windows
## build-linux: Cross-compile both binaries for Linux amd64
build-linux: $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vaultd-linux-amd64 $(CMD_VAULTD)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-linux-amd64  $(CMD_VAULT)
	@echo "  built Linux amd64 binaries"

## build-linux-arm64: Cross-compile both binaries for Linux arm64 (Graviton)
build-linux-arm64: $(BIN_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vaultd-linux-arm64 $(CMD_VAULTD)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-linux-arm64  $(CMD_VAULT)
	@echo "  built Linux arm64 binaries"

## build-darwin: Cross-compile both binaries for macOS arm64 (M-series)
build-darwin: $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vaultd-darwin-arm64 $(CMD_VAULTD)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/vault-darwin-arm64  $(CMD_VAULT)
	@echo "  built macOS arm64 binaries"

# ── Dev ───────────────────────────────────────────────────────────────────────

## run-server: Start vaultd with dev defaults (auto-generates key if .dev.env absent)
run-server: build-server
	@if [ ! -f .dev.env ]; then \
	    KEY=$$($(VAULT_BIN) keygen 2>/dev/null || $(BIN_DIR)/vault keygen); \
	    echo "VAULT_MASTER_KEY=$$KEY" > .dev.env; \
	    echo "VAULT_DB_PATH=vault-dev.db" >> .dev.env; \
	    echo "VAULT_ADDR=:8080" >> .dev.env; \
	    echo "  generated .dev.env (add to .gitignore!)"; \
	fi
	@export $$(cat .dev.env | xargs) && $(VAULTD_BIN)

## keygen: Print a fresh random master key
keygen: build-cli
	@$(VAULT_BIN) keygen

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

## docker-build: Build the Docker image (linux/amd64)
docker-build:
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(GIT_COMMIT) \
	  --build-arg BUILD_TIME=$(BUILD_TIME) \
	  --build-arg TARGETARCH=amd64 \
	  -t $(IMAGE_NAME):$(IMAGE_TAG) \
	  -t $(IMAGE_NAME):latest \
	  .
	@echo "  built $(IMAGE_NAME):$(IMAGE_TAG)"

## docker-build-arm64: Build the Docker image for linux/arm64 (Graviton)
docker-build-arm64:
	docker build \
	  --platform linux/arm64 \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(GIT_COMMIT) \
	  --build-arg BUILD_TIME=$(BUILD_TIME) \
	  --build-arg TARGETARCH=arm64 \
	  -t $(IMAGE_NAME):$(IMAGE_TAG)-arm64 \
	  .

## docker-push: Push image to registry (set IMAGE_NAME to your ECR repo)
docker-push: docker-build
	docker push $(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(IMAGE_NAME):latest

## docker-up: Start vaultd with docker compose (SQLite + Litestream)
docker-up:
	docker compose up -d

## docker-up-postgres: Start vaultd with Postgres backend
docker-up-postgres:
	docker compose --profile postgres up -d

## docker-down: Stop all compose services
docker-down:
	docker compose down

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

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo "Vault Makefile targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | awk -F: '{printf "  %-22s %s\n", $$1, $$2}'
