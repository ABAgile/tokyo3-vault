# ── Stage 1: Build Go binaries ────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

# Download deps first (cached layer unless go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build args for version stamping — override in CI with --build-arg.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

ENV MODULE=github.com/abagile/tokyo3-vault

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -ldflags="-s -w \
        -X '${MODULE}/internal/build.Version=${VERSION}' \
        -X '${MODULE}/internal/build.Commit=${COMMIT}' \
        -X '${MODULE}/internal/build.BuildTime=${BUILD_TIME}'" \
      -o /out/vaultd ./cmd/vaultd

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -ldflags="-s -w \
        -X '${MODULE}/internal/build.Version=${VERSION}' \
        -X '${MODULE}/internal/build.Commit=${COMMIT}' \
        -X '${MODULE}/internal/build.BuildTime=${BUILD_TIME}'" \
      -o /out/vault ./cmd/vault

# ── Stage 2: Runtime image ─────────────────────────────────────────────────────
FROM alpine:3.21

# ca-certificates is required for TLS connections to Postgres, NATS, and KMS.
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/vaultd /usr/local/bin/vaultd
COPY --from=builder /out/vault  /usr/local/bin/vault

# /data is used when SQLite is chosen over Postgres (VAULT_DB_PATH / AUDIT_*_DB_PATH).
VOLUME /data
EXPOSE 8443

# Default: run the API server.
# Override the subcommand to run the audit consumer instead:
#   docker run ... vaultd audit-consumer
ENTRYPOINT ["/usr/local/bin/vaultd"]
