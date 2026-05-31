# ── Stage 1: Build Go binaries ────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=arm64

WORKDIR /src

# Download deps first (cached layer unless go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/vaultd ./cmd/vaultd

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/vault ./cmd/vault

# ── Stage 2: Runtime image ─────────────────────────────────────────────────────
FROM alpine:3.21

# ca-certificates is required for TLS connections to Postgres, NATS, and KMS.
# tini runs as PID 1 to reap orphaned children (e.g. the ssl_client that
# busybox-wget healthchecks orphan) and forward signals for clean shutdown.
# A bare Go PID 1 doesn't reap, so cgroup pids.current would climb forever.
RUN apk add --no-cache ca-certificates tini

COPY --from=builder /out/vaultd /usr/local/bin/vaultd
COPY --from=builder /out/vault  /usr/local/bin/vault

EXPOSE 443

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/vaultd"]
