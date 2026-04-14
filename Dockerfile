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

# ── Stage 2: Litestream + runtime image ──────────────────────────────────────
FROM alpine:3.21

# Install Litestream for SQLite WAL replication to S3.
# Use exec mode: litestream starts vaultd as a subprocess, replicating concurrently.
ARG LITESTREAM_VERSION=0.3.13
ARG TARGETARCH=amd64

RUN apk add --no-cache ca-certificates curl && \
    curl -fsSL \
      "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-v${LITESTREAM_VERSION}-linux-${TARGETARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin && \
    apk del curl

COPY --from=builder /out/vaultd /usr/local/bin/vaultd
COPY --from=builder /out/vault  /usr/local/bin/vault
COPY litestream.yml              /etc/litestream.yml

VOLUME /data
EXPOSE 8080

# Litestream restores the DB from S3 on first boot (if not present locally),
# then starts vaultd and streams WAL changes to S3 while it runs.
# Skip Litestream entirely by overriding the entrypoint:
#   docker run --entrypoint vaultd ...
ENTRYPOINT ["litestream", "replicate", "-config", "/etc/litestream.yml", "-exec", "vaultd"]
