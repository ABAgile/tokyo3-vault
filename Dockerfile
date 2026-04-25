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

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/vault-audit ./cmd/vault-audit

# ── Stage 2: Runtime image ─────────────────────────────────────────────────────
FROM alpine:3.21

# ca-certificates is required for TLS connections to Postgres, NATS, and KMS.
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/vaultd      /usr/local/bin/vaultd
COPY --from=builder /out/vault       /usr/local/bin/vault
COPY --from=builder /out/vault-audit /usr/local/bin/vault-audit

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/vaultd"]
