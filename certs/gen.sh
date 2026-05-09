#!/usr/bin/env bash
# Generate TLS/mTLS leaf certs for the docker compose mTLS overlay, signed by
# mkcert's local CA. Run from the repo root:  bash certs/gen.sh
# Requires: mkcert (auto-installed via `go install` if missing — Go environment
# must already be set up so the mkcert binary lands on PATH).
#
# Uses the abagile/mkcert fork, which adds support for setting Subject CN from
# the first hostname argument. PostgreSQL `cert` auth matches the connecting
# role against Subject CN, so each db client cert passes the role name first
# and any DNS SANs after it.
#
# `mkcert -install` adds the root CA to the OS + browser trust stores so
# vaultd's HTTPS server cert is trusted without warnings. Re-running this
# script regenerates leaf certs in place.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

# Load .env from the repo root if present — mirrors docker compose behaviour so
# VAULT_ADMIN_DB_USERNAME / VAULT_DB_USERNAME / VAULT_AUDIT_DB_USERNAME stay in sync with the DSNs.
REPO_ROOT="$(cd "$DIR/.." && pwd)"
if [[ -f "$REPO_ROOT/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$REPO_ROOT/.env"
  set +a
fi
ADMIN_USERNAME="${VAULT_ADMIN_DB_USERNAME:-vault_admin}"
APP_USERNAME="${VAULT_DB_USERNAME:-vault_app}"
AUDIT_USERNAME="${VAULT_AUDIT_DB_USERNAME:-vault_audit}"

step() { printf '  %-34s' "$1..."; }
ok()   { echo "ok"; }

# ── Ensure mkcert (abagile fork) is available ────────────────────────────────
if ! command -v mkcert >/dev/null 2>&1; then
  step "installing mkcert"
  go install github.com/abagile/mkcert@add-cn >/dev/null
  ok
fi

# Install mkcert root CA into OS + browser trust stores (idempotent — mkcert
# does not overwrite an existing CA at $(mkcert -CAROOT)).
step "mkcert -install"
mkcert -install >/dev/null 2>&1
ok

CAROOT="$(mkcert -CAROOT)"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Server cert (serverAuth + clientAuth EKU). Args after $1 are passed through;
# the fork uses the first hostname as Subject CN.
mkc_server() {
  local name=$1; shift
  step "$name"
  mkcert -cert-file "$DIR/$name.crt" -key-file "$DIR/$name.key" "$@" >/dev/null 2>&1
  ok
}

# Client cert (clientAuth-only EKU). Args after $1 are passed through; the
# fork uses the first hostname as Subject CN — for db clients this is the
# role name, for NATS clients it's the service identity, etc.
mkc_client() {
  local name=$1; shift
  step "$name"
  mkcert -client -cert-file "$DIR/$name.crt" -key-file "$DIR/$name.key" "$@" >/dev/null 2>&1
  ok
}

# ── Server certs ─────────────────────────────────────────────────────────────
# `.localhost` and any subdomain are reserved (RFC 6761) and resolve to
# 127.0.0.1 on modern systems — no /etc/hosts entries needed. The docker
# service hostname covers in-network access.
mkc_server "vaultd-server"   vaultd   vault.localhost
mkc_server "nats-server"     nats     nats.localhost
mkc_server "db-server"       db       db.localhost
mkc_server "audit-db-server" audit-db audit-db.localhost

# ── Client certs — NATS (transport identity only) ────────────────────────────
mkc_client "vaultd-nats-client"      vaultd
mkc_client "vault-audit-nats-client" vault-audit

# ── Client certs — PostgreSQL (CN must match the DB role for cert auth) ──────
# Role name first → fork sets it as Subject CN. SAN follows.
mkc_client "vaultd-admin-db-client"  "$ADMIN_USERNAME"  vaultd
mkc_client "vaultd-app-db-client"    "$APP_USERNAME"    vaultd
mkc_client "vault-audit-db-client"   "$AUDIT_USERNAME"  vault-audit

# ── Workload cert — SPIFFE URI SAN for vault API principal auth ──────────────
mkc_client "webapp-vaultd-workload" spiffe://vault.internal/workload/webapp

echo ""
echo "leaf certs written to certs/"
echo "CA: $CAROOT/rootCA.pem (mkcert root, trusted via mkcert -install)"
echo "next: docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d"
