#!/usr/bin/env bash
# Generate a local CA and TLS/mTLS certs for the docker compose mTLS overlay.
# Run from the repo root:  bash certs/gen.sh
# Requires: openssl (LibreSSL on macOS works too)

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
DAYS=825

# Load .env from the repo root if present — mirrors docker compose behaviour so
# VAULT_ADMIN_DB_USERNAME / VAULT_APP_USERNAME / VAULT_AUDIT_USERNAME stay in sync with the DSNs.
REPO_ROOT="$(cd "$DIR/.." && pwd)"
if [[ -f "$REPO_ROOT/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$REPO_ROOT/.env"
  set +a
fi
ADMIN_USERNAME="${VAULT_ADMIN_DB_USERNAME:-vault_admin}"
APP_USERNAME="${VAULT_APP_USERNAME:-vault_app}"
AUDIT_USERNAME="${VAULT_AUDIT_USERNAME:-vault_audit}"

step() { printf '  %-34s' "$1..."; }
ok()   { echo "ok"; }

# ── CA ───────────────────────────────────────────────────────────────────────
step "CA"
openssl genrsa -out "$DIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days $DAYS \
  -key  "$DIR/ca.key" \
  -out  "$DIR/ca.crt" \
  -subj "/CN=vault-dev-ca" 2>/dev/null
ok

# ── Helper ───────────────────────────────────────────────────────────────────
# issue <name> <CN> <SAN-csv>
issue() {
  local name=$1 cn=$2 san=$3
  local ext
  ext=$(mktemp)
  trap "rm -f $ext" RETURN

  cat > "$ext" <<EOF
[v3]
basicConstraints     = CA:FALSE
keyUsage             = digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth, clientAuth
subjectAltName       = $san
EOF

  step "$name"
  openssl genrsa -out "$DIR/$name.key" 2048 2>/dev/null
  openssl req -new \
    -key  "$DIR/$name.key" \
    -out  "$DIR/$name.csr" \
    -subj "/CN=$cn" 2>/dev/null
  openssl x509 -req -days $DAYS \
    -in      "$DIR/$name.csr" \
    -CA      "$DIR/ca.crt" \
    -CAkey   "$DIR/ca.key" \
    -CAcreateserial \
    -out     "$DIR/$name.crt" \
    -extfile "$ext" \
    -extensions v3 2>/dev/null
  rm -f "$DIR/$name.csr"
  ok
}

# ── Server certs ─────────────────────────────────────────────────────────────
issue "vaultd-server"    "vaultd"    "DNS:vaultd,DNS:localhost,IP:127.0.0.1"
issue "nats-server"      "nats"      "DNS:nats,DNS:localhost,IP:127.0.0.1"
issue "db-server"        "db"        "DNS:db,DNS:localhost,IP:127.0.0.1"
issue "audit-db-server"  "audit-db"  "DNS:audit-db,DNS:localhost,IP:127.0.0.1"

# ── Client certs — NATS (CN = service name; transport identity only) ─────────
issue "vaultd-nats-client"      "vaultd"      "DNS:vaultd"
issue "vault-audit-nats-client" "vault-audit" "DNS:vault-audit"

# ── Client certs — PostgreSQL (CN must match the DB role for cert auth) ───────
issue "vaultd-admin-db-client"  "$ADMIN_USERNAME"  "DNS:vaultd"
issue "vaultd-app-db-client"    "$APP_USERNAME"    "DNS:vaultd"
issue "vault-audit-db-client"   "$AUDIT_USERNAME"  "DNS:vault-audit"

# ── Client certs — vault API workload identities (SPIFFE URI for principal auth) ──
issue "webapp-vaultd-workload"  "webapp"  "URI:spiffe://vault.internal/workload/webapp"

echo ""
echo "certs written to certs/"
echo "next: docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d"
