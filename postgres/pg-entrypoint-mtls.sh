#!/bin/bash
# Wrapper entrypoint for the mTLS overlay.
# Copies the TLS private key to /tmp with postgres-compatible ownership (uid 70)
# and mode 600, then hands off to the standard docker-entrypoint.sh.
# Must run as root (which is the default before docker-entrypoint.sh drops privileges).
#
# Expected env vars (set by docker-compose.mtls.yml):
#   POSTGRES_SSL_CERT  path to server certificate PEM
#   POSTGRES_SSL_KEY   path to server private key PEM (bind-mounted; will be copied)
#   POSTGRES_SSL_CA    path to CA certificate PEM for client cert verification
set -euo pipefail

install -m 600 -o 70 -g 70 "$POSTGRES_SSL_KEY" /tmp/server.key

exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c "ssl_cert_file=$POSTGRES_SSL_CERT" \
  -c ssl_key_file=/tmp/server.key \
  -c "ssl_ca_file=$POSTGRES_SSL_CA" \
  -c hba_file=/etc/postgresql/pg_hba.conf
