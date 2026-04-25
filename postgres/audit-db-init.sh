#!/usr/bin/env bash
# Sets up the audit database schema permissions.
# Schema (audit_logs table) is managed by versioned migrations run by
# vault-audit at startup via VAULT_AUDIT_DATABASE_URL.
# Runs once on first postgres startup via docker-entrypoint-initdb.d/.
#
# The vault_audit role (POSTGRES_USER) owns the database and has full rights.
# vault-audit uses a single VAULT_AUDIT_DATABASE_URL with this credential for
# schema migrations, writes, and queries.
set -euo pipefail

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB"   \
     --no-psqlrc <<'SQL'

-- Ensure the public schema is owned by vault_audit so migrations can create tables.
ALTER SCHEMA public OWNER TO vault_audit;

SQL
