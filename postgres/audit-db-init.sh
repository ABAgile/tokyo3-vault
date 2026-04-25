#!/usr/bin/env bash
# Sets up the audit database: creates limited roles and grants.
# Schema (audit_logs table) is managed by versioned migrations run by
# audit-consumer at startup via AUDIT_ADMIN_DATABASE_URL.
# Runs once on first postgres startup via docker-entrypoint-initdb.d/.
#
# Required env vars (set on the audit-db container):
#   AUDIT_READER_PASSWORD
#   AUDIT_WRITER_PASSWORD
set -euo pipefail

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB"   \
     -v reader_pw="$AUDIT_READER_PASSWORD" \
     -v writer_pw="$AUDIT_WRITER_PASSWORD" \
     --no-psqlrc <<'SQL'

CREATE USER vault_audit_reader WITH PASSWORD :'reader_pw';
CREATE USER vault_audit_writer WITH PASSWORD :'writer_pw';

GRANT CONNECT ON DATABASE vault_audit TO vault_audit_reader, vault_audit_writer;
GRANT USAGE   ON SCHEMA  public       TO vault_audit_reader, vault_audit_writer;

-- Default privileges apply to all tables created by vault_audit (schema owner),
-- including those created later by audit-consumer migrations.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO vault_audit_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT INSERT ON TABLES TO vault_audit_writer;

SQL
