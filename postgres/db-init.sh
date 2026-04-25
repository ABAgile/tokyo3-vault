#!/usr/bin/env bash
# Creates vault_app (SELECT/INSERT/UPDATE/DELETE, no DDL) for the main vault database.
# Runs once on first postgres startup via docker-entrypoint-initdb.d/.
#
# Required env vars (set on the db container):
#   VAULT_APP_PASSWORD
set -euo pipefail

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB"   \
     -v app_pw="$VAULT_APP_PASSWORD" \
     --no-psqlrc <<'SQL'

CREATE USER vault_app WITH PASSWORD :'app_pw';

GRANT CONNECT ON DATABASE vault TO vault_app;
GRANT USAGE   ON SCHEMA  public TO vault_app;

-- Pre-grant DML on all future tables and sequences created by vault (the migration owner).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO vault_app;

SQL
