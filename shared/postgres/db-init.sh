#!/usr/bin/env bash
# Creates the app role (DML-only: SELECT/INSERT/UPDATE/DELETE, no DDL) for the
# Postgres database named by $POSTGRES_DB. Runs once on first postgres startup
# via docker-entrypoint-initdb.d/. Shared by every db in the stack
# (vault's `db`, tokyo3-auth's `auth-db`) — the database name is read from the
# environment so the same script works regardless of which DB it targets.
#
# Required env vars (set on the db container):
#   VAULT_DB_USERNAME   app role username (default: vault_app)
#   VAULT_DB_PASSWORD   app role password
set -euo pipefail

: "${VAULT_DB_USERNAME:=vault_app}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB"   \
     -v app_user="$VAULT_DB_USERNAME" \
     -v app_pw="$VAULT_DB_PASSWORD" \
     -v db_name="$POSTGRES_DB" \
     --no-psqlrc <<'SQL'

CREATE USER :"app_user" WITH PASSWORD :'app_pw';

GRANT CONNECT ON DATABASE :"db_name" TO :"app_user";
GRANT USAGE   ON SCHEMA   public     TO :"app_user";

-- Pre-grant DML on all future tables and sequences created by the migration owner (POSTGRES_USER).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";

SQL
