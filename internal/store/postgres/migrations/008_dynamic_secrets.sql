-- Dynamic secret backends, roles, and leases.
--
-- A backend holds the encrypted admin connection config for one named target
-- (e.g. a specific PostgreSQL instance). Uniqueness is (project_id, env_id, slug)
-- so multiple backends of the same type can coexist under different slugs.
--
-- A role defines SQL templates for creating and revoking ephemeral credentials.
-- Placeholders: {{name}}, {{password}}, {{expiry}}.
--
-- A lease records every issued credential pair and is never deleted;
-- revoked_at marks revocation. Backend and revocation template are denormalized
-- so leases can be revoked even after the role or backend is deleted.

CREATE TABLE dynamic_backends (
    id                   TEXT PRIMARY KEY,
    project_id           TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_id               TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    slug                 TEXT NOT NULL,
    type                 TEXT NOT NULL,
    encrypted_config     BYTEA NOT NULL,
    encrypted_config_dek BYTEA NOT NULL,
    default_ttl          INTEGER NOT NULL DEFAULT 3600,
    max_ttl              INTEGER NOT NULL DEFAULT 86400,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, env_id, slug)
);

CREATE TABLE dynamic_roles (
    id               TEXT PRIMARY KEY,
    backend_id       TEXT NOT NULL REFERENCES dynamic_backends(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    creation_tmpl    TEXT NOT NULL,
    revocation_tmpl  TEXT NOT NULL,
    ttl              INTEGER,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(backend_id, name)
);

CREATE TABLE dynamic_leases (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL,
    env_id           TEXT NOT NULL,
    backend_id       TEXT NOT NULL,
    role_id          TEXT NOT NULL,
    role_name        TEXT NOT NULL,
    username         TEXT NOT NULL,
    revocation_tmpl  TEXT NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ,
    created_by       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dynamic_leases_project_env ON dynamic_leases(project_id, env_id);
CREATE INDEX idx_dynamic_leases_active ON dynamic_leases(expires_at) WHERE revoked_at IS NULL;
