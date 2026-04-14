CREATE TABLE IF NOT EXISTS users (
    id            TEXT        PRIMARY KEY,
    email         TEXT        UNIQUE NOT NULL,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS projects (
    id         TEXT        PRIMARY KEY,
    name       TEXT        UNIQUE NOT NULL,
    slug       TEXT        UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS environments (
    id         TEXT        PRIMARY KEY,
    project_id TEXT        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       TEXT        NOT NULL,
    slug       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, slug)
);

CREATE TABLE IF NOT EXISTS tokens (
    id         TEXT        PRIMARY KEY,
    user_id    TEXT        REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT        UNIQUE NOT NULL,
    name       TEXT        NOT NULL,
    project_id TEXT        REFERENCES projects(id) ON DELETE CASCADE,
    env_id     TEXT        REFERENCES environments(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS secrets (
    id                 TEXT        PRIMARY KEY,
    project_id         TEXT        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_id             TEXT        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    key                TEXT        NOT NULL,
    current_version_id TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, env_id, key)
);

CREATE TABLE IF NOT EXISTS secret_versions (
    id              TEXT        PRIMARY KEY,
    secret_id       TEXT        NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    encrypted_value BYTEA       NOT NULL,
    encrypted_dek   BYTEA       NOT NULL,
    version         INTEGER     NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      TEXT
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_secret_id ON secret_versions(secret_id);
CREATE INDEX IF NOT EXISTS idx_secrets_project_env       ON secrets(project_id, env_id);
CREATE INDEX IF NOT EXISTS idx_tokens_hash               ON tokens(token_hash);
