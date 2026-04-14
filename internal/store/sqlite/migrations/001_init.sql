CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tokens covers both user session tokens and machine tokens.
-- user_id is NULL for machine tokens created via API key flow.
-- project_id / env_id are non-NULL for scoped machine tokens.
CREATE TABLE IF NOT EXISTS tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT,
    token_hash  TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL,
    project_id  TEXT,
    env_id      TEXT,
    expires_at  DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)    REFERENCES users(id)    ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (env_id)     REFERENCES environments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS projects (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    slug       TEXT UNIQUE NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS environments (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (project_id, slug),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- secrets holds the key identity and a pointer to the active version.
-- current_version_id is updated on every write; history lives in secret_versions.
CREATE TABLE IF NOT EXISTS secrets (
    id                 TEXT PRIMARY KEY,
    project_id         TEXT NOT NULL,
    env_id             TEXT NOT NULL,
    key                TEXT NOT NULL,
    current_version_id TEXT,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (project_id, env_id, key),
    FOREIGN KEY (project_id) REFERENCES projects(id)      ON DELETE CASCADE,
    FOREIGN KEY (env_id)     REFERENCES environments(id)  ON DELETE CASCADE
);

-- Append-only. Rows are never updated after insert.
-- encrypted_value = AES-GCM(DEK, plaintext)
-- encrypted_dek   = AES-GCM(KEK, DEK)
-- Rotating the KEK only requires re-wrapping encrypted_dek rows — not re-encrypting values.
CREATE TABLE IF NOT EXISTS secret_versions (
    id              TEXT PRIMARY KEY,
    secret_id       TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    encrypted_dek   BLOB NOT NULL,
    version         INTEGER NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      TEXT,
    FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_secret_id ON secret_versions(secret_id);
CREATE INDEX IF NOT EXISTS idx_secrets_project_env       ON secrets(project_id, env_id);
CREATE INDEX IF NOT EXISTS idx_tokens_hash               ON tokens(token_hash);
