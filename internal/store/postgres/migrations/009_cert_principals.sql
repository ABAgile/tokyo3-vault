CREATE TABLE cert_principals (
    id          TEXT        PRIMARY KEY,
    user_id     TEXT        REFERENCES users(id) ON DELETE CASCADE,
    description TEXT        NOT NULL,
    spiffe_id   TEXT        UNIQUE NOT NULL,
    project_id  TEXT        REFERENCES projects(id) ON DELETE CASCADE,
    env_id      TEXT        REFERENCES environments(id) ON DELETE CASCADE,
    read_only   BOOLEAN     NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_cert_principals_user ON cert_principals(user_id);
