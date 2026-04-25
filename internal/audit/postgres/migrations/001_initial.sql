CREATE TABLE audit_logs (
    id         TEXT        PRIMARY KEY,
    action     TEXT        NOT NULL,
    actor_id   TEXT,
    project_id TEXT,
    env_id     TEXT,
    resource   TEXT,
    metadata   TEXT,
    ip         TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_audit_project_id ON audit_logs(project_id);
CREATE INDEX idx_audit_env_id     ON audit_logs(env_id);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_action     ON audit_logs(action);
