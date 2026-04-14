CREATE TABLE IF NOT EXISTS audit_logs (
    id         TEXT PRIMARY KEY,
    action     TEXT NOT NULL,
    actor_id   TEXT,
    project_id TEXT,
    resource   TEXT,
    metadata   TEXT,
    ip         TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_project_id ON audit_logs(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_logs(action);
