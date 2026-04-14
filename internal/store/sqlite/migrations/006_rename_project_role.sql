-- Rename project member role 'admin' -> 'editor' to avoid confusion with server-admin role.
PRAGMA foreign_keys = OFF;

CREATE TABLE project_members_new (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK(role IN ('viewer', 'editor', 'owner')),
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (project_id, user_id)
);

INSERT INTO project_members_new (project_id, user_id, role, created_at)
SELECT project_id, user_id,
    CASE WHEN role = 'admin' THEN 'editor' ELSE role END,
    created_at
FROM project_members;

DROP TABLE project_members;
ALTER TABLE project_members_new RENAME TO project_members;
CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id);

PRAGMA foreign_keys = ON;
