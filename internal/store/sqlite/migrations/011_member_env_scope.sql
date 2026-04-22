-- Add optional env scoping to project_members.
-- The new env_id column allows granting a user access to a single environment
-- rather than all environments in a project (analogous to token/principal scoping).
--
-- SQLite cannot ALTER TABLE to add a NOT NULL column with a DEFAULT that references
-- another table, so we recreate the table. Existing rows get env_id = NULL, which
-- preserves their project-level behaviour exactly.

PRAGMA foreign_keys = OFF;

CREATE TABLE project_members_new (
    project_id TEXT     NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    env_id     TEXT     REFERENCES environments(id) ON DELETE CASCADE,
    role       TEXT     NOT NULL CHECK(role IN ('viewer', 'editor', 'owner')),
    created_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO project_members_new (project_id, user_id, env_id, role, created_at)
    SELECT project_id, user_id, NULL, role, created_at FROM project_members;

DROP TABLE project_members;
ALTER TABLE project_members_new RENAME TO project_members;

-- Project-level uniqueness: one role per (project, user) when env_id IS NULL.
CREATE UNIQUE INDEX project_members_project_level
    ON project_members(project_id, user_id) WHERE env_id IS NULL;

-- Env-level uniqueness: one role per (project, user, env) when env_id IS NOT NULL.
CREATE UNIQUE INDEX project_members_env_level
    ON project_members(project_id, user_id, env_id) WHERE env_id IS NOT NULL;

CREATE INDEX idx_project_members_user ON project_members(user_id);

PRAGMA foreign_keys = ON;
