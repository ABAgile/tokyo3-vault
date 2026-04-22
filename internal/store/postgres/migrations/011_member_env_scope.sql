-- Add optional env scoping to project_members.
-- Existing rows keep env_id = NULL (project-level access, unchanged).

ALTER TABLE project_members
    ADD COLUMN env_id TEXT REFERENCES environments(id) ON DELETE CASCADE;

ALTER TABLE project_members DROP CONSTRAINT project_members_pkey;

-- Project-level uniqueness: one role per (project, user) when env_id IS NULL.
CREATE UNIQUE INDEX project_members_project_level
    ON project_members(project_id, user_id) WHERE env_id IS NULL;

-- Env-level uniqueness: one role per (project, user, env) when env_id IS NOT NULL.
CREATE UNIQUE INDEX project_members_env_level
    ON project_members(project_id, user_id, env_id) WHERE env_id IS NOT NULL;
