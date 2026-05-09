-- Track provenance of each project_members row: NULL = admin-added,
-- non-NULL = added by SCIM group sync (the value is the source group's
-- scim_external_id). Replaces the existing partial uniques with
-- provenance-aware versions so multiple SCIM groups can grant overlapping
-- access to the same (project, user [, env]) tuple without colliding.

ALTER TABLE project_members ADD COLUMN source_scim_external_id TEXT;

DROP INDEX IF EXISTS project_members_project_level;
DROP INDEX IF EXISTS project_members_env_level;

-- Admin rows: at most one per (project, user [, env]).
CREATE UNIQUE INDEX project_members_project_level_admin
    ON project_members(project_id, user_id)
    WHERE env_id IS NULL AND source_scim_external_id IS NULL;
CREATE UNIQUE INDEX project_members_env_level_admin
    ON project_members(project_id, user_id, env_id)
    WHERE env_id IS NOT NULL AND source_scim_external_id IS NULL;

-- SCIM rows: one per (project, user [, env], source group). Different SCIM
-- groups granting overlapping access produce distinct rows.
CREATE UNIQUE INDEX project_members_project_level_scim
    ON project_members(project_id, user_id, source_scim_external_id)
    WHERE env_id IS NULL AND source_scim_external_id IS NOT NULL;
CREATE UNIQUE INDEX project_members_env_level_scim
    ON project_members(project_id, user_id, env_id, source_scim_external_id)
    WHERE env_id IS NOT NULL AND source_scim_external_id IS NOT NULL;

-- Help the diff-based sync delete (rows for a given source group) and the
-- max-merge read aggregation.
CREATE INDEX IF NOT EXISTS idx_project_members_source_scim_external_id
    ON project_members(source_scim_external_id)
    WHERE source_scim_external_id IS NOT NULL;
