-- Align naming: scim_group_roles.group_id is the IdP-assigned upstream
-- identifier (matches users.scim_external_id semantics). Rename for clarity
-- and to parallel the new project_members.source_scim_external_id column.
-- SQLite cannot ALTER COLUMN to rename and replace a UNIQUE constraint in
-- one shot, so recreate the table per the project pattern.

PRAGMA foreign_keys = OFF;

CREATE TABLE scim_group_roles_new (
    id               TEXT     PRIMARY KEY,
    scim_external_id TEXT     NOT NULL,
    display_name     TEXT     NOT NULL,
    project_id       TEXT     REFERENCES projects(id) ON DELETE CASCADE,
    env_id           TEXT     REFERENCES environments(id) ON DELETE CASCADE,
    role             TEXT     NOT NULL,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (scim_external_id, project_id, env_id)
);

INSERT INTO scim_group_roles_new (id, scim_external_id, display_name, project_id, env_id, role, created_at)
    SELECT id, group_id, display_name, project_id, env_id, role, created_at FROM scim_group_roles;

DROP TABLE scim_group_roles;
ALTER TABLE scim_group_roles_new RENAME TO scim_group_roles;

PRAGMA foreign_keys = ON;
