-- Align naming: scim_group_roles.group_id is the IdP-assigned upstream
-- identifier (matches users.scim_external_id semantics). Rename for clarity
-- and to parallel the new project_members.source_scim_external_id column.

ALTER TABLE scim_group_roles RENAME COLUMN group_id TO scim_external_id;

ALTER TABLE scim_group_roles DROP CONSTRAINT scim_group_roles_group_id_project_id_env_id_key;
ALTER TABLE scim_group_roles ADD CONSTRAINT scim_group_roles_scim_external_id_project_id_env_id_key
    UNIQUE (scim_external_id, project_id, env_id);
