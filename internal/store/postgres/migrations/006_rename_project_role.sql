-- Rename project member role 'admin' -> 'editor' to avoid confusion with server-admin role.
UPDATE project_members SET role = 'editor' WHERE role = 'admin';

ALTER TABLE project_members DROP CONSTRAINT IF EXISTS project_members_role_check;
ALTER TABLE project_members ADD CONSTRAINT project_members_role_check CHECK(role IN ('viewer', 'editor', 'owner'));
