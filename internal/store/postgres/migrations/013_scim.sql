-- SCIM provisioning columns on users.
ALTER TABLE users ADD COLUMN active           BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN scim_external_id TEXT;

-- SCIM bearer tokens — one token per IdP integration.
CREATE TABLE scim_tokens (
    id          TEXT        PRIMARY KEY,
    token_hash  TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Maps IdP group IDs to vault project roles.
-- Rows drive automatic project membership when SCIM pushes group membership events.
CREATE TABLE scim_group_roles (
    id           TEXT        PRIMARY KEY,
    group_id     TEXT        NOT NULL,
    display_name TEXT        NOT NULL,
    project_id   TEXT        REFERENCES projects(id) ON DELETE CASCADE,
    env_id       TEXT        REFERENCES environments(id) ON DELETE CASCADE,
    role         TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, project_id, env_id)
);
