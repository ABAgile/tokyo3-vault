-- SCIM provisioning columns on users.
ALTER TABLE users ADD COLUMN active           INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN scim_external_id TEXT;

-- SCIM bearer tokens — one token per IdP integration.
CREATE TABLE scim_tokens (
    id          TEXT     PRIMARY KEY,
    token_hash  TEXT     NOT NULL UNIQUE,
    description TEXT     NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Maps IdP group IDs to vault project roles.
CREATE TABLE scim_group_roles (
    id           TEXT     PRIMARY KEY,
    group_id     TEXT     NOT NULL,
    display_name TEXT     NOT NULL,
    project_id   TEXT     REFERENCES projects(id) ON DELETE CASCADE,
    env_id       TEXT     REFERENCES environments(id) ON DELETE CASCADE,
    role         TEXT     NOT NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (group_id, project_id, env_id)
);
