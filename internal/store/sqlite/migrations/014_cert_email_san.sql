-- Allow cert_principals to match on email SAN in addition to (or instead of) SPIFFE URI SAN.
-- SQLite cannot DROP NOT NULL or ADD CONSTRAINT on an existing column, so we recreate the table.
PRAGMA foreign_keys = OFF;

CREATE TABLE cert_principals_new (
    id          TEXT     PRIMARY KEY,
    user_id     TEXT     REFERENCES users(id) ON DELETE CASCADE,
    description TEXT     NOT NULL,
    spiffe_id   TEXT     UNIQUE,
    email_san   TEXT     UNIQUE,
    project_id  TEXT     REFERENCES projects(id) ON DELETE CASCADE,
    env_id      TEXT     REFERENCES environments(id) ON DELETE CASCADE,
    read_only   INTEGER  NOT NULL DEFAULT 0,
    expires_at  DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (spiffe_id IS NOT NULL OR email_san IS NOT NULL)
);

INSERT INTO cert_principals_new
    (id, user_id, description, spiffe_id, email_san, project_id, env_id, read_only, expires_at, created_at)
SELECT  id, user_id, description, spiffe_id, NULL,      project_id, env_id, read_only, expires_at, created_at
FROM cert_principals;

DROP TABLE cert_principals;
ALTER TABLE cert_principals_new RENAME TO cert_principals;
CREATE INDEX idx_cert_principals_user ON cert_principals(user_id);

PRAGMA foreign_keys = ON;
