-- Make password_hash nullable and add OIDC identity columns.
-- SQLite cannot ALTER COLUMN, so we recreate the table.

PRAGMA foreign_keys = OFF;

CREATE TABLE users_new (
    id            TEXT     PRIMARY KEY,
    email         TEXT     UNIQUE NOT NULL,
    password_hash TEXT,
    role          TEXT     NOT NULL DEFAULT 'member',
    oidc_issuer   TEXT,
    oidc_subject  TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users_new (id, email, password_hash, role, created_at)
    SELECT id, email, password_hash, role, created_at FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Prevents one IdP identity from being linked to two vault users.
CREATE UNIQUE INDEX users_oidc_identity
    ON users (oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL;

PRAGMA foreign_keys = ON;
