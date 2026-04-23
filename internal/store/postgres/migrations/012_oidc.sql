-- Make password_hash nullable (OIDC users have no local password).
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- OIDC identity columns — both NULL for local accounts.
ALTER TABLE users ADD COLUMN oidc_issuer  TEXT;
ALTER TABLE users ADD COLUMN oidc_subject TEXT;

-- Unique index prevents one IdP identity from being linked to two vault users.
-- Partial index (WHERE oidc_subject IS NOT NULL) keeps local accounts out of the index.
CREATE UNIQUE INDEX users_oidc_identity
    ON users (oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL;
