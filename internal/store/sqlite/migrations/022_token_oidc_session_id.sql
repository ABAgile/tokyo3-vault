-- See postgres/migrations/022_token_oidc_session_id.sql for rationale.
ALTER TABLE tokens ADD COLUMN oidc_session_id TEXT;
CREATE INDEX IF NOT EXISTS idx_tokens_oidc_session_id ON tokens(oidc_session_id);
