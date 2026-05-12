-- oidc_session_id records the OP's `sid` claim from the ID token that
-- bootstrapped this vault session. Lets a future back-channel logout POST
-- from the IdP target exactly the vault tokens minted under that OP session,
-- instead of falling back to "delete all tokens for this user" (broader than
-- needed, especially with machine tokens in the table).
--
-- Nullable: non-OIDC sessions (local login + signup, machine tokens) leave
-- it empty. Back-channel logout falls back to sub-based deletion when sid
-- is unknown.
ALTER TABLE tokens ADD COLUMN oidc_session_id TEXT;
CREATE INDEX IF NOT EXISTS idx_tokens_oidc_session_id ON tokens(oidc_session_id);
