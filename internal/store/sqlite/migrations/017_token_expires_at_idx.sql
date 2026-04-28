CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at) WHERE expires_at IS NOT NULL;
