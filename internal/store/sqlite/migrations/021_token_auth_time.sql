-- See postgres/migrations/021_token_auth_time.sql for rationale. Nullable so
-- the SQLite path can add the column with a simple ALTER (existing rows fall
-- back to created_at via session middleware logic).
ALTER TABLE tokens ADD COLUMN auth_time DATETIME;
