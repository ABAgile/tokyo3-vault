-- read_only: when true, the token may only perform read operations.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS read_only BOOLEAN NOT NULL DEFAULT FALSE;
