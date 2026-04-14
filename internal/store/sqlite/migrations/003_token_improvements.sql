-- read_only: when 1, the token may only perform read operations.
ALTER TABLE tokens ADD COLUMN read_only INTEGER NOT NULL DEFAULT 0;
