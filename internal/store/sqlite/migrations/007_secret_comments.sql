-- Add comment to secrets.
-- Insertion order is tracked via SQLite's built-in rowid — no extra column needed.
ALTER TABLE secrets ADD COLUMN comment TEXT NOT NULL DEFAULT '';
