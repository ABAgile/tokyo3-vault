-- Add comment and a sequence-backed position to secrets.
-- The sequence guarantees unique, monotonically increasing values across concurrent inserts.
CREATE SEQUENCE IF NOT EXISTS secrets_position_seq;

ALTER TABLE secrets ADD COLUMN IF NOT EXISTS comment  TEXT   NOT NULL DEFAULT '';
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS position BIGINT NOT NULL DEFAULT nextval('secrets_position_seq');
-- Existing rows are assigned unique positions by the DEFAULT expression above.
