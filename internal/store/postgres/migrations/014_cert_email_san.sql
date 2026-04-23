-- Allow cert_principals to match on email SAN in addition to (or instead of) SPIFFE URI SAN.
ALTER TABLE cert_principals ALTER COLUMN spiffe_id DROP NOT NULL;
ALTER TABLE cert_principals ADD COLUMN email_san TEXT;
CREATE UNIQUE INDEX cert_principals_email_san ON cert_principals(email_san) WHERE email_san IS NOT NULL;
ALTER TABLE cert_principals ADD CONSTRAINT cert_principals_has_identifier
    CHECK (spiffe_id IS NOT NULL OR email_san IS NOT NULL);
