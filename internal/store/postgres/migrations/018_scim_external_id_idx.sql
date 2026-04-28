-- Index for SCIM externalId lookups: powers `GET /scim/v2/Users?filter=externalId eq "..."`
-- and outbound-SCIM cache reconciliation in upstream IdPs.
CREATE INDEX IF NOT EXISTS users_scim_external_id_idx
    ON users(scim_external_id)
    WHERE scim_external_id IS NOT NULL;
