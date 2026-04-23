# store package

`store.Store` is the single persistence interface used by all API handlers. Neither handler nor test code imports the backends directly — only `cmd/vaultd/main.go` does.

## Adding a new method

1. Add to `store.go` interface with a doc comment
2. Implement in `internal/store/postgres/postgres_<domain>.go`
3. Implement in `internal/store/sqlite/sqlite_<domain>.go`
4. Add no-op stub to `internal/testutil/mockstore/mock.go`

Steps 2–4 are the only files that need changing. Handler code imports only `store.Store`.

## Adding a migration

Name: `NNN_description.sql` (next sequential number in both `postgres/migrations/` and `sqlite/migrations/`).

Postgres supports `ALTER TABLE … ADD COLUMN`, `ALTER COLUMN … DROP NOT NULL`, `ADD CONSTRAINT`.

SQLite cannot ALTER COLUMN or ADD CONSTRAINT on existing tables — use full table recreation:

```sql
PRAGMA foreign_keys = OFF;
CREATE TABLE foo_new (…new schema…);
INSERT INTO foo_new SELECT … FROM foo;
DROP TABLE foo;
ALTER TABLE foo_new RENAME TO foo;
-- recreate indexes
PRAGMA foreign_keys = ON;
```

See `012_oidc.sql` and `014_cert_email_san.sql` for examples of each pattern.
