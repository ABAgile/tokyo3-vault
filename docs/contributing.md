# Contributing & Development

## Development setup

**Prerequisites:** Go 1.22+, Docker (for Postgres integration tests)

```bash
# Build both binaries into ./bin/
make build

# Run all tests (SQLite; no external deps)
make test                        # go test ./... -count=1
make test-verbose                # with -v

# Static analysis
staticcheck ./...

# Format
gofmt -s -w .

# Start a local server (auto-generates VAULT_MASTER_KEY + SQLite on first run)
make run-server

# Start with docker compose (Postgres + NATS + vault-audit)
make docker-up

# mTLS overlay (generates certs first, then brings up with mutual TLS)
bash certs/gen.sh
make docker-up-mtls
```

Always run in order: `gofmt -s -w .` → `make test` → `staticcheck ./...` before committing.

## Project layout

```
cmd/
  vault/        CLI client entry point
  vaultd/       Server entry point (startup, env parsing, TLS config)
  vault-audit/  Standalone audit pipeline — consume (NATS→DB) and query subcommands
internal/
  api/          HTTP handlers and middleware
  audit/        Audit pipeline — Entry, Sink, JetStreamSink, Store interface
    postgres/   Audit DB PostgreSQL backend (Open, Migrate, UpsertAuditLog, ListAuditLogs) + migrations/
    sqlite/     Audit DB SQLite backend (Open, ensureSchema inline)
  auth/         Password hashing + token generation/validation
  build/        Version metadata
  crypto/       AES-256-GCM helpers, KeyProvider interface, ProjectKeyCache
  envfile/      .env file format parser/serializer for bulk secret upload and download
  dynamic/      Issuer interface, PostgreSQL issuer, background revoker
  model/        All data types (no logic)
  store/        Store interface
    postgres/   PostgreSQL implementation + migrations
    sqlite/     SQLite implementation + migrations (same schema)
  tlsutil/      TLS certificate loading + self-signed cert generation
certs/          gen.sh — generates CA + server/client certs for the mTLS overlay
postgres/       DB init scripts (role creation; schema managed by migrations)
docs/           Architecture and reference documentation
```

## Database migrations

### Main vault DB

Migrations live in `internal/store/postgres/migrations/` and `internal/store/sqlite/migrations/`. They are embedded into the binary at compile time via `//go:embed` and run at `vaultd serve` startup with the admin credential (`VAULT_ADMIN_DATABASE_URL`).

Naming convention: `NNN_description.sql` (zero-padded 3-digit prefix). Files are sorted lexicographically and applied in order; each file is applied exactly once. The `schema_migrations` table tracks which files have been applied.

To add a migration:

1. Create `NNN_your_change.sql` in both `postgres/migrations/` and `sqlite/migrations/` — the SQL will usually differ slightly between dialects.
2. Test with `go test ./internal/store/...`.
3. Do not modify existing migration files — always add a new one.

### Audit DB

Audit DB migrations live in `internal/audit/postgres/migrations/` (Postgres only — the SQLite dev path handles schema inline via `ensureSchema`). They are embedded into the `internal/audit/postgres` package and run by `vault-audit consume` at startup using `VAULT_AUDIT_DATABASE_URL` (the `vault_audit` owner role).

Role setup (users, grants) is handled once at postgres first-start by `postgres/audit-db-init.sh`. Schema (tables, indexes) is owned by the versioned migration files.

## Adding a new dynamic backend type

1. Create `internal/dynamic/yourtype.go` implementing the `Issuer` interface:

```go
type Issuer interface {
    Issue(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend,
          role *model.DynamicRole, ttl time.Duration) (username, password string, expiresAt time.Time, err error)
    Revoke(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend,
           revocationTmpl, username string) error
}
```

2. Register the type in `internal/dynamic/issuer.go`:

```go
var registry = map[string]Issuer{
    "postgresql": &PostgresIssuer{},
    "yourtype":   &YourIssuer{},
}
```

3. Define a config struct for your backend. The config is serialized as JSON, encrypted with AES-256-GCM under the project key, and stored in `dynamic_backends.encrypted_config`. Decrypt it in `Issue` and `Revoke` via `crypto.DecryptSecret`.

4. Update API validation in `internal/api/dynamic.go` — `handleSetDynamicBackend` calls `dynamic.Get(req.Type)` to validate the type string.

5. Document the expected `creation_tmpl` and `revocation_tmpl` format for operators.

## Adding a new store backend

Implement `internal/store/store.go`'s `Store` interface (about 40 methods). See `internal/store/sqlite/` for the simplest reference implementation. Wire it up in `cmd/vaultd/main.go`'s `openStore()`.

## Adding a new API route

1. Add handler(s) to the appropriate file in `internal/api/` (or create a new file).
2. Register the route in `internal/api/server.go`'s `Routes()` method — all protected routes must be wrapped with `s.auth(...)`.
3. Add audit log constant(s) to `internal/api/audit.go`.
4. Call the appropriate audit helper and **check the error** (fail-closed — if the audit publish fails the request must not complete):
   ```go
   // Non-env-scoped actions (auth, users, tokens, members, certs, projects):
   if err := s.logAudit(r, ActionXxx, projectID, resource); err != nil {
       writeError(w, http.StatusInternalServerError, "audit unavailable")
       return
   }
   // Env-scoped actions (secrets, dynamic backends/roles/leases):
   if err := s.logAuditEnv(r, ActionXxx, projectID, envID, resource, metadata); err != nil {
       writeError(w, http.StatusInternalServerError, "audit unavailable")
       return
   }
   ```
5. Add tests (table-driven where possible; see `auth_test.go` or `secrets_test.go` for patterns).

## Testing

Tests use a `mockStore` defined in `internal/api/mock_store_test.go`. For new store methods, add a field with the same signature to the mock and implement the method stub.

Integration tests (Postgres) can be run with a `VAULT_DATABASE_URL` environment variable pointing to a real database. The test suite creates and tears down its own schema.

## Deployment notes

### Deployment modes

Vault supports three standard configurations. Pick one key provider (`VAULT_MASTER_KEY` or `VAULT_KMS_KEY_ID`) and one store backend (SQLite or Postgres); the sections below show the minimal `.env` for each mode.

#### Mode 1 — Local dev: SQLite + master key

No external dependencies. `make run-server` auto-generates this file on first run.

```
VAULT_MASTER_KEY=<64-char hex>   # vault keygen
VAULT_DB_PATH=vault.db
VAULT_ADDR=:8443
```

TLS: self-signed cert is generated automatically (not for production).
Audit: no-op sink (`VAULT_NATS_URL` unset; server logs a warning).

---

#### Mode 2 — Postgres with password auth

Standard production setup: Postgres for the main store and audit DB, NATS for the audit pipeline, AWS KMS for key management.

```
# Key provider
VAULT_KMS_KEY_ID=alias/vault-prod

# Main DB (admin runs schema migrations; app is DML-only)
VAULT_ADMIN_DATABASE_URL=postgres://vault_admin:<admin-pw>@db:5432/vault
VAULT_DATABASE_URL=postgres://vault_app:<app-pw>@db:5432/vault

# Server TLS
VAULT_TLS_CERT=/etc/vault/tls.crt
VAULT_TLS_KEY=/etc/vault/tls.key

# Audit sink (vaultd publisher)
VAULT_NATS_URL=nats://nats:4222

# vault-audit (separate process)
VAULT_AUDIT_NATS_URL=nats://nats:4222
VAULT_AUDIT_DATABASE_URL=postgres://vault_audit:<audit-pw>@auditdb:5432/vault_audit
```

The `docker-compose.yml` ships a reference implementation of this mode.

---

#### Mode 3 — Postgres with mTLS cert auth

Replaces all password credentials with client certificates for vault→Postgres and NATS connections. Typically deployed with `tbot` managing certificate rotation.

```
# Key provider
VAULT_KMS_KEY_ID=alias/vault-prod

# Main DB — client cert replaces password in the DSN
VAULT_ADMIN_DATABASE_URL=postgres://vault_admin@db:5432/vault?sslmode=verify-full
VAULT_ADMIN_DB_CERT=/etc/vault/db-admin.crt
VAULT_ADMIN_DB_KEY=/etc/vault/db-admin.key
VAULT_ADMIN_DB_CA=/etc/vault/db-ca.crt

VAULT_DATABASE_URL=postgres://vault_app@db:5432/vault?sslmode=verify-full
VAULT_DB_CERT=/etc/vault/db-app.crt
VAULT_DB_KEY=/etc/vault/db-app.key
VAULT_DB_CA=/etc/vault/db-ca.crt

# Server TLS + optional inbound mTLS from workloads (enables SPIFFE auth)
VAULT_TLS_CERT=/etc/vault/tls.crt
VAULT_TLS_KEY=/etc/vault/tls.key
VAULT_TLS_CLIENT_CA=/etc/vault/client-ca.crt

# Audit sink over mTLS
VAULT_NATS_URL=tls://nats:4222
VAULT_NATS_CERT=/etc/vault/nats.crt
VAULT_NATS_KEY=/etc/vault/nats.key
VAULT_NATS_CA=/etc/vault/nats-ca.crt

# vault-audit (separate process)
VAULT_AUDIT_NATS_URL=tls://nats:4222
VAULT_AUDIT_NATS_CERT=/etc/vault/audit-nats.crt
VAULT_AUDIT_NATS_KEY=/etc/vault/audit-nats.key
VAULT_AUDIT_NATS_CA=/etc/vault/nats-ca.crt

VAULT_AUDIT_DATABASE_URL=postgres://vault_audit@auditdb:5432/vault_audit?sslmode=verify-full
VAULT_AUDIT_DB_CERT=/etc/vault/audit-db.crt
VAULT_AUDIT_DB_KEY=/etc/vault/audit-db.key
VAULT_AUDIT_DB_CA=/etc/vault/db-ca.crt
```

The `docker-compose.mtls.yml` overlay ships a reference implementation of this mode. Run `bash certs/gen.sh` to generate development certificates, then `make docker-up-mtls`.

---

### SQLite vs Postgres

SQLite is appropriate for single-node development or small deployments with external backup. For multi-instance or high-availability deployments, use Postgres. The store interface abstracts all persistence; no application logic changes are needed when switching.

The audit DB is always Postgres in production (set `VAULT_AUDIT_DATABASE_URL`). The SQLite fallback (`VAULT_AUDIT_DB_PATH`) is for local development only — `vault-audit consume`'s `ensureSchema` handles schema creation automatically for SQLite, so no migrations directory is needed.

### TLS certificate rotation

When `VAULT_TLS_CERT` and `VAULT_TLS_KEY` are set, the server re-reads the files on each TLS handshake when the mtime changes. Update the files in-place (e.g. via `tbot` or `certbot`) and the new certificate takes effect on the next connection — no restart required.

### KMS cost optimization

Each `ProjectKeyCache` miss triggers one KMS `Decrypt` call. With the default 5-minute TTL, a single active project generates at most 12 KMS calls per hour regardless of secret access volume. Increase `VAULT_PROJECT_KEY_CACHE_TTL` to reduce KMS costs at the expense of slower PEK rotation propagation.

### Dynamic backend security

The creation and revocation templates are SQL executed against your target database. The vault server must have network access to the target database and the admin credentials stored in the backend config must have `CREATE ROLE` / `GRANT` / `DROP ROLE` privileges (or equivalent). Use a dedicated admin account with only the minimum privileges needed to create and revoke credentials.

## Known limitations

### No dynamic backend type extensibility at runtime

Backend types are registered in a compile-time map. There is no plugin system. Adding a new backend type requires modifying and redeploying the server.

### Audit DB projection grows indefinitely

The NATS JetStream `AUDIT` stream has built-in 400-day retention (`StreamMaxAge`), satisfying PCI-DSS 10.5. However, the queryable audit DB populated by `vault-audit consume` has no pruning. Implement retention externally: periodically delete rows older than your retention window, copy them to object storage first, or use Postgres table partitioning.

### Lease revocation is not transactional

The revoker calls `issuer.Revoke()` (which runs SQL on the target database) and then calls `store.RevokeDynamicLease()`. If the server crashes between those two steps, the lease will be retried on the next sweep. This means credentials may be revoked twice — write your revocation template defensively (e.g. `DROP ROLE IF EXISTS`).

If `issuer.Revoke()` itself fails (target database unreachable), the lease is not marked revoked and the revoker will retry every 60 seconds. Credentials remain active until the target database is reachable again.

### SPIFFE ID matching is exact

`cert_principals` are matched by full SPIFFE URI equality. There is no prefix or wildcard support. Each workload identity that needs vault access must be registered individually.

