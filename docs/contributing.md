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

# Start with docker compose (SQLite + Litestream, or --profile postgres for Postgres)
make docker-up
make docker-up-postgres
```

Always run in order: `gofmt -s -w .` → `make test` → `staticcheck ./...` before committing.

## Project layout

```
cmd/
  vault/        CLI client entry point
  vaultd/       Server entry point (startup, env parsing, TLS config)
internal/
  api/          HTTP handlers and middleware
  auth/         Password hashing + token generation/validation
  build/        Version metadata
  crypto/       AES-256-GCM helpers, KeyProvider interface, ProjectKeyCache
  dotenv/       .env file parser
  dynamic/      Issuer interface, PostgreSQL issuer, background revoker
  model/        All data types (no logic)
  store/        Store interface
    postgres/   PostgreSQL implementation + migrations
    sqlite/     SQLite implementation + migrations (same schema)
  tlsutil/      TLS certificate loading + self-signed cert generation
docs/           Architecture and reference documentation
```

## Database migrations

Migrations live in `internal/store/postgres/migrations/` and `internal/store/sqlite/migrations/`. They are embedded into the binary at compile time via `//go:embed`.

Naming convention: `NNN_description.sql` (zero-padded 3-digit prefix). Files are sorted lexicographically and applied in order; each file is applied exactly once. The `schema_migrations` table tracks which files have been applied.

To add a migration:

1. Create `NNN_your_change.sql` in both `postgres/migrations/` and `sqlite/migrations/` — the SQL will usually differ slightly between dialects.
2. Test with `go test ./internal/store/...`.
3. Do not modify existing migration files — always add a new one.

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
4. Call `s.logAudit(r, Action..., projectID, resource)` at the end of every successful state-changing handler.
5. Add tests (table-driven where possible; see `auth_test.go` or `secrets_test.go` for patterns).

## Testing

Tests use a `mockStore` defined in `internal/api/mock_store_test.go`. For new store methods, add a field with the same signature to the mock and implement the method stub.

Integration tests (Postgres) can be run with a `VAULT_DATABASE_URL` environment variable pointing to a real database. The test suite creates and tears down its own schema.

## Known limitations

### No dynamic backend type extensibility at runtime

Backend types are registered in a compile-time map. There is no plugin system. Adding a new backend type requires modifying and redeploying the server.

### No secret rotation scheduling

Secrets are written manually (or via CI). There is no built-in cron-style rotation or expiry for static secrets. Automatic rotation must be handled externally (write a new value via the API, then restart dependent processes).

### No audit log retention policy

Audit logs grow indefinitely. There is no built-in archival or pruning. Implement retention externally: periodically copy old rows to object storage and delete from the table, or use Postgres table partitioning.

### No project PEK rotation

`vaultd migrate-keys` migrates from the server KEK to per-project PEKs (one-way, idempotent). Once a project has a PEK there is no built-in command to rotate it to a new PEK. A rotation would require: generate new PEK, rewrap all DEKs, store new `encrypted_pek` — essentially the same as migration but starting from an existing PEK. This path is not currently implemented.

### Lease revocation is not transactional

The revoker calls `issuer.Revoke()` (which runs SQL on the target database) and then calls `store.RevokeDynamicLease()`. If the server crashes between those two steps, the lease will be retried on the next sweep. This means credentials may be revoked twice — write your revocation template defensively (e.g. `DROP ROLE IF EXISTS`).

If `issuer.Revoke()` itself fails (target database unreachable), the lease is not marked revoked and the revoker will retry every 60 seconds. Credentials remain active until the target database is reachable again.

### SPIFFE ID matching is exact

`cert_principals` are matched by full SPIFFE URI equality. There is no prefix or wildcard support. Each workload identity that needs vault access must be registered individually.

### No version pruning for static secrets

Every `SetSecret` call creates a new `SECRET_VERSION` row. Old versions are never deleted. For secrets that are written frequently (e.g. rotating API keys), this can grow the `secret_versions` table indefinitely.

### `X-Forwarded-For` IP logging is not validated

The IP recorded in audit logs comes from the first `X-Forwarded-For` value or `RemoteAddr`. If vault is exposed directly to the internet (no trusted reverse proxy), clients can spoof this header to obscure their IP in audit records.

### No built-in rate limiting

Authentication endpoints (`/login`, `/signup`) have no rate limiting. Deploy behind a reverse proxy (nginx, Caddy, Cloudflare, etc.) that enforces request rate limits before traffic reaches vaultd.

## Deployment notes

### SQLite vs Postgres

SQLite is appropriate for single-node deployments where Litestream or similar replication is used for durability. For multi-instance or high-availability deployments, use Postgres. The store interface abstracts all persistence; no application logic changes are needed when switching.

### TLS certificate rotation

When `VAULT_TLS_CERT` and `VAULT_TLS_KEY` are set, the server re-reads the files on each TLS handshake when the mtime changes. Update the files in-place (e.g. via `tbot` or `certbot`) and the new certificate takes effect on the next connection — no restart required.

### KMS cost optimization

Each `ProjectKeyCache` miss triggers one KMS `Decrypt` call. With the default 5-minute TTL, a single active project generates at most 12 KMS calls per hour regardless of secret access volume. Increase `VAULT_PROJECT_KEY_CACHE_TTL` to reduce KMS costs at the expense of slower PEK rotation propagation.

### Dynamic backend security

The creation and revocation templates are SQL executed against your target database. The vault server must have network access to the target database and the admin credentials stored in the backend config must have `CREATE ROLE` / `GRANT` / `DROP ROLE` privileges (or equivalent). Use a dedicated admin account with only the minimum privileges needed to create and revoke credentials.
