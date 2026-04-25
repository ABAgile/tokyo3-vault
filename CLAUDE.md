# Vault — agent orientation

## What this is
Self-hosted secrets manager. Stores encrypted secrets, issues short-lived dynamic database credentials, handles user auth (local, OIDC, SCIM, mTLS). Single HTTPS API server (`vaultd`) + thin CLI (`vault`).

## Layout

```
cmd/vaultd/          server binary — startup, TLS, env config, audit-consumer subcommand
cmd/vault/           CLI client (Cobra); reads ~/.vault/config.json
internal/api/        HTTP handlers (one file per resource type)
internal/audit/      audit pipeline — Sink, JetStreamSink, DB, Entry, Migrate
internal/audit/migrations/  versioned SQL migrations for the audit DB (Postgres)
internal/auth/       token hashing, issuance, validation
internal/crypto/     KEK/PEK/DEK key hierarchy, KMS/local providers
internal/dynamic/    dynamic credential issuance + background revoker
internal/model/      all shared types (one file)
internal/oidc/       OIDC provider wrapper (go-oidc/v3 + oauth2)
internal/store/      store.Store interface
internal/store/postgres/   Postgres backend — split by domain (see below)
internal/store/sqlite/     SQLite backend  — split by domain (see below)
internal/testutil/mockstore/  shared Stub for test mocks
internal/tlsutil/    TLS helpers (hot-reload, self-signed, cert pools)
certs/               gen.sh — generates CA + server/client certs for the mTLS overlay
postgres/            DB init scripts: db-init.sh (vault_app role), audit-db-init.sh (audit roles)
docs/                architecture.md, contributing.md, data-flows.md, er-diagram.md,
                     oidc-sso-design.md, security.md
```

## Store backend file layout (postgres + sqlite mirror each other)

| File | Domain |
|------|--------|
| `postgres.go` / `sqlite.go` | DB struct, `Migrate` (admin/DDL), `Open`/`OpenWithTLS` (runtime), Close, isUnique |
| `*_users.go` | userCols, scanUser, all User methods |
| `*_tokens.go` | Token CRUD + ListTokensWithAccess |
| `*_projects.go` | Projects, ProjectMembers, Environments, project keys |
| `*_secrets.go` | Secrets, SecretVersions |
| `*_dynamic.go` | DynamicBackends, DynamicRoles, DynamicLeases |
| `*_scim.go` | SCIMTokens, SCIMGroupRoles |
| `*_certs.go` | CertPrincipals (scanCertPrincipal helper) |

## Key invariants

- **Main vault DB migrations**: numbered `NNN_description.sql` in `internal/store/postgres/migrations/` and `internal/store/sqlite/migrations/`. Run at `vaultd serve` startup via `VAULT_ADMIN_DATABASE_URL` (admin/DDL role). Postgres can `ALTER COLUMN`; SQLite requires full table recreation (see 012, 014 for pattern). Never skip numbers.
- **Audit DB migrations**: numbered `NNN_description.sql` in `internal/audit/migrations/` (Postgres only). Run at `vaultd audit-consumer` startup via `AUDIT_ADMIN_DATABASE_URL`. SQLite dev path uses `ensureSchema` inline — no migration files needed there.
- **Credential separation**: `VAULT_ADMIN_DATABASE_URL` (DDL) vs `VAULT_DATABASE_URL` (DML via `vault_app`); `AUDIT_ADMIN_DATABASE_URL` (DDL) vs `AUDIT_WRITE_DATABASE_URL` (INSERT via `vault_audit_writer`). See `docs/security.md`.
- **Encryption**: secrets and dynamic backend configs are double-wrapped — DEK encrypted by PEK encrypted by KEK. See `docs/security.md`.
- **Auth middleware** (`internal/api/middleware.go`): mTLS cert (SPIFFE URI SAN first, then email SAN) → bearer token. `errCertUnregistered` is the fall-through sentinel.
- **SCIM deprovisioning**: `SetUserActive(false)` + `DeleteAllTokensForUser` — two calls intentionally, not atomic.
- **OIDC state token**: stateless HMAC-signed, carries `{code_verifier, nonce, cli_callback, exp}`, key = SHA-256(client_secret).

## Task shortcuts

| Task | Files to read |
|------|--------------|
| Add a store method | `internal/store/store.go` + the relevant `*_domain.go` in both backends + `internal/testutil/mockstore/mock.go` |
| Add an API handler | `internal/api/server.go` (routes) + the relevant handler file + `internal/api/audit.go` (action constants) |
| Add a main vault DB migration | `internal/store/postgres/migrations/` + `internal/store/sqlite/migrations/` — check highest number first |
| Add an audit DB migration | `internal/audit/migrations/` — Postgres only; check highest number first |
| Work on mTLS / deploy config | `certs/gen.sh` + `docker-compose.mtls.yml` + `postgres/` init scripts |
| Work on OIDC/SCIM | `internal/api/auth_oidc.go` or `internal/api/scim.go` + `docs/oidc-sso-design.md` |
| Work on mTLS cert principals | `internal/api/certs.go` + `internal/store/*/postgres_certs.go` |
| Crypto / key rotation | `internal/crypto/` + `docs/security.md` |
| Work on audit pipeline | `internal/audit/` + `internal/audit/migrations/` + `cmd/vaultd/audit_consumer.go` + `docs/security.md` |

## Test mocks

`internal/testutil/mockstore.Stub` satisfies `store.Store` with no-op defaults. Both test packages embed it:
- `internal/api/mock_store_test.go` — embeds Stub + adds function fields for override
- `internal/auth/issue_test.go` — embeds Stub + adds in-memory token map

**When `store.Store` gains a new method**: add one no-op to `mockstore/mock.go`. That's it — both test packages compile automatically via embedding.

## Pre-commit sequence

```
gofmt -s -w .
go test ./...
staticcheck ./...
```

## Workflow rules

- **Never commit automatically.** Always run the pre-commit sequence and stop there. Only create a git commit when the user explicitly asks (e.g. "commit", "commit the changes").
