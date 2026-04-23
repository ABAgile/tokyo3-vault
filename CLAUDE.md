# Vault — agent orientation

## What this is
Self-hosted secrets manager. Stores encrypted secrets, issues short-lived dynamic database credentials, handles user auth (local, OIDC, SCIM, mTLS). Single HTTPS API server (`vaultd`) + thin CLI (`vault`).

## Layout

```
cmd/vaultd/          server binary — startup, TLS, env config
cmd/vault/           CLI client (Cobra); reads ~/.vault/config.json
internal/api/        HTTP handlers (one file per resource type)
internal/auth/       token hashing, issuance, validation
internal/crypto/     KEK/PEK/DEK key hierarchy, KMS/local providers
internal/dynamic/    dynamic credential issuance + background revoker
internal/model/      all shared types (one file)
internal/oidc/       OIDC provider wrapper (go-oidc/v3 + oauth2)
internal/store/      store.Store interface + AuditFilter
internal/store/postgres/   Postgres backend — split by domain (see below)
internal/store/sqlite/     SQLite backend  — split by domain (see below)
internal/testutil/mockstore/  shared Stub for test mocks
internal/tlsutil/    TLS helpers (hot-reload, self-signed, cert pools)
docs/                architecture.md, er_diagram.md, oidc-sso-design.md
```

## Store backend file layout (postgres + sqlite mirror each other)

| File | Domain |
|------|--------|
| `postgres.go` / `sqlite.go` | DB struct, Open, migrate, Close, isUnique |
| `*_users.go` | userCols, scanUser, all User methods |
| `*_tokens.go` | Token CRUD + ListTokensWithAccess |
| `*_projects.go` | Projects, ProjectMembers, Environments, project keys |
| `*_secrets.go` | Secrets, SecretVersions, AuditLogs |
| `*_dynamic.go` | DynamicBackends, DynamicRoles, DynamicLeases |
| `*_scim.go` | SCIMTokens, SCIMGroupRoles |
| `*_certs.go` | CertPrincipals (scanCertPrincipal helper) |

## Key invariants

- **Migrations**: numbered `NNN_description.sql`. Postgres can `ALTER COLUMN`; SQLite requires full table recreation (see 012, 014 for pattern). Never skip numbers.
- **Encryption**: secrets and dynamic backend configs are double-wrapped — DEK encrypted by PEK encrypted by KEK. See `docs/security.md`.
- **Auth middleware** (`internal/api/middleware.go`): mTLS cert (SPIFFE URI SAN first, then email SAN) → bearer token. `errCertUnregistered` is the fall-through sentinel.
- **SCIM deprovisioning**: `SetUserActive(false)` + `DeleteAllTokensForUser` — two calls intentionally, not atomic.
- **OIDC state token**: stateless HMAC-signed, carries `{code_verifier, nonce, cli_callback, exp}`, key = SHA-256(client_secret).

## Task shortcuts

| Task | Files to read |
|------|--------------|
| Add a store method | `internal/store/store.go` + the relevant `*_domain.go` in both backends + `internal/testutil/mockstore/mock.go` |
| Add an API handler | `internal/api/server.go` (routes) + the relevant handler file + `internal/api/audit.go` (action constants) |
| Add a migration | `internal/store/postgres/migrations/` + `internal/store/sqlite/migrations/` — check highest number first |
| Work on OIDC/SCIM | `internal/api/auth_oidc.go` or `internal/api/scim.go` + `docs/oidc-sso-design.md` |
| Work on mTLS certs | `internal/api/certs.go` + `internal/store/*/postgres_certs.go` |
| Crypto / key rotation | `internal/crypto/` + `docs/security.md` |

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
