# Architecture

> Source: `cmd/vaultd/`, `internal/api/`, `internal/crypto/`, `internal/store/`, `internal/dynamic/`

## Overview

Vault is a self-hosted secrets manager. It stores encrypted secrets, issues short-lived dynamic database credentials, and provides a full audit trail. All access goes through a single HTTPS API server (`vaultd`); the companion CLI (`vault`) is a thin HTTP client.

```
┌───────────────────────────────────────────────────────────────┐
│                           Clients                             │
│                                                               │
│   vault CLI · workloads · CI pipelines · any HTTP client      │
│                                                               │
│   Auth — either method works for any client type:             │
│     ① Bearer token   →  Authorization: Bearer <raw-token>    │
│     ② SPIFFE cert    →  mTLS client cert, URI SAN matched    │
│                          against registered cert_principals   │
└────────────────────────────┬──────────────────────────────────┘
                             │ HTTPS
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                            vaultd                                │
│                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │   HTTP API   │   │    Crypto    │   │   Dynamic revoker    │  │
│  │   handlers   │   │    layer     │   │  (background, 60 s)  │  │
│  └──────┬───────┘   └──────┬───────┘   └──────────────────────┘  │
└─────────┼──────────────────┼────────────────────────────────────-┘
          │                  │
   ┌──────▼──────┐    ┌──────▼──────┐
   │    Store    │    │ KeyProvider │
   │ (PG/SQLite) │    │ (local/KMS) │
   └─────────────┘    └─────────────┘
```

## Components

### `cmd/vaultd` — server binary

Startup sequence (in order):

1. Parse key provider from env (`VAULT_MASTER_KEY` or `VAULT_KMS_KEY_ID`)
2. Open and auto-migrate the store (`VAULT_DATABASE_URL` → Postgres; `VAULT_DB_PATH` → SQLite)
3. Create `ProjectKeyCache` with configurable TTL (default 5 minutes)
4. Start background `Revoker` goroutine (sweeps expired dynamic leases every 60 s; also sweeps on startup)
5. Build TLS config — hot-reloading cert files if provided, else self-signed
6. Start `http.Server` on `VAULT_ADDR` (default `:8443`)

Graceful shutdown is triggered by SIGINT or SIGTERM.

### `internal/api` — HTTP handlers

All protected routes are wrapped by the `auth` middleware (`middleware.go`). Route patterns use Go 1.22 enhanced path matching (`{project}`, `{env}`, `{key}`, `{id}`).

Body size is capped at 4 MB globally via the `limitBody` middleware.

Handler files map roughly to resource types:

| File | Resources |
|------|-----------|
| `auth.go` | signup, login, logout, change-password |
| `tokens.go` | machine token CRUD |
| `projects.go` | project CRUD + slug helpers |
| `environments.go` | environment CRUD |
| `members.go` | project membership management |
| `secrets.go` | secret CRUD, dotenv import/export, rollback |
| `dynamic.go` | dynamic backends, roles, credential issuance, lease management |
| `certs.go` | SPIFFE principal registration + SPIFFE auth helper |
| `access.go` | unified access view (members + tokens + principals per project/env) |
| `audit.go` | audit log queries + action constants |
| `users.go` | server-admin user management |

### `internal/crypto` — encryption & key management

Three abstractions:

- **`KeyProvider`** interface: `WrapDEK` / `UnwrapDEK`
- **`LocalKeyProvider`**: wraps/unwraps in-process with AES-256-GCM (dev only)
- **`KMSKeyProvider`**: delegates to AWS KMS (production)
- **`ProjectKeyCache`**: caches per-project plaintext PEKs in memory; backed by either provider

See [security.md](security.md) for the full key hierarchy.

### `internal/store` — persistence

`store.Store` is a narrow interface shared by two implementations:

- **`postgres`**: connection pool (25 max / 5 idle), embedded SQL migrations, optional client-cert TLS
- **`sqlite`**: pure-Go driver, same schema and migration system, for single-node dev/small deployments

The interface is intentionally constrained so that new store backends can be added without touching API code.

### `internal/dynamic` — dynamic credential backends

- **`Issuer` interface**: `Issue` and `Revoke` methods; one implementation per backend type
- **`postgres.go`**: PostgreSQL issuer; executes user-supplied SQL templates against the target database
- **`revoker.go`**: background goroutine; polls for expired leases and calls `Revoke` on their issuer

### `cmd/vault` — CLI client

Cobra-based. Reads `~/.vault/config.json` for server URL and session token. Project/env context stored in `.vault/config` in the working directory.

## Data Model

See [`er_diagram.md`](er_diagram.md) for the full entity relationship diagram.

Key relationships:

- A **Project** contains **Environments**. Secrets and dynamic backends are always scoped to a `(project, environment)` pair.
- **Secrets** are versioned. `SECRET.current_version_id` points to the live `SECRET_VERSION`; older versions are retained for rollback.
- **Tokens** can be scoped to a project and optionally an environment. Unscoped tokens access all projects the owner is a member of.
- **ProjectMembers** have a role (viewer / editor / owner) and can be scoped to a specific environment via `env_id`. A project-level row (`env_id IS NULL`) grants access across all environments.
- **DynamicLeases** denormalize `role_name` and `revocation_tmpl` at issuance time so that deleted roles and backends do not block revocation.

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULT_MASTER_KEY` | one of two | — | 64-char hex AES-256 KEK (dev only) |
| `VAULT_KMS_KEY_ID` | one of two | — | AWS KMS key ID, ARN, or alias |
| `VAULT_DATABASE_URL` | one of two | — | Postgres DSN |
| `VAULT_DB_PATH` | one of two | `vault.db` | SQLite file path |
| `VAULT_ADDR` | no | `:8443` | Listen address |
| `VAULT_TLS_CERT` | no | — | TLS certificate PEM (hot-reloaded) |
| `VAULT_TLS_KEY` | no | — | TLS private key PEM |
| `VAULT_TLS_CLIENT_CA` | no | — | CA PEM for mTLS client verification |
| `VAULT_DB_SSL_CERT` | no | — | Client cert for vault→Postgres TLS |
| `VAULT_DB_SSL_KEY` | no | — | Client key for vault→Postgres TLS |
| `VAULT_DB_SSL_ROOTCERT` | no | — | CA cert to verify Postgres server |
| `VAULT_PROJECT_KEY_CACHE_TTL` | no | `5m` | How long plaintext PEKs stay in RAM |
