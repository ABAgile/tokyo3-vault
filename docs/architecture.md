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
│                            vaultd serve                          │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐    │
│  │   HTTP API   │  │    Crypto    │  │   Dynamic revoker    │    │
│  │   handlers   │  │    layer     │  │  (background, 60 s)  │    │
│  └──────┬───┬───┘  └──────┬───────┘  └──────────────────────┘    │
└─────────┼───┼─────────────┼────────────────────────────────────-─┘
          │   │ audit.Entry  │
   ┌──────▼─┐ │(publish)     │
   │ Store  │ │       ┌──────▼──────┐
   │(PG/    │ │       │ KeyProvider │
   │SQLite) │ │       │ (local/KMS) │
   └────────┘ │       └─────────────┘
              ▼
   ┌────────────────────────┐        ┌───────────────────────────┐
   │   NATS JetStream       │        │   Audit DB (read-only)    │
   │   AUDIT stream         │◄───────│   (PG or SQLite)          │
   │   (authoritative,      │ upsert │   vault_audit_reader cred │
   │    DenyDelete+Purge,   │ via    │   serves GET /api/v1/audit│
   │    FileStorage, 400 d) │ audit- └───────────────────────────┘
   └────────────────────────┘ consumer
              ▲
              │ subscribe
   ┌──────────┴──────────────┐
   │  vaultd audit-consumer  │
   │  (separate process)     │
   │  vault_audit_writer cred│
   └─────────────────────────┘
```

## Components

### `cmd/vaultd` — server binary

Three subcommands:

| Subcommand | Purpose |
|------------|---------|
| `vaultd serve` | HTTPS API server (default) |
| `vaultd migrate-keys` | One-time migration to per-project PEKs |
| `vaultd audit-consumer` | NATS→audit DB projection writer (separate process) |

**`vaultd serve` startup sequence:**

1. Dispatch `audit-consumer` early (before opening the main store) if that subcommand was requested
2. Parse key provider from env (`VAULT_MASTER_KEY` or `VAULT_KMS_KEY_ID`)
3. Open and auto-migrate the store (`VAULT_DATABASE_URL` → Postgres; `VAULT_DB_PATH` → SQLite)
4. Create `ProjectKeyCache` with configurable TTL (default 5 minutes)
5. Open `audit.JetStreamSink` (publisher credential, PUBLISH-only on `audit.events`); falls back to `NoopSink` when `NATS_URL` is unset
6. Open `audit.DB` (reader credential, SELECT-only on `audit_logs`); falls back to `NoopQueryStore` when unconfigured
7. Start background `Revoker` goroutine (sweeps expired dynamic leases every 60 s; also sweeps on startup)
8. Build TLS config — hot-reloading cert files if provided, else self-signed
9. Start `http.Server` on `VAULT_ADDR` (default `:8443`)

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

### `internal/audit` — audit pipeline

The audit subsystem uses CQRS: JetStream is the authoritative write record; the audit database is a queryable projection rebuilt by `vaultd audit-consumer`.

| Component | Package | Credential |
|-----------|---------|------------|
| `JetStreamSink` | `internal/audit` | `nats_publisher` — PUBLISH-only on `audit.events` |
| `audit.DB` (write) | `internal/audit` | `vault_audit_writer` — INSERT-only on `audit_logs` |
| `audit.DB` (read) | `internal/audit` | `vault_audit_reader` — SELECT-only on `audit_logs` |
| NATS consumer | `cmd/vaultd/audit_consumer.go` | `nats_consumer` — SUBSCRIBE + consumer management |

The AUDIT JetStream stream is configured with `DenyDelete`, `DenyPurge`, and `FileStorage` to provide tamper evidence. `StreamMaxAge` is 400 days (PCI-DSS requires 12 months).

All audit writes are **fail-closed**: if `Sink.Log` returns an error, the request returns HTTP 500 without completing the sensitive operation.

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

**Main store (`vaultd serve` + `migrate-keys`)**

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
| `VAULT_OIDC_ISSUER` | no | — | IdP issuer URL; enables OIDC when set (all four OIDC vars required together) |
| `VAULT_OIDC_CLIENT_ID` | no | — | OAuth2 client ID |
| `VAULT_OIDC_CLIENT_SECRET` | no | — | OAuth2 client secret |
| `VAULT_OIDC_REDIRECT_URI` | no | — | Callback URL registered with the IdP |
| `VAULT_OIDC_ENFORCE` | no | `false` | `"true"` disables local `/auth/login` and `/auth/signup` |

**Audit sink — `vaultd serve` (publisher credential, separate from main DB)**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NATS_URL` | no | — | NATS server URL; enables JetStream sink when set |
| `NATS_AUDIT_CERT` | no | — | mTLS client cert PEM for publisher |
| `NATS_AUDIT_KEY` | no | — | mTLS client key PEM for publisher |
| `NATS_AUDIT_CA` | no | — | CA PEM for NATS server verification |
| `AUDIT_DATABASE_URL` | no | — | Postgres DSN for audit query DB (SELECT-only) |
| `AUDIT_DB_PATH` | no | — | SQLite path for audit query DB |
| `AUDIT_DB_SSL_CERT` | no | — | Client cert PEM for audit DB mTLS |
| `AUDIT_DB_SSL_KEY` | no | — | Client key PEM for audit DB mTLS |
| `AUDIT_DB_SSL_ROOTCERT` | no | — | CA cert PEM for audit DB server verification |

**Audit consumer — `vaultd audit-consumer` (completely separate credentials)**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NATS_URL` | yes | — | NATS server URL |
| `NATS_CONSUMER_CERT` | no | — | mTLS client cert PEM for consumer |
| `NATS_CONSUMER_KEY` | no | — | mTLS client key PEM for consumer |
| `NATS_CONSUMER_CA` | no | — | CA PEM for NATS server verification |
| `AUDIT_WRITE_DATABASE_URL` | one of two | — | Postgres DSN (INSERT-only audit writer) |
| `AUDIT_WRITE_DB_PATH` | one of two | `audit.db` | SQLite path for audit write DB |
| `AUDIT_WRITE_DB_SSL_CERT` | no | — | Client cert PEM for audit write DB mTLS |
| `AUDIT_WRITE_DB_SSL_KEY` | no | — | Client key PEM for audit write DB mTLS |
| `AUDIT_WRITE_DB_SSL_ROOTCERT` | no | — | CA cert PEM for audit write DB server verification |
