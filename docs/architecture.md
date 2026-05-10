# Architecture

> Source: `cmd/vaultd/`, `internal/api/`, `internal/crypto/`, `internal/store/`, `internal/dynamic/`

## Overview

Vault is a self-hosted secrets manager. It stores encrypted secrets, issues short-lived dynamic database credentials, and provides a full audit trail. All access goes through a single HTTPS API server (`vaultd`); the companion CLI (`vault`) is a thin HTTP client. `vaultd` also serves a server-rendered admin portal at `/portal/*` on the same listener for user/project/SCIM administration — secrets and dynamic credentials remain CLI-only. See [README.md → Admin Portal](../README.md#admin-portal).

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
   ┌────────────────────────┐
   │   NATS JetStream       │
   │   vault_audit stream   │
   │   (sole authoritative  │
   │    store; DenyDelete + │
   │    Purge, FileStorage, │
   │    400 d retention)    │
   └────────────────────────┘
         ▲                ▲
         │ Subscribe      │ Subscribe
         │ (last 100      │ (last N,
         │  + tail)       │  one-shot)
   ┌─────┴────────┐ ┌─────┴──────────┐
   │ /portal/admin│ │ vaultd         │
   │ /audit/sse   │ │ audit-query    │
   │ (browser     │ │ (terminal      │
   │  live tail)  │ │  one-shot CLI) │
   └──────────────┘ └────────────────┘
```

## Components

### `cmd/vaultd` — server binary

Subcommands:

| Subcommand | Purpose |
|------------|---------|
| `vaultd` (no arg) | HTTPS API server (default) |
| `vaultd migrate-keys` | One-time migration to per-project PEKs |
| `vaultd audit-query [--limit N]` | Terminal viewer for the audit JetStream stream — prints the most recent N events as JSON, then exits. Shares the journal/jetstream.Source primitive used by /portal/admin/audit. |

**`vaultd serve` startup sequence:**

1. Parse key provider from env (`VAULT_MASTER_KEY` or `VAULT_KMS_KEY_ID`)
2. Open the main store: for Postgres, run schema migrations with `VAULT_ADMIN_DATABASE_URL` (owner/DDL role; skipped when unset) then open the runtime connection with `VAULT_DATABASE_URL` (DML-only `vault_app` role); for SQLite, open `VAULT_DB_PATH` directly (migrations run inline)
3. Create `ProjectKeyCache` with configurable TTL (default 5 minutes)
4. Dispatch `migrate-keys` → `runMigrateKeys(); exit` if that subcommand was requested
5. Open `audit.JetStreamSink` (publisher credential, PUBLISH-only on `vault.audit.events`); falls back to `NoopSink` when `VAULT_NATS_URL` is unset
6. Start background `Revoker` goroutine (sweeps expired dynamic leases every 60 s; also sweeps on startup)
7. Start background `PEKRotator` goroutine (sweeps for stale PEKs every hour; also sweeps on startup; disabled when `VAULT_PEK_ROTATION_PERIOD=0`)
8. Start background `VersionPruner` goroutine (prunes old secret versions once at startup then every 24 h; controlled by `VAULT_VERSION_MIN_KEEP` and `VAULT_VERSION_MIN_DAYS`)
9. Start background `TokenPruner` goroutine (deletes expired token rows once at startup then every hour)
9. Build TLS config — hot-reloading cert files if provided, else self-signed
10. Build OIDC provider from `VAULT_OIDC_*` env vars; `nil` provider when unconfigured (local auth only)
11. Start `http.Server` on `VAULT_ADDR` (default `:8443`)

Graceful shutdown is triggered by SIGINT or SIGTERM.

### `internal/api` — HTTP handlers

All protected routes are wrapped by the `auth` middleware (`middleware.go`). Route patterns use Go 1.22 enhanced path matching (`{project}`, `{env}`, `{key}`, `{id}`).

Body size is capped at 4 MB globally via the `limitBody` middleware.

Handler files map roughly to resource types:

| File | Resources |
|------|-----------|
| `auth.go` | signup, login, logout, change-password |
| `tokens.go` | machine token CRUD |
| `projects.go` | project CRUD, slug helpers, on-demand PEK rotation (`POST /projects/{slug}/rotate-key`) |
| `environments.go` | environment CRUD |
| `members.go` | project membership management |
| `secrets.go` | secret CRUD, envfile upload/download, rollback |
| `dynamic.go` | dynamic backends, roles, credential issuance, lease management |
| `certs.go` | SPIFFE principal registration + SPIFFE auth helper |
| `access.go` | unified access view (members + tokens + principals per project/env) |
| `audit.go` | action string constants + `logAudit`/`logAuditEnv` helpers |
| `users.go` | server-admin user management |
| `scim.go` | SCIM 2.0 Users + Groups + SCIM token + group→role mapping management |
| `web.go` | embedded `web/` template + static FS, `tmplManager`, `staticHandler` |
| `web_portal.go` | `/portal/*` self-service (login, register, account, tokens) + portal cookie + `portalAuth` middleware |
| `web_portal_admin.go` | `/portal/admin/*` (users, SCIM tokens, SCIM group→role, projects) |

### `internal/crypto` — encryption & key management

Four abstractions:

- **`KeyProvider`** interface: `WrapDEK` / `UnwrapDEK`
- **`LocalKeyProvider`**: wraps/unwraps in-process with AES-256-GCM (dev only)
- **`KMSKeyProvider`**: delegates to AWS KMS (production)
- **`ProjectKeyCache`**: caches per-project plaintext PEKs in memory; backed by either provider

`cmd/vaultd/rotator.go` contains `PEKRotator`, which runs as a background goroutine and rotates project PEKs older than `VAULT_PEK_ROTATION_PERIOD`. See [security.md](security.md) for the full key hierarchy and rotation policy.

### `internal/store` — persistence

`store.Store` is a narrow interface shared by two implementations:

- **`postgres`**: connection pool (25 max / 5 idle), embedded SQL migrations, optional client-cert TLS
- **`sqlite`**: pure-Go driver, same schema and migration system, for single-node dev/small deployments

The interface is intentionally constrained so that new store backends can be added without touching API code.

### `internal/audit` — audit event types

JetStream is the **sole** authoritative store for audit events; there is no separate projection database. `internal/audit` keeps only the wire shape (`Entry` struct + `Subject` / `StreamName` / `StreamMaxAge` constants); the publish path goes through `journal.NewJSONSink[Entry]` and the read path through `journal/jetstream.Source` — both from `tokyo3-base`.

| Component | Package | Credential |
|-----------|---------|------------|
| Publisher (audit.Append) | `internal/api/audit.go` | `nats_publisher` — PUBLISH on `vault.audit.events` |
| Live tail (browser SSE) | `internal/api/audit_stream.go` + `base/journal/sse` | `nats_consumer` — CONSUME on `vault.audit.events` |
| CLI viewer (`vaultd audit-query`) | `cmd/vaultd/audit.go` | same NATS credential as the server |

The `vault_audit` JetStream stream is configured with `DenyDelete`, `DenyPurge`, and `FileStorage` to provide tamper evidence. `StreamMaxAge` is 400 days (PCI-DSS requires 12 months).

All audit writes are **fail-closed**: if the JetStream publish fails, the request returns HTTP 503 without completing the sensitive operation.

### `internal/dynamic` — dynamic credential backends

- **`Issuer` interface**: `Issue` and `Revoke` methods; one implementation per backend type
- **`postgres.go`**: PostgreSQL issuer; executes user-supplied SQL templates against the target database
- **`revoker.go`**: background goroutine; polls for expired leases and calls `Revoke` on their issuer

### `cmd/vault` — CLI client

Cobra-based. Reads `~/.vault/config` for server URL and session token. Project/env context stored in `.vault.toml` in the working directory.

## Data Model

See [`er-diagram.md`](er-diagram.md) for the full entity relationship diagram.

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
| `VAULT_ADMIN_DATABASE_URL` | no | falls back to `VAULT_DATABASE_URL` | Postgres DSN for schema migrations (owner/DDL role) |
| `VAULT_ADMIN_DB_CERT` | no | — | Client cert for admin DB mTLS |
| `VAULT_ADMIN_DB_KEY` | no | — | Client key for admin DB mTLS |
| `VAULT_ADMIN_DB_CA` | no | — | CA cert to verify admin Postgres server |
| `VAULT_DATABASE_URL` | one of two | — | Postgres DSN (DML-only `vault_app` role) |
| `VAULT_DB_PATH` | one of two | `vault.db` | SQLite file path |
| `VAULT_ADDR` | no | `:8443` | Listen address |
| `VAULT_API_CERT` | no | — | TLS certificate PEM (hot-reloaded) |
| `VAULT_API_KEY` | no | — | TLS private key PEM |
| `VAULT_API_CLIENT_CA` | no | — | CA PEM for mTLS client verification |
| `VAULT_DB_CERT` | no | — | Client cert for vault→Postgres TLS |
| `VAULT_DB_KEY` | no | — | Client key for vault→Postgres TLS |
| `VAULT_DB_CA` | no | — | CA cert to verify Postgres server |
| `VAULT_PROJECT_KEY_CACHE_TTL` | no | `5m` | How long plaintext PEKs stay in RAM |
| `VAULT_PEK_ROTATION_PERIOD` | no | `2160h` (90 days) | Maximum age of a project PEK before automatic rotation; set to `0` to disable |
| `VAULT_TRUSTED_PROXIES` | no | — | Comma-separated CIDRs **appended to** the built-in trusted ranges (loopback, RFC-1918, ULA). X-Forwarded-For is only trusted when the TCP connection comes from a trusted CIDR. |
| `VAULT_AUTH_RATE_PER_MIN` | no | `5` | Maximum requests per minute per client IP on auth endpoints (`/auth/login`, `/auth/signup`, `PUT /auth/password`). Both the sustained rate and burst cap are set to this value. |
| `VAULT_VERSION_MIN_KEEP` | no | `10` | Minimum number of secret versions to retain per secret. A version is pruned only when **both** this threshold **and** `VAULT_VERSION_MIN_DAYS` are exceeded. |
| `VAULT_VERSION_MIN_DAYS` | no | `180` | Minimum age in days a secret version must reach before it is eligible for pruning (together with `VAULT_VERSION_MIN_KEEP`). |
| `VAULT_OIDC_ISSUER` | no | — | IdP issuer URL; enables OIDC when set (all four OIDC vars required together) |
| `VAULT_OIDC_CLIENT_ID` | no | — | OAuth2 client ID |
| `VAULT_OIDC_CLIENT_SECRET` | no | — | OAuth2 client secret |
| `VAULT_OIDC_REDIRECT_URI` | no | — | Callback URL registered with the IdP |
| `VAULT_OIDC_ENFORCE` | no | `false` | `"true"` disables local `/auth/login` and `/auth/signup` |
| `VAULT_ALLOW_REGISTRATION` | no | `false` | `"true"` enables self-service signup at `/portal/register`. First registrant becomes admin if no admin exists. Ignored when `VAULT_OIDC_ENFORCE=true`. |

**Audit sink — `vaultd serve` (publisher credential)**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULT_NATS_URL` | no | — | NATS server URL; enables JetStream sink when set |
| `VAULT_NATS_CERT` | no | — | mTLS client cert PEM for publisher |
| `VAULT_NATS_KEY` | no | — | mTLS client key PEM for publisher |
| `VAULT_NATS_CA` | no | — | CA PEM for NATS server verification |

`vaultd audit-query` reuses the server's `VAULT_NATS_*` env vars — there is no separate audit binary or audit-DB credentials anymore.
