# Security Model

> Source: `internal/auth/`, `internal/api/middleware.go`, `internal/crypto/`, `internal/api/audit.go`

## Authentication

Two credential types are accepted on every protected route. The middleware checks mTLS first, then falls back to bearer token.

### Bearer tokens

- **Generation**: `crypto/rand` → 32 random bytes → hex-encoded 64-char string sent to the client once
- **Storage**: only the SHA-256 hash is stored; the server never sees the raw token again after issuance
- **Validation**: `Authorization: Bearer <raw>` → SHA-256 → lookup in `tokens` table → expiry check

Two token flavors:

| Flavor | `user_id` | `project_id` | Typical use |
|--------|-----------|--------------|-------------|
| Session | set | nil | Human users after login |
| Machine | nil or set | nil (unscoped) or set | CI/CD, workloads |

Machine tokens can optionally carry an `env_id` to restrict access further to a single environment.

### SPIFFE / mTLS

When a client presents a TLS certificate, the `auth` middleware:

1. Extracts the `spiffe://` URI SAN from the leaf certificate
2. Looks up the SPIFFE ID in `cert_principals`
3. Checks the principal's `expires_at` (independent of the certificate's own validity window)
4. If found and unexpired, constructs an ephemeral `*model.Token` (never persisted) — ID set to the principal's ID, scopes from the principal row

If the SPIFFE ID is not registered the middleware falls through to bearer token auth. Any other error (expired principal, store failure) returns 401 immediately.

Certificate verification itself is handled by Go's TLS stack. `VAULT_TLS_CLIENT_CA` must be set for the server to request and verify client certificates.

### Password security

- bcrypt cost factor 12 (`auth.HashPassword`)
- `auth.CheckPassword` uses `bcrypt.CompareHashAndPassword` (constant-time)
- Plaintext passwords are never logged or stored anywhere other than the bcrypt hash in the DB
- Minimum length: 8 characters (enforced in API handlers)

### First-user bootstrap

The `/signup` endpoint is only accessible when `HasAdminUser()` returns false. The first account always receives the `admin` role. Subsequent accounts require an existing admin to create them via `POST /users`.

## Authorization

### Role hierarchy

```
viewer (1) < editor (2) < owner (3)
```

Roles are per-project, per-user. A `project_members` row with `env_id IS NULL` grants access to the entire project; a row with `env_id` set restricts the user to that environment only. Both types of rows can coexist for the same user.

### Authorization checks (middleware.go)

| Check | Used on | Effect |
|-------|---------|--------|
| `requireServerAdmin` | `/users` admin routes | Token's user must have `role = admin` in `users` table |
| `requireOwner` | Member management | Project-level role = owner; machine tokens always rejected |
| `requireWrite` | Secret/env create+delete | Editor+ role; read-only tokens rejected |
| `requireWritable` | Global writes (no projectID) | Read-only token check only |
| `requireUnscoped` | Project/token creation | Scoped machine tokens cannot create projects or tokens |
| `authorize` | All project access | Scope check for machine tokens; membership lookup for users |

Server admins bypass all project membership checks (implicitly owner everywhere).

### Machine token scoping

A machine token with `project_id` set can only access that project. If `env_id` is also set, access is further restricted to that environment. An unscoped machine token (`project_id = nil`) must have a matching `project_members` entry, just like a user session token.

The `read_only` flag on a token is enforced per-operation: any handler that mutates state calls `requireWrite` or `requireWritable` first.

## Encryption

### Key hierarchy

```
AWS KMS (or local AES-256 KEK)
    └── Project Envelope Key (PEK)  — per project, stored wrapped in projects.encrypted_pek
            └── Data Encryption Key (DEK)  — per secret version / per dynamic backend config
                    └── Ciphertext  — stored in secret_versions.encrypted_value / dynamic_backends.encrypted_config
```

All symmetric encryption uses **AES-256-GCM** with a random 12-byte nonce prepended to the ciphertext.

### Key provider

Exactly one must be configured:

- **`LocalKeyProvider`** (`VAULT_MASTER_KEY`): 32-byte AES-256 key in process memory. Wrap/unwrap is a local `seal`/`open` call. For development only — the master key is directly visible in the environment.
- **`KMSKeyProvider`** (`VAULT_KMS_KEY_ID`): delegates `WrapDEK`/`UnwrapDEK` to AWS KMS `Encrypt`/`Decrypt`. No key material lives on the vault host. Credentials are loaded from the AWS default chain (environment variables, IAM role, config file).

### Project Envelope Key (PEK) and caching

Each project has its own PEK, wrapped by the server KEK and stored in `projects.encrypted_pek`. On every secret access, `ProjectKeyCache.ForProject`:

1. Checks the in-memory cache (read lock; fast path)
2. On miss: unwraps the PEK via the server key provider (may call KMS), caches the plaintext for the configured TTL (default 5 minutes)

This bounds KMS API calls to roughly one per project per TTL window under steady traffic.

`ProjectKeyCache.Invalidate(projectID)` clears the cached entry. It is called automatically after every PEK rotation so the next request fetches and caches the new key.

### PEK rotation

`projects.pek_rotated_at` records when each PEK was last rotated (NULL until the first rotation).

**Automatic rotation** — the `PEKRotator` background goroutine runs a sweep at server startup and every hour thereafter. It queries for projects whose `pek_rotated_at IS NULL OR pek_rotated_at < now() - period` (`VAULT_PEK_ROTATION_PERIOD`, default 90 days) and rotates each one in turn. Projects with `encrypted_pek IS NULL` (not yet migrated) are logged as warnings and skipped.

**On-demand rotation** — project owners can trigger an immediate rotation via `POST /projects/{slug}/rotate-key`. This follows the same code path and emits a `project.rotate_key` audit event (fail-closed).

Both paths use `store.RotateProjectPEK`, which re-wraps all DEKs **and** updates `encrypted_pek` + `pek_rotated_at` in a single DB transaction. A crash mid-rotation leaves the database unchanged; the project will be retried on the next sweep.

The automatic rotator emits a `project.rotate_key` audit event on success (best-effort: the rotation has already committed, so a NATS failure is logged but does not roll back the key change).

> When AWS KMS automatic key rotation is enabled, `VAULT_PEK_ROTATION_PERIOD` doubles as the re-wrap schedule: each PEK rotation calls `kp.UnwrapDEK` (KMS uses the old key version) then `kp.WrapDEK` (KMS uses the current key version), progressively migrating all stored PEKs to the latest KMS key material.

### Key migration

Projects created before PEK support have `encrypted_pek = NULL`. The `ForProject` method detects this and returns the server-level provider directly, so existing DEKs continue to work without any data migration.

`vaultd migrate-keys` iterates all un-migrated projects and for each one atomically:

1. Generates a fresh 32-byte PEK
2. Wraps it with the server KEK → `encPEK`
3. Re-wraps all secret-version and dynamic-backend DEKs under the new PEK
4. Stores `encPEK` and sets `pek_rotated_at = now()`

All four steps run inside `store.RotateProjectPEK` — a single DB transaction per project. If the transaction fails, the project remains un-migrated and `migrate-keys` can be re-run safely (idempotent: projects with an existing PEK are skipped).

> After migrating keys, the KMS cost is proportional to the number of projects × (1 / cache TTL), not the number of secrets.

## Audit Logging

Every state-changing operation, every read of a secret value, and authentication failures are recorded as immutable audit events.

### Architecture (PCI-DSS aligned)

Audit uses a two-process design with credential separation between the vault server and the audit tool:

```
vaultd serve (publisher credential)
    │ Sink.Log → NATS JetStream "AUDIT" stream
    │            (DenyDelete, DenyPurge, FileStorage, 400-day retention)
    │
vault-audit consume (subscriber credential)
    └── Fetch → decode → UpsertAuditLog → Audit DB
```

Querying is handled entirely by `vault-audit query`, which reads directly from the audit DB. `vaultd` has no connection to the audit database at runtime.

**Fail-closed**: `logAudit` returns an error; every handler that calls it checks the return value. If the publish to JetStream fails, the handler writes HTTP 500 and discards the response — the sensitive operation is never considered complete without a durable audit record.

**Tamper evidence**: the NATS stream is configured with `DenyDelete` and `DenyPurge`, so no individual message or the entire stream can be deleted via the NATS API. `FileStorage` ensures records survive restarts.

**Credential separation** (five distinct identities):

| Identity | Rights | Used by |
|----------|--------|---------|
| `vault_app` | DML-only on main DB | `vaultd serve` (runtime) |
| `vault` (admin) | DDL on main DB | `vaultd serve` (startup migration only) |
| `nats_publisher` | PUBLISH-only on `audit.events` | `vaultd serve` |
| `nats_consumer` | SUBSCRIBE + consumer management | `vault-audit consume` |
| `vault_audit` | DDL + INSERT + SELECT on audit DB | `vault-audit` (both subcommands) |

### Covered events

| Category | Actions |
|----------|---------|
| Auth | `auth.signup`, `auth.login`, `auth.logout`, `auth.login_failed`, `auth.change_password` |
| OIDC | `auth.oidc.login`, `auth.oidc.jit_provision`, `auth.oidc.identity_linked` |
| Projects | `project.create`, `project.delete` |
| Environments | `env.create`, `env.delete` |
| Secrets | `secret.get`, `secret.set`, `secret.delete`, `secret.rollback`, `secret.import`, `secret.dotenv_upload`, `secret.dotenv_download` |
| Tokens | `token.create`, `token.delete` |
| Members | `member.add`, `member.update`, `member.remove` |
| Dynamic | `dynamic.backend.set`, `dynamic.backend.delete`, `dynamic.role.set`, `dynamic.role.delete`, `dynamic.lease.issue`, `dynamic.lease.revoke` |
| Certificates | `cert.principal.register`, `cert.principal.delete` |
| Users | `user.create` |
| SCIM | `scim.user.create`, `scim.user.update`, `scim.user.deactivate`, `scim.group.sync`, `scim.token.create`, `scim.token.delete` |

### Record structure

| Field | Notes |
|-------|-------|
| `id` | UUID — used as the idempotency key for upsert on redelivery |
| `action` | Action string, e.g. `secret.get` — see Covered events table above |
| `actor_id` | Token ID of the caller; empty for unauthenticated operations |
| `project_id` | Empty string when not project-scoped |
| `env_id` | Environment UUID for env-scoped actions (`secret.*`, `dynamic.*`, `env.*`); empty otherwise |
| `resource` | Identifies the affected resource (secret key name, user email, SPIFFE ID, etc.) |
| `metadata` | Free-form string; secret values are masked to first 3 characters + `...` |
| `ip` | From `X-Forwarded-For` header (first value) or `RemoteAddr` |
| `occurred_at` | Server-side UTC timestamp; stored as `created_at` in the audit DB and returned as `created_at` by the API |

Failed login attempts record the submitted email address in `resource` to support forensic analysis without exposing whether the account exists (the 401 response is identical regardless).

The audit consumer uses `INSERT ... ON CONFLICT (id) DO NOTHING` so JetStream at-least-once redelivery is safe.

## Transport Security

- The server always uses HTTPS (`ListenAndServeTLS`).
- If no cert files are configured, an ephemeral self-signed ECDSA P-256 certificate is generated — development only; a warning is logged.
- When `VAULT_TLS_CERT` / `VAULT_TLS_KEY` are set, `CertLoader.GetCertificate` is used: the certificate is re-read from disk on each TLS handshake when the mtime changes. This supports cert rotation via `tbot` or any certificate manager without a server restart.
- `VAULT_TLS_CLIENT_CA` enables `tls.VerifyClientCertIfGiven`: client certificates are optional but verified against the CA when present, enabling SPIFFE authentication for workloads that can present a cert.

## Known Security Limitations

- **Dynamic credential templates are user-provided SQL.** There is no parameterization framework; placeholders (`{{username}}`, `{{password}}`, `{{expiry}}`) are replaced by string substitution. This is safe for trusted admins configuring backends but would be a SQL injection vector if templates were user-controlled input from untrusted parties.
- **Token expiry is checked at auth time, not stored as a DB-level constraint.** A very small window exists between a token expiring and the server detecting it on the next request. This is typical for bearer token systems and is generally acceptable.
- **The `X-Forwarded-For` header used for IP logging is not validated.** Behind a trusted reverse proxy this is fine; direct internet exposure means a client can spoof its IP in audit logs.
- **Session tokens are not automatically rotated.** After a password change, existing session tokens remain valid until they expire or are manually deleted.
- **No rate limiting** is applied to authentication endpoints. Deploy behind a reverse proxy with rate limiting for production.
