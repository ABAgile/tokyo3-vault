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

### Rate limiting

Auth endpoints (`POST /auth/login`, `POST /auth/signup`, `PUT /auth/password`) are protected by a per-IP token-bucket rate limiter. The limiter is seeded at server startup and runs in-process; no external state is needed.

| Parameter | Env var | Default |
|-----------|---------|---------|
| Sustained rate (req/min) | `VAULT_AUTH_RATE_PER_MIN` | `5` |
| Burst cap | — | equals sustained rate |

Exceeding the limit returns `HTTP 429`. The limiter is keyed on the extracted client IP (see Trusted Proxies below), so it tracks the real client rather than a shared proxy address.

### Trusted proxies and X-Forwarded-For

When a request arrives from a trusted CIDR, the server reads the first value of the `X-Forwarded-For` header as the client IP; otherwise it uses `RemoteAddr` directly.

The built-in trusted ranges are: `127.0.0.0/8`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`. Additional CIDRs can be appended (not replaced) via `VAULT_TRUSTED_PROXIES` (comma-separated). When your reverse proxy sits outside these ranges, set `VAULT_TRUSTED_PROXIES` explicitly so that the client IP in audit logs reflects the real client rather than the proxy.

The extracted IP is used for both audit records and rate limiting.

### Token invalidation on password change

`PUT /auth/password` (change own password) and `PUT /users/{user_id}/password` (admin reset) both call `DeleteAllTokensForUser` after updating the password hash. All existing session and machine tokens for the affected user are invalidated immediately; any concurrent requests using those tokens will receive `401` on their next authenticated call.

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

### DEK rotation — design rationale

DEKs are intentionally not rotated independently. The threat that DEK rotation would address — an attacker obtaining a plaintext DEK and using it to decrypt a secret version — already requires compromising the PEK first, since DEKs are stored wrapped by the PEK. If the PEK is compromised, all DEKs for that project are exposed regardless; rotating individual DEKs provides no marginal protection.

PEK rotation (automatic every 90 days, or on demand) serves as the crypto-hygiene refresh for the entire key hierarchy: after rotation, all DEKs are re-wrapped under fresh PEK material and the in-memory PEK cache is invalidated. This is the correct boundary at which to rotate — one operation protects all secrets in the project.

In-place DEK rotation would also require mutating existing `secret_versions` rows (decrypt value, re-encrypt under new DEK, update both `encrypted_dek` and `encrypted_value`). Secret versions are otherwise immutable records of value changes; mutating them for key-material reasons conflates two orthogonal concerns.

**Secret value rotation** (automatically replacing a secret's content — cycling a database password, regenerating an API key) is a separate concern that requires outbound integration with the target system. It is not implemented and is out of scope for the core vault server.

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
| Projects | `project.create`, `project.delete`, `project.rotate_key` |
| Environments | `env.create`, `env.delete` |
| Secrets | `secret.get`, `secret.set`, `secret.delete`, `secret.rollback`, `secret.import`, `secret.envfile_upload`, `secret.envfile_download` |
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
| `ip` | Client IP: `X-Forwarded-For` (first value) when the TCP connection arrives from a trusted proxy CIDR (`VAULT_TRUSTED_PROXIES`), otherwise `RemoteAddr` |
| `occurred_at` | Server-side UTC timestamp; stored as `created_at` in the audit DB and returned as `created_at` by the API |

Failed login attempts record the submitted email address in `resource` to support forensic analysis without exposing whether the account exists (the 401 response is identical regardless).

The audit consumer uses `INSERT ... ON CONFLICT (id) DO NOTHING` so JetStream at-least-once redelivery is safe.

## Transport Security

- The server always uses HTTPS (`ListenAndServeTLS`).
- If no cert files are configured, an ephemeral self-signed ECDSA P-256 certificate is generated — development only; a warning is logged.
- When `VAULT_TLS_CERT` / `VAULT_TLS_KEY` are set, `CertLoader.GetCertificate` is used: the certificate is re-read from disk on each TLS handshake when the mtime changes. This supports cert rotation via `tbot` or any certificate manager without a server restart.
- `VAULT_TLS_CLIENT_CA` enables `tls.VerifyClientCertIfGiven`: client certificates are optional but verified against the CA when present, enabling SPIFFE authentication for workloads that can present a cert.

## Secret Version Retention

Every `SetSecret` call appends a new version row; the `current_version_id` pointer advances but old rows are kept for rollback. The `VersionPruner` background goroutine (started at `vaultd serve`) trims old versions once at startup and then every 24 hours.

A version is eligible for pruning only when **both** conditions hold:

1. There are more than `VAULT_VERSION_MIN_KEEP` versions for the secret (default: `10`).
2. The version is older than `VAULT_VERSION_MIN_DAYS` days (default: `180`).

The current version is never pruned regardless of age or count. Both thresholds must be exceeded simultaneously — a secret with 50 versions but all written in the last month will not be pruned.

## Known Security Limitations

- **Dynamic credential templates are user-provided SQL.** There is no parameterization framework; placeholders (`{{username}}`, `{{password}}`, `{{expiry}}`) are replaced by string substitution. This is safe for trusted admins configuring backends but would be a SQL injection vector if templates were user-controlled input from untrusted parties.
- **Token expiry is checked at auth time, not stored as a DB-level constraint.** A very small window exists between a token expiring and the server detecting it on the next request. This is typical for bearer token systems and is generally acceptable.
