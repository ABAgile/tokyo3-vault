# OIDC/SSO & SCIM Integration

This document covers the technical implementation of IdP integration: OIDC login + JIT provisioning, SCIM 2.0 lifecycle provisioning, and mTLS for non-SPIFFE certificates.

Primary target IdP is **Authentik** (self-hosted, open-source). The implementation follows standard protocols and is compatible with any OIDC/SCIM-compliant IdP: Okta, Azure AD, Keycloak, Dex, Auth0, Google Workspace.

---

## Architecture

```
                 Browser / vault CLI
                        │
           GET /auth/oidc/login?cli_callback=<url>
                        │
              ┌─────────▼──────────┐
              │    vaultd           │   1. BeginAuth: generate PKCE + nonce
              │ auth_oidc.go        │   2. Sign state JWT (HMAC-SHA256)
              └─────────┬──────────┘   3. Return authorization_url
                        │
           Redirect ────►──── IdP (Authentik/Okta/…)
                                │
                   User logs in │
                                │
           Redirect to VAULT_OIDC_REDIRECT_URI
                        │
              ┌─────────▼──────────┐
              │    vaultd           │   4. Verify state JWT
              │ auth_oidc.go        │   5. Exchange code + code_verifier
              │                     │   6. Verify ID token + nonce
              │ jitProvision()      │   7. JIT-provision or look up user
              └─────────┬──────────┘   8. Issue session token
                        │
           Token ────────────── Browser (JSON) or CLI (redirect)
```

**Why OIDC + SCIM?** They are complementary protocols:
- **OIDC** handles *authentication* — proves who the user is on each login.
- **SCIM** handles *lifecycle provisioning* — pre-creates accounts, deactivates them on offboarding, syncs group memberships. Closes the gap where a user's account lingers in vault after they leave the organization.

---

## Database Schema

### Migration 012 — OIDC columns (`012_oidc.sql`)

```sql
-- Postgres
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN oidc_issuer  TEXT;
ALTER TABLE users ADD COLUMN oidc_subject TEXT;
CREATE UNIQUE INDEX users_oidc_identity
    ON users (oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL;

-- SQLite: table recreation (see migrations/012_oidc.sql)
```

`password_hash` becomes nullable. OIDC-only users have `NULL` password_hash and cannot authenticate locally (bcrypt rejects the empty hash). The `(oidc_issuer, oidc_subject)` unique index prevents one IdP identity from linking to two vault users.

### Migration 013 — SCIM columns (`013_scim.sql`)

```sql
ALTER TABLE users ADD COLUMN active           BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN scim_external_id TEXT;

CREATE TABLE scim_tokens (
    id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scim_group_roles (
    id TEXT PRIMARY KEY, scim_external_id TEXT NOT NULL, display_name TEXT NOT NULL,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    env_id TEXT REFERENCES environments(id) ON DELETE CASCADE,
    role TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (scim_external_id, project_id, env_id)
);
```

`active = false` means deprovisioned by SCIM. All existing tokens are deleted when a user is deactivated; new logins are blocked. `scim_group_roles` maps the IdP's `scim_external_id` (the SCIM group's stable upstream ID) to vault project roles. SCIM group sync then upserts/diffs `project_members` rows tagged with `source_scim_external_id` for provenance, so PUT-style replacement removes only that source group's grants and overlapping grants from other groups (or admin rows) survive.

---

## Data Model (`internal/model/model.go`)

```go
type User struct {
    ID             string
    Email          string
    PasswordHash   string  // empty for OIDC-only users
    Role           string  // UserRoleAdmin | UserRoleMember
    OIDCIssuer     *string // nil for local accounts
    OIDCSubject    *string // nil for local accounts; unique per issuer when set
    Active         bool    // false = deprovisioned by SCIM
    SCIMExternalID *string // IdP externalId for correlation
    CreatedAt      time.Time
}

type SCIMToken struct {
    ID          string
    TokenHash   string
    Description string
    CreatedAt   time.Time
}

type SCIMGroupRole struct {
    ID             string
    SCIMExternalID string  // IdP-assigned group ID; stable upstream identifier
    DisplayName    string
    ProjectID      *string
    EnvID          *string
    Role           string
    CreatedAt      time.Time
}
```

---

## Store Interface (`internal/store/store.go`)

New methods added for OIDC and SCIM:

```go
// OIDC
CreateOIDCUser(ctx, email, oidcIssuer, oidcSubject, role string) (*model.User, error)
GetUserByOIDCSubject(ctx, issuer, subject string) (*model.User, error)
SetUserOIDCIdentity(ctx, userID, issuer, subject string) error

// SCIM lifecycle
SetUserActive(ctx, userID string, active bool) error
DeleteAllTokensForUser(ctx, userID string) error

// SCIM tokens
CreateSCIMToken(ctx, *model.SCIMToken) error
GetSCIMTokenByHash(ctx, hash string) (*model.SCIMToken, error)
ListSCIMTokens(ctx) ([]*model.SCIMToken, error)
DeleteSCIMToken(ctx, id string) error

// SCIM group→role mappings
SetSCIMGroupRole(ctx, scimExternalID, displayName string, projectID, envID *string, role string) (*model.SCIMGroupRole, error)
ListSCIMGroupRoles(ctx) ([]*model.SCIMGroupRole, error)
ListSCIMGroupRolesByExternalID(ctx, scimExternalID string) ([]*model.SCIMGroupRole, error)
GetSCIMGroupRole(ctx, id string) (*model.SCIMGroupRole, error)
DeleteSCIMGroupRole(ctx, id string) error
```

OIDC/user methods are implemented in `postgres_users.go` / `sqlite_users.go`; SCIM methods in `postgres_scim.go` / `sqlite_scim.go`. User scans use `sql.NullString` for all nullable columns.

---

## OIDC Login + JIT Provisioning

### OIDC Package (`internal/oidc/`)

**`provider.go`** — wraps `github.com/coreos/go-oidc/v3`:

```go
type Config struct {
    Issuer       string // IdP discovery URL base
    ClientID     string
    ClientSecret string
    RedirectURL  string
}

func New(ctx context.Context, cfg Config) (*Provider, error)

// BeginAuth generates PKCE code_verifier + nonce, signs state JWT, returns auth URL.
func (p *Provider) BeginAuth(cliCallback string) (authURL, stateToken string, err error)

// CompleteAuth verifies state, exchanges code (PKCE), verifies ID token.
func (p *Provider) CompleteAuth(ctx context.Context, code, state string) (claims *Claims, cliCallback string, err error)
```

The `Claims` type carries `Issuer`, `Subject`, and `Email` from the ID token.

**`state.go`** — stateless OIDC state:

State is an HMAC-SHA256-signed token (no server-side session storage). Format:
```
base64url(json({cv, nonce, cli_callback, exp})) + "." + base64url(HMAC-SHA256(key, payload))
```
The HMAC key is `SHA-256(VAULT_OIDC_CLIENT_SECRET)`. State expires in 10 minutes.

PKCE code_challenge is computed as `base64url(SHA-256(code_verifier))` (S256 method), per RFC 7636.

### API Handlers (`internal/api/auth_oidc.go`)

| Route | Handler | Description |
|-------|---------|-------------|
| `GET /api/v1/auth/oidc/config` | `handleOIDCConfig` | Returns `{"enabled": true/false, "enforce": bool}` |
| `GET /api/v1/auth/oidc/login` | `handleOIDCLogin` | Calls `BeginAuth`, returns `{"authorization_url": "..."}` |
| `GET /api/v1/auth/oidc/callback` | `handleOIDCCallback` | Calls `CompleteAuth`, JIT-provisions, issues token |

**JIT provisioning** (`jitProvision` in `auth_oidc.go`):

```
1. GetUserByOIDCSubject(issuer, subject) → found: return existing user
2. GetUserByEmail(email) → found: SetUserOIDCIdentity + return user (link, log auth.oidc.identity_linked)
3. Not found: CreateOIDCUser(email, issuer, subject, "member") (log auth.oidc.jit_provision)
```

New OIDC users are provisioned with `member` role. Admins can upgrade the role via the admin API or via SCIM group→role mapping.

**Callback flow:**
1. Verify `error` query param (IdP error redirect)
2. Extract `code` and `state`
3. `CompleteAuth` → claims + optional `cliCallback`
4. `jitProvision` → vault user
5. Check `user.Active` (SCIM deprovisioning guard)
6. `IssueUserToken` → session token
7. If `cliCallback == "vault://portal"` → seal token into `vault_portal` cookie + `302 /portal` (admin portal flow — see `web_portal.go`)
8. Else if `cliCallback` set → `302 Location: cliCallback?token=<raw>` (CLI loopback flow)
9. Otherwise → `200 {"token": "...", "name": "session"}` (programmatic web flow)

The portal flow reuses the same `BeginAuth`/`CompleteAuth`/`jitProvision` machinery and the same IdP redirect URI — there is no second OAuth client registration. The `vault://portal` sentinel is opaque to the IdP because the redirect URI it sees is still `/api/v1/auth/oidc/callback`; the discrimination happens after the IdP returns control.

### Server Integration (`internal/api/server.go`)

```go
type Server struct {
    // ... existing fields ...
    oidc        *oidcpkg.Provider // nil when not configured
    oidcEnforce bool              // true = local login/signup returns 403
    cookieKey   []byte            // 32 bytes; nil disables /portal/*
    portalTmpl  *tmplManager      // lazy-initialised when cookieKey is set
    allowReg    bool              // VAULT_ALLOW_REGISTRATION; ignored when oidcEnforce
}

func New(st store.Store, kp crypto.KeyProvider, projectKP *crypto.ProjectKeyCache,
         log *slog.Logger, cfg api.Config) *Server
```

`api.Config` carries `OIDC`, `OIDCEnforce`, `Sink`, `TrustedProxies`,
`AuthRatePerMin`, `PruneMinCount`, `PruneMinAge`, `CookieKey`, and
`AllowRegistration`.

### Enforce Mode (`internal/api/auth.go`)

When `VAULT_OIDC_ENFORCE=true`:

```go
// handleSignup
if s.oidcEnforce {
    writeError(w, 403, "local account creation is disabled — accounts are managed through the IdP")
    return
}

// handleLogin
if s.oidcEnforce {
    writeError(w, 403, "local authentication is disabled — use SSO")
    return
}
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_OIDC_ISSUER` | Yes (if OIDC) | IdP issuer URL; used to fetch OIDC discovery document |
| `VAULT_OIDC_CLIENT_ID` | Yes (if OIDC) | OAuth2 client ID registered with the IdP |
| `VAULT_OIDC_CLIENT_SECRET` | Yes (if OIDC) | OAuth2 client secret; also used to derive the state signing key |
| `VAULT_OIDC_REDIRECT_URI` | Yes (if OIDC) | Callback URL (e.g. `https://vault.example.com/api/v1/auth/oidc/callback`) |
| `VAULT_OIDC_ENFORCE` | No | Set to `"true"` to disable `/auth/login` and `/auth/signup` |
| `VAULT_ALLOW_REGISTRATION` | No | `"true"` enables self-service signup at `/portal/register`. First registrant is promoted to admin if no admin exists. Ignored when `VAULT_OIDC_ENFORCE=true`. |

OIDC is disabled (no env vars set) → `s.oidc == nil` → all OIDC endpoints return 404, local auth works normally.

### CLI `vault login --sso` (Future)

1. Start a local HTTP server on an available port (e.g. `http://localhost:PORT/callback`)
2. `GET /api/v1/auth/oidc/login?cli_callback=http://localhost:PORT/callback` → receive `authorization_url`
3. Open browser to `authorization_url`
4. User logs in at IdP → IdP redirects to `VAULT_OIDC_REDIRECT_URI`
5. vaultd issues token, redirects browser to `http://localhost:PORT/callback?token=<raw>`
6. CLI's local server receives `token`, saves to config, exits

---

## SCIM 2.0 Provisioning

### SCIM Handler (`internal/api/scim.go`)

**Authentication:** SCIM requests use SCIM bearer tokens (from `scim_tokens` table), not vault session tokens. Middleware `scimAuth` validates the token hash:

```go
func (s *Server) scimAuth(next http.HandlerFunc) http.HandlerFunc
```

**Content-Type:** All SCIM responses use `application/scim+json`.

### Users Endpoints

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| `GET` | `/scim/v2/Users` | `handleSCIMListUsers` | List all users |
| `POST` | `/scim/v2/Users` | `handleSCIMCreateUser` | Provision new user |
| `GET` | `/scim/v2/Users/{id}` | `handleSCIMGetUser` | Get user by vault ID |
| `PUT` | `/scim/v2/Users/{id}` | `handleSCIMReplaceUser` | Full replace |
| `PATCH` | `/scim/v2/Users/{id}` | `handleSCIMPatchUser` | Partial update (deactivation) |
| `DELETE` | `/scim/v2/Users/{id}` | `handleSCIMDeleteUser` | Deactivate (soft delete) |

**Deactivation flow** (`applyActiveChange` in `scim.go`):

```go
SetUserActive(ctx, userID, false)
DeleteAllTokensForUser(ctx, userID)  // invalidate all active sessions
logAudit(..., ActionSCIMUserDeactivate, ...)
```

**PATCH deactivation** (Okta/Azure AD pattern):

```json
{
  "Operations": [{"op": "Replace", "path": "active", "value": false}]
}
```

The handler `handleSCIMPatchUser` handles both bare-bool values and the object-form `{"active": false}` sent by some IdPs.

**Create flow**: If email already exists, returns the existing user (idempotent). New users are created with empty `password_hash` (OIDC-only) and `active = true`. OIDC identity is linked on first login via JIT provisioning.

**Delete**: Deactivates the user (sets `active=false`, deletes tokens) rather than hard-deleting, to preserve audit log references.

### Groups Endpoints

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| `GET` | `/scim/v2/Groups` | `handleSCIMListGroups` | List configured group→role mappings |
| `POST` | `/scim/v2/Groups` | `handleSCIMCreateGroup` | Accept group from IdP |
| `GET` | `/scim/v2/Groups/{id}` | `handleSCIMGetGroup` | Get group |
| `PUT` | `/scim/v2/Groups/{id}` | `handleSCIMReplaceGroup` | Sync group members |
| `PATCH` | `/scim/v2/Groups/{id}` | `handleSCIMPatchGroup` | Partial group update |
| `DELETE` | `/scim/v2/Groups/{id}` | `handleSCIMDeleteGroup` | Delete group role mapping |

Vault has no native "group" concept. Groups are mapped to project roles via `scim_group_roles`. When the IdP pushes a group with members, `syncGroupMembers` calls `AddProjectMember` for each user+mapping combination.

### Discovery Endpoints

| Path | Description |
|------|-------------|
| `GET /scim/v2/ServiceProviderConfig` | Reports SCIM capabilities (PATCH: supported, filter: supported subset, bulk: not supported) |
| `GET /scim/v2/ResourceTypes` | Lists User and Group resource types |
| `GET /scim/v2/Schemas` | Returns empty schema list |

### Supported SCIM filter subset

`GET /scim/v2/Users` and `GET /scim/v2/Groups` accept the `filter` query parameter for a deliberately small subset of RFC 7644 §3.4.2.2:

```
filter=<attribute> eq "<value>"
```

| Resource | Allowed attributes |
|----------|--------------------|
| Users    | `userName`, `externalId`, `id` |
| Groups   | `displayName`, `id` |

Anything outside this whitelist — other operators (`co`, `sw`, `ew`, `ne`, `gt`, `ge`, `lt`, `le`, `pr`), conjunctions (`and`, `or`), grouped expressions (`(...)`), `not`, or off-whitelist attributes — returns `400 Bad Request` with `scimType: "invalidFilter"`.

This subset is sufficient for Okta and Azure AD (which only emit equality filters in practice) and lets outbound SCIM clients re-resolve users by externalId after a stale-cache 404. Implemented in `internal/api/scim_filter.go`. Persistence of `externalId` is wired through `SetUserSCIMExternalID` so filtered lookups round-trip correctly across IdP re-syncs.

Examples:
```
GET /scim/v2/Users?filter=userName eq "alice@example.com"
GET /scim/v2/Users?filter=externalId eq "abc-123"
GET /scim/v2/Groups?filter=displayName eq "Engineering"
```

### SCIM Token Management (Admin API)

```
POST   /api/v1/scim/tokens             — create token (returns raw token once)
GET    /api/v1/scim/tokens             — list tokens (no raw values returned)
DELETE /api/v1/scim/tokens/{id}        — revoke token
```

```
POST   /api/v1/scim/group-roles        — map IdP group → vault project role
GET    /api/v1/scim/group-roles        — list all mappings
DELETE /api/v1/scim/group-roles/{id}   — remove mapping
```

**Create group-role request body:**
```json
{
  "scim_external_id": "idp-group-uuid",
  "display_name": "Engineering",
  "project_slug": "my-project",
  "env_slug": "production",
  "role": "editor"
}
```
`env_slug` is optional; omit for project-level access.

---

## Operating Modes

| Mode | `VAULT_OIDC_ENFORCE` | `VAULT_OIDC_*` set | Behavior |
|------|---------------------|---------------------|---------|
| Local only | unset | No | `/auth/login` + `/auth/signup` work; OIDC routes 404 |
| Mixed | unset | Yes | Both local and OIDC auth work |
| SSO enforce | `true` | Yes | `/auth/login` + `/auth/signup` return 403; only OIDC works |

**Break-glass in enforce mode**: Set `VAULT_OIDC_ENFORCE=false` and restart, or patch the DB directly. There is no built-in local admin fallback.

---

## Authentik Setup Reference

1. Create an **OAuth2/OpenID Provider**:
   - Name: `vault`
   - Client type: Confidential
   - Redirect URIs: `https://vault.example.com/api/v1/auth/oidc/callback`
   - Scopes: `openid email profile`

2. Create an **Application** linked to the provider.

3. Note the `Issuer URL` (e.g. `https://authentik.example.com/application/o/vault/`), `Client ID`, and `Client Secret`.

4. Configure vault:
   ```
   VAULT_OIDC_ISSUER=https://authentik.example.com/application/o/vault/
   VAULT_OIDC_CLIENT_ID=<client-id>
   VAULT_OIDC_CLIENT_SECRET=<client-secret>
   VAULT_OIDC_REDIRECT_URI=https://vault.example.com/api/v1/auth/oidc/callback
   ```

5. For SCIM:
   - Enable SCIM in the Authentik application settings.
   - Base URL: `https://vault.example.com/scim/v2/`
   - Token: value from `POST /api/v1/scim/tokens`.

---

## IdP Compatibility

| IdP | OIDC | SCIM | Notes |
|-----|------|------|-------|
| Authentik | ✓ | ✓ | Primary target |
| **tokyo3-auth** | ✓ | ✓ | Sibling project; see "tokyo3-auth as IdP" below for the closed-loop setup |
| Okta | ✓ | ✓ | PATCH uses `{"op":"Replace","path":"active","value":false}` |
| Azure AD / Entra | ✓ | ✓ | PATCH uses object-form active |
| Keycloak | ✓ | Partial | SCIM via extension plugin |
| Dex | ✓ | ✗ | OIDC only |
| Auth0 | ✓ | ✓ | |
| Google Workspace | ✓ | ✗ | OIDC only |

---

## tokyo3-auth as IdP

`tokyo3-auth` (sibling project at `/auth/`) is a self-hosted OIDC provider with built-in outbound SCIM provisioning to vault. The integration closes the loop: auth owns identity, vault owns secrets, and membership flows automatically.

### Wiring

```
   ┌────────┐  user logs in via /auth        ┌──────────────┐
   │ vault  │ ──────────────────────────────▶│ tokyo3-auth  │
   │  CLI   │ (loopback redirect for token)  │   (OIDC)     │
   └────────┘                                │              │
       ▲                                     │              │
       │  /scim/v2/Users + Groups            │              │
       │ ◀───────────────────────────────────│ (SCIM client)│
       │                                     └──────────────┘
       └─ users/groups arrive in vault before they need access
```

- **OIDC**: vault is registered as an OAuth2 client in auth (`POST /admin/clients`); claims `sub`+`email`+`name` are read by vault's `jitProvision` to upsert users.
- **SCIM**: auth's `provision.Set` fans out user/group lifecycle events from every authoritative path (inbound SCIM, admin API, self-registration, portal admin) to vault's `/scim/v2`. Auth uses Phase 2's `filter=externalId eq` for stale-cache 404 self-heal.
- **Group → role**: vault's `scim_group_roles` table (operator-managed) maps `displayName` → `(project, env, role)`. When auth pushes a group with members, vault's `syncGroupMembers` binds each member to the correct project membership automatically.

### Setup

**On auth**:
```bash
# Register vault as a client (returns client_id + client_secret; secret shown once)
curl -X POST -H "Authorization: Bearer <auth-admin-token>" $AUTH/admin/clients \
  -d '{"name":"vault","redirect_uris":["https://vault.example.com/api/v1/auth/oidc/callback"],
       "scopes":["openid","email","profile","offline_access"],"public":false}'

# Set env on auth
AUTH_VAULT_SCIM_ENABLED=true
AUTH_VAULT_SCIM_URL=https://vault.example.com/scim/v2
AUTH_VAULT_SCIM_TOKEN=<minted on vault, see below>
```

**On vault**:
```bash
# 1. Mint a SCIM token for auth's outbound client
curl -X POST -H "Authorization: Bearer <vault-admin-token>" \
  $VAULT/api/v1/scim/tokens \
  -d '{"description":"tokyo3-auth -> vault"}'

# 2. Configure vault to use auth as the OIDC IdP
VAULT_OIDC_ISSUER=https://auth.example.com
VAULT_OIDC_CLIENT_ID=<from auth>
VAULT_OIDC_CLIENT_SECRET=<from auth>
VAULT_OIDC_REDIRECT_URI=https://vault.example.com/api/v1/auth/oidc/callback
VAULT_OIDC_ENFORCE=true   # disable local /auth/login + /auth/signup
```

**One-time backfill** (recommended order: provision before first SSO login to avoid the JIT-vs-SCIM email race):
```bash
authd admin sync --target=vault
```

### Verification

```bash
# OIDC config visible to vault CLI
curl -i $VAULT/api/v1/auth/oidc/config        # → enabled:true, enforce:true

# Login from CLI (Phase 1)
vault login --oidc                            # opens browser, captures token
vault projects list                           # any authenticated call confirms the token works

# SCIM provisioning round-trip (after creating a user in auth)
curl -H "Authorization: Bearer $SCIM_TOKEN" \
  "$VAULT/scim/v2/Users?filter=externalId%20eq%20%22<auth-user-uuid>%22" \
  | jq '.totalResults'                         # → 1

# Deactivation revokes vault tokens
# (PATCH active=false on auth → vault SetUserActive(false) + DeleteAllTokensForUser)
```

---

## Security Considerations

- **PKCE (S256)** is required even though `VAULT_OIDC_CLIENT_SECRET` is set. PKCE protects the CLI localhost callback against authorization code interception attacks.
- **Nonce** in the ID token prevents replay attacks.
- **State token HMAC** uses `SHA-256(client_secret)` as key; 10-minute expiry prevents CSRF.
- **Back-channel token exchange**: `VAULT_OIDC_CLIENT_SECRET` is only sent server-to-server (never reaches the browser).
- **SCIM tokens** are stored as SHA-256 hashes only; the raw token is shown once at creation.
- **Deactivation** deletes all sessions atomically-ish (two sequential DB calls). If the server crashes between them, the user remains deprovisioned but old tokens are not deleted — a subsequent SCIM PATCH/DELETE will retry and clean up.

---

## mTLS for Non-SPIFFE Certificates

This section extends `cert_principals` to support email SAN (`rfc822Name`) in addition to SPIFFE URI SANs, enabling engineers to authenticate with personal x.509 certificates (corporate PKI, Teleport tbot) without a browser OIDC flow.

### Schema (migration `014_cert_email_san`)

```sql
-- postgres
ALTER TABLE cert_principals ALTER COLUMN spiffe_id DROP NOT NULL;
ALTER TABLE cert_principals ADD COLUMN email_san TEXT;
CREATE UNIQUE INDEX cert_principals_email_san ON cert_principals(email_san) WHERE email_san IS NOT NULL;
ALTER TABLE cert_principals ADD CONSTRAINT cert_principals_has_identifier
    CHECK (spiffe_id IS NOT NULL OR email_san IS NOT NULL);
```

SQLite uses full table recreation (same logical schema).

### Registration API

```
POST /api/v1/cert-principals
{
  "description": "alice workstation",
  "email_san": "alice@corp.example.com",   // one of spiffe_id or email_san required
  "project": "myapp",                       // optional scope
  "read_only": false,
  "expires_in": "8760h"
}
```

Exactly one identifier (`spiffe_id` or `email_san`) must be provided. `email_san` is validated with `net/mail.ParseAddress`.

### Auth flow (`internal/api/certs.go — authFromClientCert`)

```
client cert present?
  ├── has URI SAN with spiffe:// scheme?
  │     → GetCertPrincipalBySPIFFEID; if found → authorize
  └── has email SANs?
        → GetCertPrincipalByEmailSAN (first match); if found → authorize
  └── no match → errCertUnregistered → fall through to bearer token
```

After looking up a principal, `checkPrincipalUserActive` verifies the owning user's `active` flag (fail-closed: DB errors also reject). This ensures SCIM-deprovisioned users cannot authenticate via their registered certificates.

### CLI

```
# SPIFFE workload identity (existing)
vault principals register "myapp-server" \
  --spiffe-id spiffe://cluster.local/ns/myapp/sa/server \
  --project myapp --env production

# Email SAN for human users (new)
vault principals register "alice workstation" \
  --email-san alice@corp.example.com \
  --project myapp

vault principals list    # TYPE column shows "spiffe" or "email"
vault principals revoke <id>
```

### Store interface additions

```go
GetCertPrincipalByEmailSAN(ctx context.Context, emailSAN string) (*model.CertPrincipal, error)
```

### Security notes

- The `email_san` value on the registered principal must exactly match the cert's `rfc822Name` SAN (case-sensitive byte comparison at the DB layer).
- Certificate trust is still enforced by `VAULT_API_CLIENT_CA` — any cert that reaches the SAN-matching step has already been verified against the trusted CA.
- Active-user check applies to both SPIFFE and email SAN principals.
