# OIDC/SSO & SCIM Integration

This document covers the technical implementation of IdP integration: Phase 1 (OIDC login + JIT provisioning) and Phase 2 (SCIM 2.0 lifecycle provisioning).

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
    id TEXT PRIMARY KEY, group_id TEXT NOT NULL, display_name TEXT NOT NULL,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    env_id TEXT REFERENCES environments(id) ON DELETE CASCADE,
    role TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, project_id, env_id)
);
```

`active = false` means deprovisioned by SCIM. All existing tokens are deleted when a user is deactivated; new logins are blocked. `scim_group_roles` maps IdP group IDs to vault project roles and drives automatic project membership on SCIM group sync.

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
    ID          string
    GroupID     string
    DisplayName string
    ProjectID   *string
    EnvID       *string
    Role        string
    CreatedAt   time.Time
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
SetSCIMGroupRole(ctx, groupID, displayName string, projectID, envID *string, role string) (*model.SCIMGroupRole, error)
ListSCIMGroupRoles(ctx) ([]*model.SCIMGroupRole, error)
GetSCIMGroupRole(ctx, id string) (*model.SCIMGroupRole, error)
DeleteSCIMGroupRole(ctx, id string) error
```

Both `internal/store/postgres/postgres.go` and `internal/store/sqlite/sqlite.go` implement all methods. User scans use `sql.NullString` for all nullable columns.

---

## Phase 1: OIDC Login + JIT Provisioning

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
7. If `cliCallback` set → `302 Location: cliCallback?token=<raw>` (CLI flow)
8. Otherwise → `200 {"token": "...", "name": "session"}` (web flow)

### Server Integration (`internal/api/server.go`)

```go
type Server struct {
    // ... existing fields ...
    oidc        *oidcpkg.Provider // nil when not configured
    oidcEnforce bool              // true = local login/signup returns 403
}

func New(st, kp, projectKP, log, oidcProvider *oidcpkg.Provider, oidcEnforce bool) *Server
```

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

OIDC is disabled (no env vars set) → `s.oidc == nil` → all OIDC endpoints return 404, local auth works normally.

### CLI `vault login --sso` (Future)

1. Start a local HTTP server on an available port (e.g. `http://localhost:PORT/callback`)
2. `GET /api/v1/auth/oidc/login?cli_callback=http://localhost:PORT/callback` → receive `authorization_url`
3. Open browser to `authorization_url`
4. User logs in at IdP → IdP redirects to `VAULT_OIDC_REDIRECT_URI`
5. vaultd issues token, redirects browser to `http://localhost:PORT/callback?token=<raw>`
6. CLI's local server receives `token`, saves to config, exits

---

## Phase 2: SCIM 2.0 Provisioning

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
| `GET /scim/v2/ServiceProviderConfig` | Reports SCIM capabilities (PATCH: supported, bulk: not supported) |
| `GET /scim/v2/ResourceTypes` | Lists User and Group resource types |
| `GET /scim/v2/Schemas` | Returns empty schema list |

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
  "group_id": "idp-group-uuid",
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
| Okta | ✓ | ✓ | PATCH uses `{"op":"Replace","path":"active","value":false}` |
| Azure AD / Entra | ✓ | ✓ | PATCH uses object-form active |
| Keycloak | ✓ | Partial | SCIM via extension plugin |
| Dex | ✓ | ✗ | OIDC only |
| Auth0 | ✓ | ✓ | |
| Google Workspace | ✓ | ✗ | OIDC only |

---

## Security Considerations

- **PKCE (S256)** is required even though `VAULT_OIDC_CLIENT_SECRET` is set. PKCE protects the CLI localhost callback against authorization code interception attacks.
- **Nonce** in the ID token prevents replay attacks.
- **State token HMAC** uses `SHA-256(client_secret)` as key; 10-minute expiry prevents CSRF.
- **Back-channel token exchange**: `VAULT_OIDC_CLIENT_SECRET` is only sent server-to-server (never reaches the browser).
- **SCIM tokens** are stored as SHA-256 hashes only; the raw token is shown once at creation.
- **Deactivation** deletes all sessions atomically-ish (two sequential DB calls). If the server crashes between them, the user remains deprovisioned but old tokens are not deleted — a subsequent SCIM PATCH/DELETE will retry and clean up.

---

## Phase 3: mTLS for Human Users (Future)

The existing `authFromSPIFFECert` in `internal/api/certs.go` already constructs user-level virtual tokens when `p.UserID` is set. Phase 3 would extend `cert_principals` matching to accept email SAN (`rfc822Name`) in addition to URI SAN (SPIFFE IDs), enabling engineers to authenticate with their personal x.509 certificates (e.g. from a corporate PKI or Teleport's tbot) without going through an OIDC browser flow.

No new protocol machinery is needed — only extended SAN matching in `authFromSPIFFECert` and a new principal type in the `cert_principals` table.
