# api package

HTTP handlers for vaultd. All routes go through the `auth` middleware in `middleware.go`.

## File map

| File | Handles |
|------|---------|
| `server.go` | `Server` struct, `New()`, `Routes()` — edit here to add routes |
| `middleware.go` | `auth`, `authorize`, `requireWrite`, `requireOwner`, role helpers |
| `auth.go` | `/auth/signup`, `/auth/login`, `/auth/logout`, `/auth/change-password` |
| `auth_oidc.go` | `/auth/oidc/*` — OIDC authorize + callback + JIT provisioning |
| `tokens.go` | machine token CRUD |
| `projects.go` | project CRUD |
| `environments.go` | environment CRUD |
| `members.go` | project membership management |
| `secrets.go` | secret CRUD, envfile upload/download, rollback |
| `dynamic.go` | dynamic backends, roles, credential issuance, lease management |
| `certs.go` | cert principal registration + `authFromClientCert` (mTLS auth helper) |
| `access.go` | unified access view per project/env |
| `audit.go` | audit log queries (reads from `auditStore`) + **all action string constants** + `logAudit`/`logAuditEnv` helpers |
| `users.go` | server-admin user management |
| `scim.go` | SCIM 2.0 Users + Groups endpoints + SCIM token management |
| `web.go` | embedded `web/` template + static FS, `tmplManager`, `staticHandler` |
| `web_portal.go` | `/portal/*` self-service: login (local + OIDC sentinel), register, account, tokens. Cookie helpers (`set/read/clearPortalCookie`), `portalAuth` middleware, `loginUser` (shared with JSON `handleLogin`), `flashRedirect`, `portalMeta` |
| `web_portal_admin.go` | `/portal/admin/*` admin-only: users, SCIM tokens, SCIM group→role mappings, projects (envs + members) |

## Adding a handler

1. Add the method to the appropriate handler file
2. Register the route in `server.go` → `Routes()`
3. Add an action constant in `audit.go` if it's auditable
4. Call `s.logAudit` or `s.logAuditEnv` **and check the error** (fail-closed):
   ```go
   // non-env actions (auth, user, member, cert, project-level):
   if err := s.logAudit(r, ActionXxx, projectID, resource); err != nil {
       writeError(w, http.StatusInternalServerError, "audit unavailable")
       return
   }
   // env-scoped actions (secrets, dynamic):
   if err := s.logAuditEnv(r, ActionXxx, projectID, envID, resource, metadata); err != nil {
       writeError(w, http.StatusInternalServerError, "audit unavailable")
       return
   }
   ```

## Auth flow (middleware.go)

```
mTLS cert present?
  SPIFFE URI SAN → GetCertPrincipalBySPIFFEID
  email SAN      → GetCertPrincipalByEmailSAN
  no match       → errCertUnregistered → fall through
Bearer token → auth.Validate
```

## Portal flow (web_portal.go)

```
portalAuth → readPortalCookie (AES-256-GCM unseal, base64url) → auth.Validate
  → expiry check → slide if IsSession → reject if !UserID
  → GetUserByID → reject if !Active → set both portalCtxKey and tokenKey in ctx
```

Portal handlers reuse `s.logAudit*` because `tokenKey` is set in the request
context. Use `flashRedirect(w, r, path, "error"|"success"|"token", msg)` for
all portal redirects (escapes via `url.Values`) and `portalMeta(map)` for
audit metadata (always tags `via=portal`). New portal handlers register on
the `s.portalAuth` or `s.portalAdminAuth` middleware in `server.go`.

## Testing

`mock_store_test.go` defines `mockStore` — embeds `mockstore.Stub` + function fields for test overrides. Use `newTestServer(t, st)` to build a test server with a given store.
