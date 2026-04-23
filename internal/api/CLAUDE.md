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
| `secrets.go` | secret CRUD, dotenv import/export, rollback |
| `dynamic.go` | dynamic backends, roles, credential issuance, lease management |
| `certs.go` | cert principal registration + `authFromClientCert` (mTLS auth helper) |
| `access.go` | unified access view per project/env |
| `audit.go` | audit log queries (reads from `auditStore`) + **all action string constants** + `logAudit`/`logAuditMeta` helpers |
| `users.go` | server-admin user management |
| `scim.go` | SCIM 2.0 Users + Groups endpoints + SCIM token management |

## Adding a handler

1. Add the method to the appropriate handler file
2. Register the route in `server.go` → `Routes()`
3. Add an action constant in `audit.go` if it's auditable
4. Call `s.logAudit(r, ActionXxx, projectID, resource)` **and check the error** (fail-closed):
   ```go
   if err := s.logAudit(r, ActionXxx, projectID, resource); err != nil {
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

## Testing

`mock_store_test.go` defines `mockStore` — embeds `mockstore.Stub` + function fields for test overrides. Use `newTestServer(t, st)` to build a test server with a given store.
