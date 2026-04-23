# Data Flows

> Step-by-step traces of the most important operations.

## Server startup

```
main()
 ├─ openKeyProvider()        — parse VAULT_MASTER_KEY / VAULT_KMS_KEY_ID
 ├─ openStore()              — open Postgres or SQLite; apply pending migrations
 ├─ NewProjectKeyCache(kp)   — in-memory PEK cache, TTL from VAULT_PROJECT_KEY_CACHE_TTL
 ├─ NewRevoker(...)          — background goroutine: sweep expired leases immediately,
 │                            then every 60 s
 ├─ buildServerTLS()         — load cert files (hot-reload) or generate self-signed
 └─ http.Server.ListenAndServeTLS()
```

All routes pass through the `limitBody` middleware (4 MB cap) and then the per-route `auth` middleware.

## Authentication middleware (every protected request)

```
request arrives
 ├─ TLS connection has PeerCertificates?
 │   ├─ YES → extract spiffe:// URI SAN from leaf cert
 │   │         lookup cert_principals by spiffe_id
 │   │         ├─ not found   → fall through to bearer
 │   │         ├─ expired     → 401
 │   │         └─ found       → build ephemeral *model.Token, inject into ctx
 │   └─ NO  → proceed to bearer
 │
 └─ bearer: "Authorization: Bearer <raw>"
             SHA-256(raw) → lookup tokens table
             ├─ not found  → 401
             ├─ expired    → 401
             └─ valid      → inject *model.Token into ctx
```

## Reading a secret

```
GET /v1/projects/{project}/envs/{env}/secrets/{key}
 │
 ├─ auth middleware         — token injected into ctx
 ├─ store.GetProject(slug)
 ├─ authorize(tok, project, env)
 │   ├─ machine token       → scope check (project_id match; optional env_id match)
 │   └─ user token          → GetProjectMemberForEnv or GetProjectMember
 │
 ├─ store.GetSecret(project, env, key)
 │   └─ includes current_version_id → fetches SECRET_VERSION row
 │
 ├─ projectKP.ForProject(project.ID, project.EncryptedPEK)
 │   ├─ cache hit           → return cached projectKeyProvider (no KMS call)
 │   └─ cache miss          → kp.UnwrapDEK(encPEK) [may call AWS KMS] → cache
 │
 ├─ crypto.DecryptSecret(projectKP, encDEK, encValue)
 │   └─ projectKP.UnwrapDEK(encDEK) → 32-byte DEK
 │      AES-256-GCM open(DEK, encValue) → plaintext
 │
 ├─ store.CreateAuditLog(action=secret.get, resource=key, metadata={masked value})
 └─ JSON response: {key, value, version, ...}
```

## Writing a secret

```
PUT /v1/projects/{project}/envs/{env}/secrets/{key}
 │
 ├─ auth middleware
 ├─ store.GetProject → authorize → requireWrite (editor+ or non-read-only machine token)
 ├─ validate key format: ^[A-Z][A-Z0-9_]*$
 │
 ├─ projectKP.ForProject(...)          — resolve project key provider
 ├─ crypto.EncryptSecret(projectKP, plaintext)
 │   ├─ rand.Read(32)                  — fresh DEK
 │   ├─ AES-256-GCM seal(DEK, plaintext) → encValue (nonce||ciphertext)
 │   └─ projectKP.WrapDEK(DEK)        → encDEK
 │
 ├─ store.SetSecret(project, env, key, encValue, encDEK, createdBy)
 │   ├─ INSERT secret if not exists (with position = MAX+1)
 │   ├─ INSERT secret_version (version = MAX+1)
 │   └─ UPDATE secret.current_version_id
 │
 ├─ store.CreateAuditLog(action=secret.set, metadata={masked value})
 └─ 204 No Content
```

## Issuing dynamic credentials

```
POST /v1/projects/{project}/envs/{env}/dynamic/{backend}/roles/{role}/creds
 │
 ├─ auth middleware → requireWrite
 ├─ store.GetDynamicBackend(project, env, slug)
 ├─ store.GetDynamicRole(backend.ID, roleName)
 │
 ├─ dynamic.EffectiveTTL(backend, role, requestedTTL)
 │   └─ role.TTL ?? backend.DefaultTTL, capped at backend.MaxTTL
 │
 ├─ projectKP.ForProject(...)
 ├─ issuer.Issue(ctx, projectKP, backend, role, ttl)
 │   ├─ kp.UnwrapDEK(backend.EncryptedConfigDEK) → configDEK
 │   │  AES-256-GCM open(configDEK, backend.EncryptedConfig) → config JSON
 │   ├─ connect to target database (e.g. Postgres)
 │   ├─ generate: username = "vault_" + 16-char hex
 │   │            password = 48-char hex (24 random bytes)
 │   ├─ interpolate creation_tmpl: {{username}}, {{password}}, {{expiry}}
 │   └─ execute SQL on target database
 │
 ├─ store.CreateDynamicLease(
 │       project, env, backend, role,
 │       role_name (snapshot), username,
 │       revocation_tmpl (snapshot),   ← denormalized so deletion of role/backend
 │       expires_at, created_by)        ← doesn't block future revocation
 │
 ├─ store.CreateAuditLog(action=dynamic.lease.issue, metadata={username, ttl, masked password})
 └─ JSON response: {username, password, expires_at, lease_id}
     NOTE: password is returned exactly once and never stored in plaintext.
```

## Automatic lease revocation (background)

```
Revoker.Run(ctx)
 ├─ sweep() immediately on startup    — catch leases that expired while server was down
 └─ time.Ticker(60s) → sweep()

sweep():
 ├─ store.ListExpiredDynamicLeases()  — WHERE revoked_at IS NULL AND expires_at < NOW()
 └─ for each lease:
     revokeLease(lease)
      ├─ store.GetDynamicBackendByID(lease.BackendID)
      │   └─ ErrNotFound → store.RevokeDynamicLease (skip template; backend gone)
      ├─ projectKP.ForProject(backend.ProjectID, encPEK)
      ├─ issuer.Revoke(projectKP, backend, lease.RevocationTmpl, lease.Username)
      │   ├─ decrypt backend config
      │   ├─ connect to target database
      │   ├─ interpolate revocation_tmpl with {{username}}
      │   └─ execute SQL
      └─ store.RevokeDynamicLease(lease.ID)   — marks revoked_at = NOW()
          NOTE: if Revoke() fails, the lease is NOT marked revoked.
                The next sweep will retry (every 60 s).
```

## SPIFFE principal registration

```
POST /v1/principals
 │
 ├─ auth middleware (bearer token required; SPIFFE auth is for workloads, not humans)
 ├─ requireUnscoped — machine tokens cannot register principals
 ├─ tok.UserID != nil — principals are owned by a human user
 ├─ validate spiffe_id: url.Parse + scheme == "spiffe" && host != ""
 ├─ resolveTokenScope(project, env) — optional scoping, same logic as machine tokens
 ├─ store.CreateCertPrincipal(principal)
 ├─ store.CreateAuditLog(action=cert.principal.register, resource=spiffe_id)
 └─ 201 Created {id, description, spiffe_id, project_id, env_id, ...}
```

## Key migration (`vaultd migrate-keys`)

```
runMigrateKeys(ctx, store, kp)
 └─ store.ListProjects()
     for each project where encrypted_pek IS NULL:
      ├─ rand.Read(32)                     — new PEK
      ├─ kp.WrapDEK(pek)                  → encPEK  (may call KMS)
      ├─ store.SetProjectKey(project.ID, encPEK)
      │
      └─ store.RewrapProjectDEKs(project.ID, func(oldEncDEK) newEncDEK):
          ├─ kp.UnwrapDEK(oldEncDEK)      — unwrap under server KEK
          └─ projectKP.WrapDEK(dek)       — re-wrap under new PEK
          (entire rewrap is one DB transaction per project)
```

Projects with `encrypted_pek != NULL` are silently skipped — safe to re-run at any time.

## dotenv upload

```
POST /v1/projects/{project}/envs/{env}/secrets/dotenv
 │
 ├─ auth middleware → requireWrite
 ├─ io.ReadAll(r.Body)                — body already capped at 4 MB by limitBody
 ├─ dotenv.Parse(body)               — returns []dotenv.Entry{Key, Value, Comment}
 │
 └─ for each entry:
     ├─ projectKP.ForProject(...)    — resolved once, shared across all secrets
     ├─ crypto.EncryptSecret(kp, value)
     └─ store.SetSecret(...)
 │
 ├─ store.CreateAuditLog(action=secret.dotenv_upload, metadata={count})
 └─ 204 No Content
```

## Secret rollback

```
POST /v1/projects/{project}/envs/{env}/secrets/{key}/rollback
 body: {"version": N}
 │
 ├─ auth middleware → requireWrite
 ├─ store.GetSecret(project, env, key)
 ├─ store.ListSecretVersions(secret.ID)   — fetch all versions
 ├─ find requested version N
 │   └─ not found → 404
 ├─ store.RollbackSecret(secret.ID, version.ID)
 │   └─ UPDATE secret SET current_version_id = version.ID
 ├─ store.CreateAuditLog(action=secret.rollback, metadata={version})
 └─ 204 No Content
     NOTE: a rollback does NOT delete newer versions; they remain available for
           another rollback or audit purposes.
```
