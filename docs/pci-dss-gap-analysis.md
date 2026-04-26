# PCI-DSS v4.0.1 Gap Analysis

| Field | Value |
|-------|-------|
| **Standard** | PCI-DSS v4.0.1 |
| **Assessment type** | Service Provider (SAQ D-SP / ROC Track 1) |
| **Subject** | Tokyo-3 Vault — secrets management server (`vaultd`) |
| **Last reviewed** | 2026-04-26 |
| **Reviewed by** | Szeto Bo |
| **Status** | In progress — P0 items unresolved |

## Scope

The vault server stores, transmits, and brokers access to secrets that may include cardholder data (CHD) or sensitive authentication data (SAD). Analysis covers the application codebase (`vaultd`, `vault`, `vault-audit`). Physical controls, network segmentation, and organisation-level policy requirements are flagged where they affect compliance posture but are noted as out-of-code-scope.

## Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Implemented and evidenced in code |
| ⚠️ | Partially implemented or requires deployment-time configuration |
| ❌ | Not implemented — gap exists |
| N/A | Not applicable to this system |

---

## Requirement 2 — Secure Configurations

| ID | Sub-req | Requirement | Status | Finding | Fix |
|----|---------|-------------|--------|---------|-----|
| 2-1 | 2.2.7 | All non-console admin access encrypted | ✅ | HTTPS enforced via `ListenAndServeTLS`; self-signed cert path logs a warning | — |
| 2-2 | 2.2.1 | Configuration standards documented | ⚠️ | Env-var reference exists in `docs/architecture.md` and `cmd/vaultd/main.go` godoc; no formal hardening baseline or CIS-style checklist | Add deployment hardening checklist to docs |
| 2-3 | 4.2.1 | TLS minimum version explicitly enforced | ❌ | `buildServerTLS()` creates `tls.Config{}` with no `MinVersion` set. Go 1.22 server default is TLS 1.2 but this is implicit — a future Go upgrade could change behaviour silently. PCI §4.2.1 requires **explicit** enforcement. | `cfg.MinVersion = tls.VersionTLS12` in `cmd/vaultd/main.go:buildServerTLS()` and `internal/tlsutil/` |
| 2-4 | 4.2.1 | Cipher suite restrictions | ❌ | No `CipherSuites` or `PreferServerCipherSuites` set. PCI prohibits RC4, DES, and suites lacking forward secrecy. Go's default list is acceptable but undocumented and not auditable. | Add explicit `CipherSuites` allowlist to `tls.Config` |

---

## Requirement 3 — Protect Stored Account Data

| ID | Sub-req | Requirement | Status | Finding | Fix |
|----|---------|-------------|--------|---------|-----|
| 3-1 | 3.5.1 | Strong cryptography for stored data | ✅ | AES-256-GCM with per-version random DEK; GCM provides authenticated encryption | — |
| 3-2 | 3.6 | Key management — three-tier hierarchy | ✅ | KEK → PEK → DEK; each layer isolated; PEK per-project | — |
| 3-3 | 3.6.1 | Keys protected from disclosure | ✅ | Token raw values never stored (SHA-256 hash only); DEK plaintext never persisted | — |
| 3-4 | 3.7.1 | Strong randomness for key generation | ✅ | `crypto/rand` / `io.ReadFull(rand.Reader, …)` throughout | — |
| 3-5 | 3.7.2 | Split knowledge / dual control for KEK | ❌ | `VAULT_MASTER_KEY` is a single 32-byte key accessible to any operator with env access. No Shamir secret sharing or HSM enforcement. `KMSKeyProvider` delegates this concern to AWS IAM; `LocalKeyProvider` (documented dev-only) has no such controls. If `LocalKeyProvider` is used in production this is critical. | Document `LocalKeyProvider` as non-compliant for production; add deployment gate that warns when `VAULT_MASTER_KEY` is set |
| 3-6 | 3.7.4 | Key rotation | ✅ | Automatic PEK rotation every 90 days; on-demand `POST /projects/{slug}/rotate-key`; DEKs re-wrapped atomically in same DB transaction | — |
| 3-7 | 3.7.6 | Retired keys decommissioned | ✅ | `RotateProjectPEK` re-wraps all DEKs; `ProjectKeyCache.Invalidate` clears stale cache | — |
| 3-8 | 3.3 | SAD not stored post-authorisation | ✅ | Raw tokens never stored; bcrypt hash only for passwords | — |

---

## Requirement 4 — Protect Cardholder Data in Transit

| ID | Sub-req | Requirement | Status | Finding | Fix |
|----|---------|-------------|--------|---------|-----|
| 4-1 | 4.2.1 | Strong cryptography for all transmission | ⚠️ | HTTPS enforced for client-facing API ✓. Outbound: Postgres `sslmode` not enforced by vault code — operators can connect with `sslmode=disable`. NATS mTLS is optional (`VAULT_NATS_CERT`). AWS KMS uses AWS SDK which enforces TLS. | Add startup assertion that rejects DSNs with `sslmode=disable`; log warning when NATS mTLS is unconfigured |
| 4-2 | 4.2.1 | TLS minimum version — outbound connections | ❌ | `tlsutil.FromFiles` assembles TLS config for Postgres/NATS with no `MinVersion` set | Set `MinVersion: tls.VersionTLS12` in `tlsutil.FromFiles` |
| 4-3 | 4.2.2 | Trusted certificates for external services | ⚠️ | Postgres and NATS accept custom CA via env vars; if CA unset, Go system trust store used — not explicitly verified in deployment docs | Document CA requirements as mandatory for production |

---

## Requirement 6 — Develop and Maintain Secure Systems

| ID | Sub-req | Requirement | Status | Finding | Fix |
|----|---------|-------------|--------|---------|-----|
| 6-1 | 6.2.4 | Practices preventing common vulnerabilities | ⚠️ | `gofmt` + `staticcheck` in pre-commit sequence. No `govulncheck`, `gosec`, or `semgrep` in documented CI pipeline. | Add `govulncheck ./...` to CI |
| 6-2 | 6.3.3 | Components free of known vulnerabilities | ❌ | No CVE tracking. `go.sum` prevents substitution attacks but does not surface vulnerabilities. No Dependabot or equivalent. | Enable `govulncheck` and Dependabot / `go mod audit` in CI |
| 6-3 | 6.4.1 | Web apps protected against OWASP Top 10 | ⚠️ | **SQL injection in dynamic templates** is a standing documented gap (`docs/security.md`): `{{username}}`, `{{password}}`, `{{expiry}}` use string substitution in operator-supplied SQL. Mitigated by restricting authorship to project owners, but not eliminated. | Parameterise substitution or implement a template allowlist; document compensating control |
| 6-4 | 6.4.2 | Automated solutions detecting web-app attacks | ❌ | No WAF, RASP, or anomaly detection | Infrastructure/deployment concern; document WAF requirement |
| 6-5 | 6.2.1 | Bespoke software based on security standards | ⚠️ | No formal secure-SDLC policy or threat model document | Produce threat model; reference in `docs/` |

---

## Requirement 7 — Restrict Access by Business Need

| ID | Sub-req | Requirement | Status | Finding | Fix |
|----|---------|-------------|--------|---------|-----|
| 7-1 | 7.2.1 | Access control model defined and enforced | ✅ | RBAC: viewer < editor < owner per project; server admin role; env-scoped membership; machine token project/env scoping | — |
| 7-2 | 7.2.2 | Access granted on need-to-know | ✅ | Per-project/env scope; `read_only` token flag; unscoped tokens constrained to project membership | — |
| 7-3 | 7.2.5 | Least privilege for all accounts | ⚠️ | Session tokens (`IssueUserToken`) never set `ExpiresAt` — sessions are indefinitely valid until explicitly revoked. Machine tokens have optional expiry that is not enforced. | Add configurable max session lifetime; warn on machine tokens with no expiry |
| 7-4 | 7.3.1 | Access controlled by IAM | ✅ | All protected routes wrapped by `s.auth()` middleware | — |
| 7-5 | 7.3.2 | Periodic access reviews | ❌ | No cross-project token or membership enumeration endpoint for administrators. `GET /api/v1/tokens` is per-user only. | Add admin-only `GET /api/v1/admin/access-report` endpoint listing all active tokens and memberships |

---

## Requirement 8 — Identify Users and Authenticate

> This requirement has the highest concentration of gaps.

| ID | Sub-req | Requirement | Status | Finding | Fix |
|----|---------|-------------|--------|---------|-----|
| 8-1 | 8.2.1 | All users have unique IDs | ✅ | UUID per user; email uniqueness enforced at DB level | — |
| 8-2 | 8.2.2 | Shared/group accounts prohibited | ✅ | No group login; SCIM provisions individual accounts | — |
| 8-3 | 8.2.4 | User credential lifecycle managed | ✅ | SCIM deprovisioning (`SetUserActive(false)` + `DeleteAllTokensForUser`); token invalidation on password change and admin reset | — |
| 8-4 | 8.2.6 | Inactive accounts disabled within 90 days | ❌ | No `last_login_at` column; no automated sweep to disable inactive accounts. `users.active` is only set by SCIM. | Add `last_login_at` to `users`; add background sweep to deactivate accounts idle > 90 days |
| 8-5 | 8.2.8 | Session idle timeout ≤ 15 minutes | ❌ | **Not implemented.** Session tokens have no inactivity timeout. An abandoned session remains valid until logout or password change. | Track `last_used_at` on tokens; reject tokens unused for > 15 min (or implement short-lived tokens with refresh) |
| 8-6 | 8.3.4 | Account lockout after ≤ 10 failed attempts; lockout ≥ 30 min | ❌ | **Critical gap.** Current rate limiting (`VAULT_AUTH_RATE_PER_MIN`) is per-IP and throttles rather than locks. An attacker using distributed IPs faces no per-account barrier. Failed attempts are audited but do not trigger account lock. | Add `failed_login_count` + `locked_until` columns to `users`; enforce in `handleLogin`; reset on success |
| 8-7 | 8.3.6 | Password minimum length ≥ 12 characters | ❌ | **Critical gap.** `validatePassword` (`internal/api/validate.go:8`) enforces only `len(password) < 8`. PCI-DSS v4.0.1 §8.3.6 raised the minimum to **12 characters**. | Change threshold in `validate.go`; add migration to force password reset for existing short passwords |
| 8-8 | 8.3.6 | Password complexity (mixed character classes) | ❌ | No uppercase/lowercase/numeric/special character requirements. | Extend `validatePassword` with character-class checks |
| 8-9 | 8.3.7 | Password history — cannot reuse last 4 passwords | ❌ | No `password_history` table. `UpdateUserPassword` replaces the hash directly with no prior-hash comparison. | Add `password_history` table; check against last 4 hashes before accepting new password |
| 8-10 | 8.3.9 | Password change required every 90 days (if no MFA) | ❌ | No `password_changed_at` column; no enforcement. Waived if §8.4 MFA is enforced for all access. | Add `password_changed_at`; enforce 90-day expiry at login; or satisfy via MFA mandate |
| 8-11 | 8.4.2 | MFA required for all non-console access into CDE | ❌ | **Critical gap.** Local authentication (`POST /auth/login`) has no second factor. OIDC SSO can delegate to an MFA-capable IdP, but `VAULT_OIDC_ENFORCE=true` is not the default. Admin users can authenticate with password only. | Either add TOTP/WebAuthn to local auth flow, or enforce `VAULT_OIDC_ENFORCE=true` in production with documented IdP MFA requirement |
| 8-12 | 8.6.1 | System/application accounts managed rigorously | ⚠️ | Machine tokens can have no expiry. No mandatory expiry at issuance or automated review. | Require `expires_in` for machine tokens; add max TTL cap |
| 8-13 | 8.6.3 | Passwords/credentials for service accounts rotated periodically | ❌ | No enforcement of machine token rotation. Long-lived tokens remain valid indefinitely. | Enforce mandatory expiry on machine tokens; add warning/report for tokens approaching max age |

---

## Requirement 10 — Log and Monitor All Access

| ID | Sub-req | Requirement | Status | Finding | Fix |
|----|---------|-------------|--------|---------|-----|
| 10-1 | 10.2.1 | Audit events captured (who/what/when/where) | ✅ | Comprehensive event coverage: auth, secrets, tokens, members, dynamic, SCIM; `actor_id`, `action`, `occurred_at`, `ip`, `resource` recorded | — |
| 10-2 | 10.2.1.a | Successful + failed authentication logged | ✅ | `auth.login`, `auth.login_failed`, `auth.signup`, `auth.logout` all covered; fail-closed | — |
| 10-3 | 10.2.1.b | Actions by privileged users logged | ✅ | Server admin actions (`user.create`, `scim.*`, `token.*`) are audited | — |
| 10-4 | 10.2.1.c | Changes to audit trail logged | ⚠️ | NATS stream `DenyDelete`/`DenyPurge` prevents in-stream deletion. Schema changes via admin DSN are not themselves audited by the vault. | Document admin DB access controls; consider DDL audit at DB level |
| 10-5 | 10.3.2 | Audit logs protected from destruction | ✅ | Separate `vault-audit` process with distinct credential; NATS `DenyDelete`, `DenyPurge`, `FileStorage` | — |
| 10-6 | 10.5.1 | Retain ≥ 12 months; ≥ 3 months immediately available | ✅ | NATS stream `MaxAge = 400 days`; JetStream consumer makes recent events immediately queryable | — |
| 10-7 | 10.5.1 | Audit DB retention bounded | ⚠️ | Audit DB (Postgres projection) grows indefinitely. NATS stream is authoritative at 400 days, but the queryable DB has no pruning. | Add scheduled `DELETE FROM audit_logs WHERE created_at < now() - interval '400 days'` |
| 10-8 | 10.6.1 | Time synchronisation (NTP, stratum ≤ 2) | ⚠️ | Vault uses `time.Now().UTC()` for all timestamps. NTP is not referenced in deployment documentation. | Add NTP configuration requirement to `docs/contributing.md` deployment notes |
| 10-9 | 10.7.1 | Failures of critical security controls detected | ❌ | Audit publish failure returns HTTP 500 (fail-closed) but generates no external alert. No dead-man switch if NATS connection drops silently between requests. No alerting on auth-failure surge. | Expose a health/metrics endpoint; integrate with alerting on NATS disconnect and failed-auth rate |
| 10-10 | 10.7.2 | Automated alerts for suspicious events | ❌ | No SIEM integration, no alerting pipeline, no threshold-based anomaly detection | Infrastructure/deployment concern; document SIEM integration requirement |

---

## Requirement 11 — Test Security Regularly

| ID | Sub-req | Requirement | Status | Finding | Fix |
|----|---------|-------------|--------|---------|-----|
| 11-1 | 11.3.1 | Internal vulnerability scans quarterly | ❌ | No `govulncheck` or equivalent in documented CI | Add to CI pipeline |
| 11-2 | 11.3.2 | External vulnerability scans by ASV | ❌ | Process gap — no ASV engagement documented | Engage ASV vendor |
| 11-3 | 11.4 | Penetration test annually | ❌ | Process gap — no pen-test record or scope document | Schedule annual penetration test |
| 11-4 | 11.5 | IDS/IPS | ❌ | No application-layer IDS/IPS | Infrastructure concern; document deployment requirement |
| 11-5 | 11.6 | Unauthorised changes to payment pages detected | N/A | Not a web payment page | — |

---

## Requirement 12 — Policies and Programs

> All items are process/people gaps outside the codebase. Listed for completeness.

| ID | Sub-req | Requirement | Status |
|----|---------|-------------|--------|
| 12-1 | 12.1 | Formal information security policy | ❌ |
| 12-2 | 12.3 | Targeted risk analysis per requirement | ❌ |
| 12-3 | 12.6 | Security awareness program | ❌ |
| 12-4 | 12.10 | Incident response plan tested annually | ❌ |

---

## Remediation Roadmap

### P0 — Assessor will issue findings without these

| Ref | Gap | Req | File / Location | Estimated Effort |
|-----|-----|-----|-----------------|-----------------|
| 8-7 | Raise minimum password length to 12 characters | 8.3.6 | `internal/api/validate.go:8` | XS |
| 8-8 | Add password complexity rules (mixed character classes) | 8.3.6 | `internal/api/validate.go` | XS |
| 8-6 | Per-account lockout after ≤ 10 failed attempts | 8.3.4 | New columns on `users`; `internal/api/auth.go:handleLogin` | M |
| 8-11 | MFA for local accounts — TOTP or mandate OIDC+MFA | 8.4.2 | New TOTP flow or `VAULT_OIDC_ENFORCE` hardening | L |
| 2-3 | Explicit `tls.VersionTLS12` minimum | 4.2.1 | `cmd/vaultd/main.go:buildServerTLS`, `internal/tlsutil/` | XS |

### P1 — High risk; resolve before next audit cycle or document compensating control

| Ref | Gap | Req | File / Location | Estimated Effort |
|-----|-----|-----|-----------------|-----------------|
| 8-5 | Session idle timeout ≤ 15 min | 8.2.8 | Token `last_used_at` tracking + check in `internal/api/middleware.go:auth` | M |
| 8-9 | Password history — reject reuse of last 4 | 8.3.7 | New `password_history` table + check in `handleChangePassword`, `handleResetUserPassword` | M |
| 8-10 | 90-day password expiry (waived if MFA enforced) | 8.3.9 | `password_changed_at` column on `users`; check at login | S |
| 8-4 | Inactive account sweep (90 days) | 8.2.6 | `last_login_at` column; background goroutine in `cmd/vaultd/` | M |
| 2-4 | Explicit cipher suite allowlist | 4.2.1 | `cmd/vaultd/main.go:buildServerTLS` | XS |
| 4-2 | TLS `MinVersion` on outbound connections | 4.2.1 | `internal/tlsutil/tls.go` | XS |

### P2 — Address within current development cycle

| Ref | Gap | Req | File / Location | Estimated Effort |
|-----|-----|-----|-----------------|-----------------|
| 6-2 | `govulncheck` + Dependabot in CI | 6.3.3 | CI config | XS |
| 10-7 | Audit DB retention pruning | 10.5.1 | `cmd/vault-audit/` or scheduled SQL | S |
| 8-12 | Machine token max TTL / mandatory expiry | 8.6.1, 8.6.3 | `internal/api/tokens.go:handleCreateToken` | S |
| 10-9 | Health/metrics endpoint + NATS disconnect alert | 10.7.1 | New `GET /healthz` handler; NATS reconnect hook | M |
| 7-5 | Admin access-report endpoint | 7.3.2 | New handler in `internal/api/` | S |
| 3-5 | Warn when `VAULT_MASTER_KEY` used in production | 3.7.2 | `cmd/vaultd/main.go:openKeyProvider` startup log | XS |

### P3 — Process and policy (no code changes required)

| Ref | Gap | Req | Owner |
|-----|-----|-----|-------|
| 12-1 | Information security policy | 12.1 | Security/Legal |
| 12-2 | Risk assessment per requirement | 12.3 | Security |
| 12-3 | Security awareness training | 12.6 | HR/Security |
| 12-4 | Incident response plan | 12.10 | Security/Engineering |
| 11-2 | ASV external scan engagement | 11.3.2 | Security |
| 11-3 | Annual penetration test | 11.4 | Security |
| 10-8 | NTP deployment requirement documented | 10.6.1 | DevOps |
| 3-5 | Key custodian procedures for KEK | 3.7.2 | Security/Operations |
| 6-5 | Threat model document | 6.2.1 | Engineering |

---

## Open Items Tracker

> Update this table as gaps are closed. Add the commit SHA or PR reference when resolved.

| Ref | Status | Resolved in | Notes |
|-----|--------|-------------|-------|
| 8-7 | ❌ Open | — | |
| 8-8 | ❌ Open | — | |
| 8-6 | ❌ Open | — | |
| 8-11 | ❌ Open | — | Interim: document OIDC+MFA as mandatory for production |
| 2-3 | ❌ Open | — | |
| 8-5 | ❌ Open | — | |
| 8-9 | ❌ Open | — | |
| 8-10 | ❌ Open | — | Waived if 8-11 resolved via OIDC+MFA |
| 8-4 | ❌ Open | — | |
| 2-4 | ❌ Open | — | |
| 4-2 | ❌ Open | — | |
| 6-2 | ❌ Open | — | |
| 10-7 | ❌ Open | — | |
| 8-12 | ❌ Open | — | |
| 10-9 | ❌ Open | — | |
| 7-5 | ❌ Open | — | |
| 3-5 | ❌ Open | — | |

---

## Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2026-04-26 | Szeto Bo | Initial draft — full gap analysis against PCI-DSS v4.0.1 |
