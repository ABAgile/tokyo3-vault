// vaultd is the Vault secret manager server.
//
// Key provider — exactly one must be set:
//
//	VAULT_MASTER_KEY      64-char hex string (32 bytes) — local AES-256 KEK, dev only
//	                      Generate with: vault keygen
//	VAULT_KMS_KEY_ID      AWS KMS key ID, ARN, or alias — recommended for production
//	                      AWS credentials loaded from the standard chain (env, IAM role, etc.)
//
// Storage:
//
//	VAULT_DATABASE_URL  Store backend selector. A "sqlite:<path>" URL uses the embedded
//	                    SQLite backend (dev/test; "sqlite::memory:" is ephemeral); any other
//	                    value is a Postgres DSN (postgres://...; vault_app user, DML-only).
//	                    Unset defaults to "sqlite:vault.db".
//
// Workload CA (single root for every internal mTLS channel — DB, NATS, SCIM):
//
//	VAULT_WORKLOAD_CA  CA PEM that signs every internal workload cert vault
//	                   talks to (Postgres, NATS, inbound SCIM clients). Used
//	                   as the fallback for VAULT_DB_CA / VAULT_ADMIN_DB_CA /
//	                   VAULT_NATS_CA / VAULT_SCIM_MTLS_CA when any of those
//	                   is unset. Leave the per-channel CA vars empty in
//	                   deployments that issue all internal certs from one
//	                   workload CA; set the per-channel vars when stricter
//	                   separation is needed.
//
// Vault DB admin (Postgres only — schema migration):
//
//	VAULT_ADMIN_DATABASE_URL  Postgres DSN for schema migration (vault owner, DDL privileges).
//	                          Falls back to VAULT_DATABASE_URL if unset, but that requires
//	                          the runtime role to have DDL privileges — not for production.
//	VAULT_ADMIN_DB_CERT       Client cert PEM path for admin DB mTLS.
//	                          Falls back to VAULT_DB_CERT.
//	VAULT_ADMIN_DB_KEY        Client key PEM path. Falls back to VAULT_DB_KEY.
//	VAULT_ADMIN_DB_CA         CA cert PEM path. Falls back to VAULT_DB_CA → VAULT_WORKLOAD_CA.
//
// TLS (server always uses HTTPS):
//
//	VAULT_API_CERT        Path to server TLS certificate PEM (tbot: tls.crt).
//	                      Hot-reloaded on each handshake when the file changes.
//	VAULT_API_KEY         Path to server TLS private key PEM (tbot: tls.key).
//	                      Must be set when VAULT_API_CERT is set.
//	                      If neither VAULT_API_CERT nor VAULT_API_KEY is set,
//	                      an ephemeral self-signed certificate is generated (dev only).
//	VAULT_API_CLIENT_CA   Path to CA certificate PEM used to verify client certificates.
//	                      When set, enables mTLS: clients may authenticate via SPIFFE cert
//	                      instead of a Bearer token. Falls back to VAULT_WORKLOAD_CA
//	                      when unset — most API mTLS callers are workload services
//	                      using the same workload CA as DB/NATS, so the default
//	                      "set workload CA, leave per-channel CAs empty" deployment
//	                      pattern gets API mTLS for free.
//
// Inbound SCIM mTLS (optional — when set, the IdP can call /scim/v2/* with a
// client cert instead of minting a SCIM bearer token):
//
//	VAULT_SCIM_MTLS_CA       Path to CA bundle PEM that signs the IdP's client
//	                         cert. Merged into the same ClientCAs pool as
//	                         VAULT_API_CLIENT_CA — either may be omitted. Falls
//	                         back to VAULT_WORKLOAD_CA when unset.
//	VAULT_SCIM_MTLS_SAN_DNS  Comma-separated allow-list of DNS SANs that
//	                         identify the IdP. Required alongside
//	                         VAULT_SCIM_MTLS_CA. The peer cert's SAN must match
//	                         one of these (case-insensitive); CN is not
//	                         consulted. Without these, inbound SCIM stays
//	                         bearer-only.
//
// Vault's own Postgres TLS (optional):
//
//	VAULT_DB_CERT  Path to client certificate PEM for the vault→postgres connection.
//	VAULT_DB_KEY   Path to client key PEM. Must be paired with VAULT_DB_CERT.
//	VAULT_DB_CA    Path to CA certificate PEM for verifying the postgres server cert.
//	               Falls back to VAULT_WORKLOAD_CA when unset.
//
// Optional:
//
//	VAULT_ADDR                    Listen address (default: :8443)
//	VAULT_PROJECT_KEY_CACHE_TTL   How long a project's plaintext PEK stays cached in memory
//	                              (default: 5m). Longer = fewer KMS calls; shorter = faster
//	                              effect after PEK rotation. Accepts Go duration strings (5m, 1h).
//	VAULT_PEK_ROTATION_PERIOD     How long a project PEK may exist before automatic rotation
//	                              (default: 2160h / 90 days). The background rotator checks
//	                              every hour; set to 0 to disable automatic rotation.
//	VAULT_TRUSTED_PROXIES         Comma-separated list of additional CIDR ranges appended to
//	                              the built-in defaults (127.0.0.0/8, ::1/128, 10.0.0.0/8,
//	                              172.16.0.0/12, 192.168.0.0/16, fc00::/7) when deciding
//	                              whether to trust X-Forwarded-For for client IP extraction.
//	                              Set when your reverse proxy sits outside the built-in ranges.
//	VAULT_AUTH_RATE_PER_MIN       Maximum auth-endpoint requests per minute per client IP
//	                              (default: 5). Applies to /auth/login, /auth/signup, and
//	                              PUT /auth/password. Both the sustained rate and the burst
//	                              cap are set to this value.
//	VAULT_VERSION_MIN_KEEP        Minimum number of secret versions to retain per secret
//	                              (default: 10). A version is pruned only when BOTH this
//	                              threshold and VAULT_VERSION_MIN_DAYS are exceeded.
//	VAULT_VERSION_MIN_DAYS        Minimum age in days a secret version must reach before it
//	                              is eligible for pruning (default: 180). Works together with
//	                              VAULT_VERSION_MIN_KEEP — both conditions must hold.
//	VAULT_ALLOW_REGISTRATION      Set to "true" to enable self-service signup at /portal/register
//	                              and a "Create one" link on /portal/login. The first registrant
//	                              is promoted to admin if no admin exists yet. Ignored when
//	                              VAULT_OIDC_ENFORCE=true (local accounts are off entirely).
//	                              Default: false (admins manage users via /portal/admin/users).
//	VAULT_DEBUG_ADDR              Optional plaintext address for the diagnostics server
//	                              (net/http/pprof + a goroutine/OS-thread stats log), e.g.
//	                              "127.0.0.1:6060". Unset ⇒ disabled. Never expose publicly — it
//	                              serves unauthenticated profiling off the main TLS API.
//
// NATS / Audit sink (serve subcommand):
//
//	VAULT_NATS_URL    NATS server URL. When set, audit events are published to
//	                  JetStream (fail-closed: the request returns HTTP 500 if the
//	                  publish fails) and operational logs ship to app_log.vaultd.
//	                  Omit only in development.
//	VAULT_NATS_CERT   mTLS client certificate PEM path (publisher credential).
//	                  Falls back to VAULT_WORKLOAD_CERT when unset.
//	VAULT_NATS_KEY    mTLS client key PEM path. Falls back to VAULT_WORKLOAD_KEY.
//	VAULT_NATS_CA     CA certificate PEM path for NATS server verification.
//	                  Falls back to VAULT_WORKLOAD_CA when unset.
//
// Subcommands:
//
//	vaultd serve           Start the server (default when no subcommand is given)
//	vaultd migrate-keys    Migrate all projects to use per-project envelope keys (PEKs).
//	                       Safe to re-run (idempotent). Requires the same env vars as serve.
//	vaultd audit-query     Print the most recent audit events from the JetStream journal as
//	                       JSON (--limit N, default 100). Reads via VAULT_NATS_URL only.
//	vaultd version         Print version information and exit.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/cli"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/abagile/tokyo3-base/envutil"
	"github.com/abagile/tokyo3-base/guard"
	"github.com/abagile/tokyo3-base/run"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/abagile/tokyo3-base/tls/reloader"
	"github.com/abagile/tokyo3-base/version"
	"github.com/abagile/tokyo3-vault/internal/api"
	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/crypto/awskms"
	"github.com/abagile/tokyo3-vault/internal/dynamic"
	oidcpkg "github.com/abagile/tokyo3-vault/internal/oidc"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/abagile/tokyo3-vault/internal/store/postgres"
	"github.com/abagile/tokyo3-vault/internal/store/sqlite"
	"github.com/spf13/cobra"
)

const (
	appName   = "vaultd"
	envPrefix = "VAULT"

	// defaultDatabaseURL is the store backend used when VAULT_DATABASE_URL is
	// unset — the embedded SQLite backend at ./vault.db, for zero-config dev.
	defaultDatabaseURL = "sqlite:vault.db"
)

// Version is overridden at build time via -ldflags "-X main.Version=...".
// When that injection is absent, version.Resolve falls back to
// runtime/debug.BuildInfo: tagged installs report their tag, source-tree
// builds report "dev-<sha7>[-dirty] (<time>)".
var Version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   appName,
		Short: "Vault secret manager server",
	}
	root.AddCommand(serveCmd(), migrateKeysCmd(), auditQueryCmd(), versionCmd())
	// The container ENTRYPOINT runs a bare `vaultd` (no subcommand) and the
	// docs document `vaultd` as "start the server"; default to serve when no
	// subcommand is given so that invocation keeps working.
	if len(os.Args) < 2 {
		root.SetArgs([]string{"serve"})
	}
	return root
}

// ── serve ───────────────────────────────────────────────────────────────────

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the Vault HTTPS API server (default when no subcommand is given)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context())
		},
	}
}

func runServe(ctx context.Context) error {
	rt := cli.App{Name: appName, EnvPrefix: envPrefix}.Setup(ctx)
	defer rt.Shutdown()
	log := rt.Log

	// ── configuration ───────────────────────────────────────────────────────────
	// Parsed and validated up front so a bad value fails fast — before the store
	// is opened or any background worker starts, which would otherwise log
	// spurious errors against a half-initialized server as runServe unwinds.
	cacheTTL := 5 * time.Minute
	if d, err := envutil.Duration("VAULT_PROJECT_KEY_CACHE_TTL"); err != nil {
		return err
	} else if d > 0 {
		cacheTTL = d
	}

	trustedProxies, err := envutil.CIDRList("VAULT_TRUSTED_PROXIES")
	if err != nil {
		return err
	}

	authRatePerMin := 5
	if n, err := envutil.Int("VAULT_AUTH_RATE_PER_MIN"); err != nil {
		return err
	} else if n > 0 {
		authRatePerMin = n
	}

	pruneMinCount := 10
	if n, err := envutil.Int("VAULT_VERSION_MIN_KEEP"); err != nil {
		return err
	} else if n > 0 {
		pruneMinCount = n
	}

	pruneMinDays := 180
	if n, err := envutil.Int("VAULT_VERSION_MIN_DAYS"); err != nil {
		return err
	} else if n > 0 {
		pruneMinDays = n
	}
	pruneMinAge := time.Duration(pruneMinDays) * 24 * time.Hour

	// Unset keeps the 90-day default; an explicit value (including 0, which
	// disables rotation) overrides it — so the presence check, not just the
	// parsed duration, decides.
	rotationPeriod := 90 * 24 * time.Hour
	if d, err := envutil.Duration("VAULT_PEK_ROTATION_PERIOD"); err != nil {
		return err
	} else if os.Getenv("VAULT_PEK_ROTATION_PERIOD") != "" {
		rotationPeriod = d
	}

	addr := envutil.Or("VAULT_ADDR", ":8443")

	// ── resources ─────────────────────────────────────────────────────────────
	kp, err := openKeyProvider(rt.Ctx, log)
	if err != nil {
		return fmt.Errorf("key provider: %w", err)
	}

	st, err := openStore(rt)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer guard.Close(st)

	projectKP := bcrypto.NewKeyProviderCache(kp, cacheTTL)

	auditSink, err := cli.AuditSink[audit.Entry](rt, audit.Subject)
	if err != nil {
		return fmt.Errorf("audit sink: %w", err)
	}
	defer guard.Close(auditSink)
	auditSource, err := cli.AuditSource(rt, audit.StreamName, audit.Subject)
	if err != nil {
		return fmt.Errorf("audit source: %w", err)
	}
	defer guard.Close(auditSource)

	// ── background workers ──────────────────────────────────────────────────────
	guard.Go(log, "revoker", func() { dynamic.NewRevoker(st, kp, projectKP, log).Run(rt.Ctx) })
	guard.Go(log, "version-pruner", func() { newVersionPruner(st, log, pruneMinCount, pruneMinAge).Run(rt.Ctx) })
	guard.Go(log, "token-pruner", func() { newTokenPruner(st, log).Run(rt.Ctx) })
	if rotationPeriod > 0 {
		guard.Go(log, "pek-rotator", func() {
			newPEKRotator(st, kp, projectKP, auditSink, rotationPeriod, log).Run(rt.Ctx)
		})
	}

	tlsCfg, err := buildServerTLS(log)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}

	oidcProvider, oidcEnforce, err := buildOIDCProvider(rt.Ctx, log)
	if err != nil {
		return fmt.Errorf("oidc config: %w", err)
	}

	cookieKey, err := portalCookieKey(log)
	if err != nil {
		return fmt.Errorf("portal cookie key: %w", err)
	}

	scimAllowedSANs := splitCSV(os.Getenv("VAULT_SCIM_MTLS_SAN_DNS"))
	if len(scimAllowedSANs) > 0 {
		// Resolve through the same fallback chain buildServerTLS uses for the
		// ClientCAs pool. Without this check the warning fires even on
		// correctly-configured deployments that set VAULT_WORKLOAD_CA and
		// leave VAULT_SCIM_MTLS_CA unset (the intended simple setup).
		scimCAFile := envutil.First("VAULT_SCIM_MTLS_CA", "VAULT_WORKLOAD_CA")
		if scimCAFile == "" {
			log.Warn("VAULT_SCIM_MTLS_SAN_DNS is set but neither VAULT_SCIM_MTLS_CA nor VAULT_WORKLOAD_CA is — inbound SCIM mTLS will not work; the TLS handshake has no CA to verify the IdP cert against")
		} else {
			log.Info("inbound SCIM mTLS enabled", "allowed_sans", scimAllowedSANs, "ca", scimCAFile)
		}
	}

	srv := api.New(st, kp, projectKP, log, api.Config{
		OIDC:              oidcProvider,
		OIDCEnforce:       oidcEnforce,
		Sink:              auditSink,
		Source:            auditSource,
		TrustedProxies:    trustedProxies,
		AuthRatePerMin:    authRatePerMin,
		PruneMinCount:     pruneMinCount,
		PruneMinAge:       pruneMinAge,
		CookieKey:         cookieKey,
		AllowRegistration: strings.EqualFold(os.Getenv("VAULT_ALLOW_REGISTRATION"), "true"),
		SCIMAllowedSANDNS: scimAllowedSANs,
	})
	httpSrv := &http.Server{
		Addr:      addr,
		Handler:   srv.Routes(),
		TLSConfig: tlsCfg,
		// BaseContext makes every request inherit from the SIGTERM-aware
		// ctx so long-lived handlers (e.g. /portal/admin/audit/sse, which
		// blocks in select{} on r.Context().Done() and the JetStream
		// iterator) abort promptly on shutdown. Without this, Shutdown
		// would wait its full 10s deadline for each open SSE tab; with
		// it, ctx cancels propagate down the SSE → Source.Subscribe →
		// jetstream consumer chain in milliseconds.
		BaseContext: func(net.Listener) context.Context { return rt.Ctx },
	}

	log.Info("vaultd starting", "addr", addr, "tls", true)
	if err := run.Group(rt.Ctx, run.HTTPServer(httpSrv, 10*time.Second, true)); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	log.Info("vaultd stopped")
	return nil
}

// ── migrate-keys ──────────────────────────────────────────────────────────────

func migrateKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate-keys",
		Short: "Migrate all projects to per-project envelope keys (PEKs); idempotent",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrateKeysCmd(cmd.Context())
		},
	}
}

func runMigrateKeysCmd(ctx context.Context) error {
	rt := cli.App{Name: appName, EnvPrefix: envPrefix}.Setup(ctx)
	defer rt.Shutdown()
	log := rt.Log

	kp, err := openKeyProvider(rt.Ctx, log)
	if err != nil {
		return fmt.Errorf("key provider: %w", err)
	}
	st, err := openStore(rt)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer guard.Close(st)
	return runMigrateKeys(rt.Ctx, st, kp, log)
}

// ── audit-query ───────────────────────────────────────────────────────────────

func auditQueryCmd() *cobra.Command {
	limit := 100
	cmd := &cobra.Command{
		Use:   "audit-query",
		Short: "Print the most recent audit events from the NATS journal as JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			n := cli.App{Name: appName, EnvPrefix: envPrefix}.NATS()
			return runAuditQuery(cmd.Context(), n, limit)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of events to print (1-1000)")
	return cmd
}

// ── version ─────────────────────────────────────────────────────────────────

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("%s %s\n", appName, version.Resolve(Version))
		},
	}
}

// runMigrateKeys iterates every project where encrypted_pek IS NULL, generates a
// PEK, wraps it with the server KEK, and re-wraps all per-secret and per-backend
// DEKs for that project so they are wrapped by the PEK instead of the server KEK.
// Safe to re-run (idempotent): projects with an existing PEK are skipped.
func runMigrateKeys(ctx context.Context, st store.Store, kp bcrypto.KeyProvider, log *slog.Logger) error {
	projects, err := st.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("list projects: %w", err)
	}
	for _, p := range projects {
		if p.EncryptedPEK != nil {
			log.Info("migrate-keys: already migrated, skipping", "slug", p.Slug)
			continue
		}

		pek := make([]byte, 32)
		if _, err := rand.Read(pek); err != nil {
			return fmt.Errorf("generate PEK for %s: %w", p.Slug, err)
		}
		encPEK, err := kp.Wrap(ctx, pek)
		if err != nil {
			return fmt.Errorf("wrap PEK for %s: %w", p.Slug, err)
		}

		// RotateProjectPEK stores the new PEK and re-wraps all DEKs atomically.
		// Old DEKs here are wrapped by the server KEK directly (pre-migration).
		projectKP := bcrypto.NewLocalKeyProvider(pek)
		err = st.RotateProjectPEK(ctx, p.ID, encPEK, time.Now().UTC(), func(old []byte) ([]byte, error) {
			dek, err := kp.Unwrap(ctx, old)
			if err != nil {
				return nil, err
			}
			return projectKP.Wrap(ctx, dek)
		})
		if err != nil {
			return fmt.Errorf("migrate PEK for %s: %w", p.Slug, err)
		}
		log.Info("migrate-keys: migrated", "slug", p.Slug, "id", p.ID)
	}
	return nil
}

// buildServerTLS constructs the server tls.Config.
// Cert source priority:
//  1. VAULT_API_CERT + VAULT_API_KEY files (tbot hot-reload via GetCertificate)
//  2. Auto-generated self-signed cert (dev fallback, logs a warning)
//
// Client-cert verification is enabled if VAULT_API_CLIENT_CA (general client
// auth) and/or VAULT_SCIM_MTLS_CA (IdP-only, for inbound SCIM) is set. Both
// CAs are merged into the same ClientCAs pool — the per-route middleware then
// decides which trust path is acceptable for that route.
func buildServerTLS(log *slog.Logger) (*tls.Config, error) {
	certFile := os.Getenv("VAULT_API_CERT")
	keyFile := os.Getenv("VAULT_API_KEY")
	clientCAFile := envutil.First("VAULT_API_CLIENT_CA", "VAULT_WORKLOAD_CA")
	scimCAFile := envutil.First("VAULT_SCIM_MTLS_CA", "VAULT_WORKLOAD_CA")

	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("VAULT_API_CERT and VAULT_API_KEY must both be set or both unset")
	}

	cfg := &tls.Config{}

	if certFile != "" {
		log.Info("TLS: using certificate files (hot-reload enabled)", "cert", certFile)
		loader := reloader.NewCertLoader(certFile, keyFile)
		cfg.GetCertificate = loader.GetCertificate
	} else {
		log.Warn("TLS: no certificate configured, using self-signed (not for production)")
		cert, err := btls.SelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	pool := x509.NewCertPool()
	hasCA := false
	if clientCAFile != "" {
		data, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read VAULT_API_CLIENT_CA: %w", err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse VAULT_API_CLIENT_CA: no valid certificates")
		}
		hasCA = true
		log.Info("TLS: client CA loaded for general mTLS", "ca", clientCAFile)
	}
	if scimCAFile != "" {
		data, err := os.ReadFile(scimCAFile)
		if err != nil {
			return nil, fmt.Errorf("read VAULT_SCIM_MTLS_CA: %w", err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse VAULT_SCIM_MTLS_CA: no valid certificates")
		}
		hasCA = true
		log.Info("TLS: SCIM mTLS CA loaded (IdP)", "ca", scimCAFile)
	}
	if hasCA {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return cfg, nil
}

// portalCookieKey returns the 32-byte AES-GCM key used to seal the portal
// session cookie. Local-key deployments reuse VAULT_MASTER_KEY directly so
// portal sessions survive vaultd restart. KMS-mode deployments mint a random
// per-process key — restarting vaultd invalidates outstanding portal sessions,
// which is acceptable for an admin portal.
func portalCookieKey(log *slog.Logger) ([]byte, error) {
	if hex := os.Getenv("VAULT_MASTER_KEY"); hex != "" {
		return bcrypto.ParseKEK(hex)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate ephemeral cookie key: %w", err)
	}
	log.Warn("portal cookie key is ephemeral; restarting vaultd will invalidate all portal sessions",
		"reason", "VAULT_MASTER_KEY not set (KMS-mode deployment)")
	return key, nil
}

// openKeyProvider selects LocalKeyProvider (VAULT_MASTER_KEY) or KMSKeyProvider
// (VAULT_KMS_KEY_ID). Exactly one must be set; setting both is an error.
func openKeyProvider(ctx context.Context, log *slog.Logger) (bcrypto.KeyProvider, error) {
	masterKeyHex := os.Getenv("VAULT_MASTER_KEY")
	kmsKeyID := os.Getenv("VAULT_KMS_KEY_ID")

	if masterKeyHex != "" && kmsKeyID != "" {
		return nil, fmt.Errorf("set either VAULT_MASTER_KEY or VAULT_KMS_KEY_ID, not both")
	}
	if kmsKeyID != "" {
		log.Info("using AWS KMS key provider", "key_id", kmsKeyID)
		return awskms.New(ctx, kmsKeyID)
	}
	if masterKeyHex == "" {
		return nil, fmt.Errorf("VAULT_MASTER_KEY or VAULT_KMS_KEY_ID is required")
	}
	kek, err := bcrypto.ParseKEK(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid VAULT_MASTER_KEY: %w", err)
	}
	log.Info("using local master key provider")
	return bcrypto.NewLocalKeyProvider(kek), nil
}

// buildOIDCProvider configures the OIDC provider from environment variables.
// Returns nil provider (with no error) when OIDC is not configured.
//
// Required env vars to enable OIDC:
//
//	VAULT_OIDC_ISSUER       IdP issuer URL (discovery endpoint base)
//	VAULT_OIDC_CLIENT_ID    OAuth2 client ID
//	VAULT_OIDC_CLIENT_SECRET OAuth2 client secret
//	VAULT_OIDC_REDIRECT_URI Callback URL registered with the IdP
//
// Optional:
//
//	VAULT_OIDC_ENFORCE      Set to "true" to disable local login/signup entirely
func buildOIDCProvider(ctx context.Context, log *slog.Logger) (*oidcpkg.Provider, bool, error) {
	issuer := os.Getenv("VAULT_OIDC_ISSUER")
	clientID := os.Getenv("VAULT_OIDC_CLIENT_ID")
	clientSecret := os.Getenv("VAULT_OIDC_CLIENT_SECRET")
	redirectURI := os.Getenv("VAULT_OIDC_REDIRECT_URI")

	if clientID == "" {
		return nil, false, nil // OIDC not configured
	}
	if issuer == "" || clientSecret == "" || redirectURI == "" {
		return nil, false, fmt.Errorf("VAULT_OIDC_ISSUER, VAULT_OIDC_CLIENT_ID, VAULT_OIDC_CLIENT_SECRET, and VAULT_OIDC_REDIRECT_URI must all be set")
	}
	enforce := os.Getenv("VAULT_OIDC_ENFORCE") == "true"
	log.Info("OIDC configured", "issuer", issuer, "enforce", enforce)

	provider, err := oidcpkg.New(ctx, oidcpkg.Config{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
	})
	if err != nil {
		return nil, false, fmt.Errorf("init OIDC provider: %w", err)
	}
	return provider, enforce, nil
}

// migrateVaultDB runs Postgres schema migrations with the admin (DDL) DSN before
// the runtime connection is opened. cli.App.AdminDB() resolves the admin material
// from VAULT_ADMIN_DATABASE_URL → VAULT_DATABASE_URL and the
// VAULT_ADMIN_DB_CERT/KEY/CA → VAULT_DB_CERT/KEY/CA → VAULT_WORKLOAD_CA fallback
// chain; we warn when no dedicated admin DSN is configured (the runtime DSN then
// needs DDL rights — not for production).
func migrateVaultDB(rt cli.Runtime) error {
	if os.Getenv("VAULT_ADMIN_DATABASE_URL") == "" {
		rt.Log.Warn("VAULT_ADMIN_DATABASE_URL not set — using VAULT_DATABASE_URL for schema migration (not for production)")
	}
	tlsCfg, err := btls.FromFiles(rt.AdminDB.CertFile, rt.AdminDB.KeyFile, rt.AdminDB.CAFile)
	if err != nil {
		return fmt.Errorf("vault admin db TLS: %w", err)
	}
	if tlsCfg != nil {
		rt.Log.Info("vault db: schema migration with mTLS client cert")
	} else {
		rt.Log.Info("vault db: running schema migrations")
	}
	return postgres.Migrate(rt.AdminDB.URL, tlsCfg)
}

// openStore selects the store backend from VAULT_DATABASE_URL: a "sqlite:<path>"
// URL uses the embedded SQLite backend (dev/test; "sqlite::memory:" is ephemeral),
// anything else is a Postgres DSN. Unset defaults to defaultDatabaseURL. For
// Postgres, schema migrations run with the admin DSN first (see migrateVaultDB),
// then the runtime connection opens with VAULT_DB_CERT/KEY/CA (CA falling back to
// VAULT_WORKLOAD_CA) for client-certificate auth.
func openStore(rt cli.Runtime) (store.Store, error) {
	dsn := rt.DB.URL
	if dsn == "" {
		dsn = defaultDatabaseURL
	}
	if path, ok := strings.CutPrefix(dsn, "sqlite:"); ok {
		rt.Log.Info("using SQLite store", "path", path)
		return sqlite.Open(path)
	}
	if err := migrateVaultDB(rt); err != nil {
		return nil, fmt.Errorf("vault db migration: %w", err)
	}
	tlsCfg, err := btls.FromFiles(rt.DB.CertFile, rt.DB.KeyFile, rt.DB.CAFile)
	if err != nil {
		return nil, fmt.Errorf("postgres TLS config: %w", err)
	}
	if tlsCfg != nil {
		rt.Log.Info("using Postgres store with client certificate auth")
	} else {
		rt.Log.Info("using Postgres store")
	}
	return postgres.OpenWithTLS(dsn, tlsCfg)
}

// splitCSV trims and returns non-empty entries from a comma-separated string.
// Used for VAULT_SCIM_MTLS_SAN_DNS and any other plain string-list env var.
func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for s := range strings.SplitSeq(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
