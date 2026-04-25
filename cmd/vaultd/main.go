// vaultd is the Vault secret manager server.
//
// Key provider — exactly one must be set:
//
//	VAULT_MASTER_KEY      64-char hex string (32 bytes) — local AES-256 KEK, dev only
//	                      Generate with: vault keygen
//	VAULT_KMS_KEY_ID      AWS KMS key ID, ARN, or alias — recommended for production
//	                      AWS credentials loaded from the standard chain (env, IAM role, etc.)
//
// Storage — exactly one must be set:
//
//	VAULT_DATABASE_URL      Postgres DSN (postgres://...) — uses Postgres store (vault_app user, DML-only)
//	VAULT_DB_PATH           SQLite file path (default: vault.db) — uses SQLite store
//
// Vault DB admin (Postgres only — schema migration):
//
//	VAULT_ADMIN_DATABASE_URL  Postgres DSN for schema migration (vault owner, DDL privileges).
//	                          Falls back to VAULT_DATABASE_URL if unset, but that requires
//	                          the runtime role to have DDL privileges — not for production.
//	VAULT_ADMIN_DB_CERT   Client cert PEM path for admin DB mTLS
//	VAULT_ADMIN_DB_KEY    Client key PEM path for admin DB mTLS
//	VAULT_ADMIN_DB_CA     CA cert PEM path for admin DB server verification
//
// TLS (server always uses HTTPS):
//
//	VAULT_TLS_CERT        Path to server TLS certificate PEM (tbot: tls.crt).
//	                      Hot-reloaded on each handshake when the file changes.
//	VAULT_TLS_KEY         Path to server TLS private key PEM (tbot: tls.key).
//	                      Must be set when VAULT_TLS_CERT is set.
//	                      If neither VAULT_TLS_CERT nor VAULT_TLS_KEY is set,
//	                      an ephemeral self-signed certificate is generated (dev only).
//	VAULT_TLS_CLIENT_CA   Path to CA certificate PEM used to verify client certificates.
//	                      When set, enables mTLS: clients may authenticate via SPIFFE cert
//	                      instead of a Bearer token.
//
// Vault's own Postgres TLS (optional):
//
//	VAULT_DB_CERT     Path to client certificate PEM for the vault→postgres connection.
//	VAULT_DB_KEY      Path to client key PEM. Must be paired with VAULT_DB_CERT.
//	VAULT_DB_CA Path to CA certificate PEM for verifying the postgres server cert.
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
//
// NATS / Audit sink (serve subcommand):
//
//	VAULT_NATS_URL    NATS server URL. When set, audit events are published to
//	                  JetStream (fail-closed: the request returns HTTP 500 if the
//	                  publish fails). Omit only in development.
//	VAULT_NATS_CERT   mTLS client certificate PEM path (publisher credential).
//	VAULT_NATS_KEY    mTLS client key PEM path.
//	VAULT_NATS_CA     CA certificate PEM path for NATS server verification.
//
// Subcommands:
//
//	vaultd serve           Start the server (default when no subcommand is given)
//	vaultd migrate-keys    Migrate all projects to use per-project envelope keys (PEKs).
//	                       Safe to re-run (idempotent). Requires the same env vars as serve.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abagile/tokyo3-vault/internal/api"
	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/dynamic"
	oidcpkg "github.com/abagile/tokyo3-vault/internal/oidc"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/abagile/tokyo3-vault/internal/store/postgres"
	"github.com/abagile/tokyo3-vault/internal/store/sqlite"
	"github.com/abagile/tokyo3-vault/internal/tlsutil"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	subcommand := "serve"
	if len(os.Args) > 1 {
		subcommand = os.Args[1]
	}

	kp, err := openKeyProvider(ctx, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key provider: %v\n", err)
		os.Exit(1)
	}

	st, err := openStore(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}
	if closer, ok := st.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	cacheT := 5 * time.Minute
	if v := os.Getenv("VAULT_PROJECT_KEY_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cacheT = d
		} else {
			log.Warn("invalid VAULT_PROJECT_KEY_CACHE_TTL, using default", "value", v, "default", cacheT)
		}
	}
	projectKP := crypto.NewProjectKeyCache(kp, cacheT)

	if subcommand == "migrate-keys" {
		if err := runMigrateKeys(ctx, st, kp, log); err != nil {
			fmt.Fprintf(os.Stderr, "migrate-keys: %v\n", err)
			os.Exit(1)
		}
		return
	}

	auditSink, err := openAuditSink(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit sink: %v\n", err)
		os.Exit(1)
	}
	defer auditSink.Close()

	revoker := dynamic.NewRevoker(st, kp, projectKP, log)
	go revoker.Run(ctx)

	rotationPeriod := 90 * 24 * time.Hour
	if v := os.Getenv("VAULT_PEK_ROTATION_PERIOD"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			rotationPeriod = d
		} else {
			log.Warn("invalid VAULT_PEK_ROTATION_PERIOD, using default", "value", v, "default", rotationPeriod)
		}
	}
	if rotationPeriod > 0 {
		rotator := newPEKRotator(st, kp, projectKP, auditSink, rotationPeriod, log)
		go rotator.Run(ctx)
	}

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = ":8443"
	}

	tlsCfg, err := buildServerTLS(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls config: %v\n", err)
		os.Exit(1)
	}

	oidcProvider, oidcEnforce, err := buildOIDCProvider(ctx, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oidc config: %v\n", err)
		os.Exit(1)
	}

	srv := api.New(st, kp, projectKP, log, oidcProvider, oidcEnforce, auditSink)
	httpSrv := &http.Server{
		Addr:      addr,
		Handler:   srv.Routes(),
		TLSConfig: tlsCfg,
	}

	log.Info("vaultd starting", "addr", addr, "tls", true)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// runMigrateKeys iterates every project where encrypted_pek IS NULL, generates a
// PEK, wraps it with the server KEK, and re-wraps all per-secret and per-backend
// DEKs for that project so they are wrapped by the PEK instead of the server KEK.
// Safe to re-run (idempotent): projects with an existing PEK are skipped.
func runMigrateKeys(ctx context.Context, st store.Store, kp crypto.KeyProvider, log *slog.Logger) error {
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
		encPEK, err := kp.WrapDEK(ctx, pek)
		if err != nil {
			return fmt.Errorf("wrap PEK for %s: %w", p.Slug, err)
		}

		// RotateProjectPEK stores the new PEK and re-wraps all DEKs atomically.
		// Old DEKs here are wrapped by the server KEK directly (pre-migration).
		projectKP := crypto.NewProjectKeyProvider(pek)
		err = st.RotateProjectPEK(ctx, p.ID, encPEK, time.Now().UTC(), func(old []byte) ([]byte, error) {
			dek, err := kp.UnwrapDEK(ctx, old)
			if err != nil {
				return nil, err
			}
			return projectKP.WrapDEK(ctx, dek)
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
//  1. VAULT_TLS_CERT + VAULT_TLS_KEY files (tbot hot-reload via GetCertificate)
//  2. Auto-generated self-signed cert (dev fallback, logs a warning)
//
// If VAULT_TLS_CLIENT_CA is set, mTLS client verification is enabled.
func buildServerTLS(log *slog.Logger) (*tls.Config, error) {
	certFile := os.Getenv("VAULT_TLS_CERT")
	keyFile := os.Getenv("VAULT_TLS_KEY")
	clientCAFile := os.Getenv("VAULT_TLS_CLIENT_CA")

	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("VAULT_TLS_CERT and VAULT_TLS_KEY must both be set or both unset")
	}

	cfg := &tls.Config{}

	if certFile != "" {
		log.Info("TLS: using certificate files (hot-reload enabled)", "cert", certFile)
		loader := tlsutil.NewCertLoader(certFile, keyFile)
		cfg.GetCertificate = loader.GetCertificate
	} else {
		log.Warn("TLS: no certificate configured, using self-signed (not for production)")
		cert, err := tlsutil.SelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if clientCAFile != "" {
		data, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read VAULT_TLS_CLIENT_CA: %w", err)
		}
		pool, err := tlsutil.CertPoolFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parse VAULT_TLS_CLIENT_CA: %w", err)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		log.Info("TLS: mTLS client CA loaded", "ca", clientCAFile)
	}

	return cfg, nil
}

// openKeyProvider selects LocalKeyProvider (VAULT_MASTER_KEY) or KMSKeyProvider
// (VAULT_KMS_KEY_ID). Exactly one must be set; setting both is an error.
func openKeyProvider(ctx context.Context, log *slog.Logger) (crypto.KeyProvider, error) {
	masterKeyHex := os.Getenv("VAULT_MASTER_KEY")
	kmsKeyID := os.Getenv("VAULT_KMS_KEY_ID")

	if masterKeyHex != "" && kmsKeyID != "" {
		return nil, fmt.Errorf("set either VAULT_MASTER_KEY or VAULT_KMS_KEY_ID, not both")
	}
	if kmsKeyID != "" {
		log.Info("using AWS KMS key provider", "key_id", kmsKeyID)
		return crypto.NewKMSKeyProvider(ctx, kmsKeyID)
	}
	if masterKeyHex == "" {
		return nil, fmt.Errorf("VAULT_MASTER_KEY or VAULT_KMS_KEY_ID is required")
	}
	kek, err := crypto.ParseKEK(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid VAULT_MASTER_KEY: %w", err)
	}
	log.Info("using local master key provider")
	return crypto.NewLocalKeyProvider(kek), nil
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

	if issuer == "" && clientID == "" {
		return nil, false, nil // OIDC not configured
	}
	if issuer == "" || clientID == "" || clientSecret == "" || redirectURI == "" {
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

// openAuditSink opens the NATS JetStream publisher used by the serve path.
// When VAULT_NATS_URL is unset a NoopSink is returned (dev only).
// mTLS is enabled when VAULT_NATS_CERT/KEY/CA are all set.
func openAuditSink(log *slog.Logger) (audit.Sink, error) {
	url := os.Getenv("VAULT_NATS_URL")
	if url == "" {
		log.Warn("VAULT_NATS_URL not set — audit sink is no-op; not for production")
		return audit.NoopSink{}, nil
	}
	tlsCfg, err := tlsutil.FromFiles(
		os.Getenv("VAULT_NATS_CERT"),
		os.Getenv("VAULT_NATS_KEY"),
		os.Getenv("VAULT_NATS_CA"),
	)
	if err != nil {
		return nil, fmt.Errorf("nats audit TLS: %w", err)
	}
	if tlsCfg != nil {
		log.Info("audit sink: NATS JetStream with mTLS", "url", url)
	} else {
		log.Warn("audit sink: VAULT_NATS_CERT not set — connecting without mTLS (not for production)")
	}
	return audit.NewJetStreamSink(url, tlsCfg)
}

// openStore selects SQLite or Postgres based on environment variables.
// For Postgres, runs schema migrations with the admin DSN first, then opens
// the runtime connection. VAULT_DB_CERT/KEY/CA enable client certificate auth.
// migrateVaultDB runs schema migrations with the admin DSN before the runtime
// connection is opened. Falls back to VAULT_DATABASE_URL with a warning when
// VAULT_ADMIN_DATABASE_URL is not set.
func migrateVaultDB(log *slog.Logger) error {
	adminDSN := os.Getenv("VAULT_ADMIN_DATABASE_URL")
	if adminDSN == "" {
		log.Warn("VAULT_ADMIN_DATABASE_URL not set — using VAULT_DATABASE_URL for schema migration (not for production)")
		adminDSN = os.Getenv("VAULT_DATABASE_URL")
	}
	tlsCfg, err := tlsutil.FromFiles(
		os.Getenv("VAULT_ADMIN_DB_CERT"),
		os.Getenv("VAULT_ADMIN_DB_KEY"),
		os.Getenv("VAULT_ADMIN_DB_CA"),
	)
	if err != nil {
		return fmt.Errorf("vault admin db TLS: %w", err)
	}
	if tlsCfg != nil {
		log.Info("vault db: schema migration with mTLS client cert")
	} else {
		log.Info("vault db: running schema migrations")
	}
	return postgres.Migrate(adminDSN, tlsCfg)
}

func openStore(log *slog.Logger) (store.Store, error) {
	if dsn := os.Getenv("VAULT_DATABASE_URL"); dsn != "" {
		if err := migrateVaultDB(log); err != nil {
			return nil, fmt.Errorf("vault db migration: %w", err)
		}
		tlsCfg, err := tlsutil.FromFiles(
			os.Getenv("VAULT_DB_CERT"),
			os.Getenv("VAULT_DB_KEY"),
			os.Getenv("VAULT_DB_CA"),
		)
		if err != nil {
			return nil, fmt.Errorf("postgres TLS config: %w", err)
		}
		if tlsCfg != nil {
			log.Info("using Postgres store with client certificate auth")
		} else {
			log.Info("using Postgres store")
		}
		return postgres.OpenWithTLS(dsn, tlsCfg)
	}
	dbPath := os.Getenv("VAULT_DB_PATH")
	if dbPath == "" {
		dbPath = "vault.db"
	}
	log.Info("using SQLite store", "path", dbPath)
	return sqlite.Open(dbPath)
}
