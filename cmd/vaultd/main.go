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
//	VAULT_DATABASE_URL    Postgres DSN (postgres://...) — uses Postgres store
//	VAULT_DB_PATH         SQLite file path (default: vault.db) — uses SQLite store
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
//	VAULT_DB_SSL_CERT     Path to client certificate PEM for the vault→postgres connection.
//	VAULT_DB_SSL_KEY      Path to client key PEM. Must be paired with VAULT_DB_SSL_CERT.
//	VAULT_DB_SSL_ROOTCERT Path to CA certificate PEM for verifying the postgres server cert.
//
// Optional:
//
//	VAULT_ADDR            Listen address (default: :8443)
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/abagile/tokyo3-vault/internal/api"
	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/dynamic"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/abagile/tokyo3-vault/internal/store/postgres"
	"github.com/abagile/tokyo3-vault/internal/store/sqlite"
	"github.com/abagile/tokyo3-vault/internal/tlsutil"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

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

	revoker := dynamic.NewRevoker(st, kp, log)
	go revoker.Run(ctx)

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = ":8443"
	}

	tlsCfg, err := buildServerTLS(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls config: %v\n", err)
		os.Exit(1)
	}

	srv := api.New(st, kp, log)
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

// openStore selects SQLite or Postgres based on environment variables.
// For Postgres, VAULT_DB_SSL_CERT/KEY/ROOTCERT enable client certificate auth.
func openStore(log *slog.Logger) (store.Store, error) {
	if dsn := os.Getenv("VAULT_DATABASE_URL"); dsn != "" {
		tlsCfg, err := tlsutil.FromFiles(
			os.Getenv("VAULT_DB_SSL_CERT"),
			os.Getenv("VAULT_DB_SSL_KEY"),
			os.Getenv("VAULT_DB_SSL_ROOTCERT"),
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
