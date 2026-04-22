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
// Optional:
//
//	VAULT_ADDR            Listen address (default: :8080)
package main

import (
	"context"
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
		addr = ":8080"
	}

	srv := api.New(st, kp, log)
	log.Info("vaultd starting", "addr", addr)
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
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
func openStore(log *slog.Logger) (store.Store, error) {
	if dsn := os.Getenv("VAULT_DATABASE_URL"); dsn != "" {
		log.Info("using Postgres store")
		return postgres.Open(dsn)
	}
	dbPath := os.Getenv("VAULT_DB_PATH")
	if dbPath == "" {
		dbPath = "vault.db"
	}
	log.Info("using SQLite store", "path", dbPath)
	return sqlite.Open(dbPath)
}
