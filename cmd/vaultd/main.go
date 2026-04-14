// vaultd is the Vault secret manager server.
//
// Required environment variables:
//
//	VAULT_MASTER_KEY      64-char hex string (32 bytes) — generate with: vault keygen
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
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/abagile/tokyo3-vault/internal/api"
	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/abagile/tokyo3-vault/internal/store/postgres"
	"github.com/abagile/tokyo3-vault/internal/store/sqlite"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	masterKeyHex := os.Getenv("VAULT_MASTER_KEY")
	if masterKeyHex == "" {
		fmt.Fprintln(os.Stderr, "VAULT_MASTER_KEY is required (generate with: vault keygen)")
		os.Exit(1)
	}
	kek, err := crypto.ParseKEK(masterKeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid VAULT_MASTER_KEY: %v\n", err)
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

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	srv := api.New(st, kek, log)
	log.Info("vaultd starting", "addr", addr)
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
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
