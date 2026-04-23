// Package postgres implements store.Store using PostgreSQL via pgx/v5.
// Connect via VAULT_DATABASE_URL (standard DSN or postgres:// URL).
//
// Swap from SQLite to Postgres by changing the store constructor in cmd/vaultd/main.go —
// nothing else changes because the Store interface is the only contract.
package postgres

import (
	"crypto/tls"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	pgxstdlib "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations
var migrationsFS embed.FS

// DB wraps sql.DB and implements store.Store for Postgres.
type DB struct {
	db *sql.DB
}

// Open connects to a Postgres database and runs migrations.
// dsn is a postgres:// URL or a key=value connection string.
func Open(dsn string) (*DB, error) {
	return OpenWithTLS(dsn, nil)
}

// OpenWithTLS connects using a custom TLS config, enabling client certificate
// authentication when tlsCfg is non-nil. Pass nil for a plain (DSN-only) connection.
func OpenWithTLS(dsn string, tlsCfg *tls.Config) (*DB, error) {
	var db *sql.DB
	if tlsCfg != nil {
		connCfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return nil, fmt.Errorf("parse postgres dsn: %w", err)
		}
		connCfg.TLSConfig = tlsCfg
		db = pgxstdlib.OpenDB(*connCfg)
	} else {
		var err error
		db, err = sql.Open("pgx", dsn)
		if err != nil {
			return nil, fmt.Errorf("open postgres: %w", err)
		}
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &DB{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *DB) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version := e.Name()

		var already int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = $1`, version).Scan(&already)
		if already > 0 {
			continue
		}

		data, err := migrationsFS.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(data)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("exec migration %s: %w", version, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
	}
	return nil
}

func (s *DB) Close() error { return s.db.Close() }

// ── helpers ───────────────────────────────────────────────────────────────────

func isUnique(err error) bool {
	if err == nil {
		return false
	}
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code == "23505"
	}
	return false
}
