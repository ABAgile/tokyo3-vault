package audit

import (
	"crypto/tls"
	"database/sql"
	"embed"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	pgxstdlib "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations
var migrationsFS embed.FS

// Migrate connects to Postgres with dsn (the admin/owner role) and runs all
// pending audit schema migrations. Call this at audit-consumer startup before
// opening the restricted write connection via OpenPostgres. tlsCfg may be nil.
func Migrate(dsn string, tlsCfg *tls.Config) error {
	var db *sql.DB
	if tlsCfg != nil {
		connCfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return fmt.Errorf("parse audit admin postgres dsn: %w", err)
		}
		connCfg.TLSConfig = tlsCfg
		db = pgxstdlib.OpenDB(*connCfg)
	} else {
		var err error
		db, err = sql.Open("pgx", dsn)
		if err != nil {
			return fmt.Errorf("open audit admin postgres: %w", err)
		}
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping audit admin postgres: %w", err)
	}
	return runMigrations(db)
}

func runMigrations(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`)
	if err != nil {
		return fmt.Errorf("create audit schema_migrations: %w", err)
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
		_ = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = $1`, version).Scan(&already)
		if already > 0 {
			continue
		}

		data, err := migrationsFS.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("read audit migration %s: %w", version, err)
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(data)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("exec audit migration %s: %w", version, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record audit migration %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit audit migration %s: %w", version, err)
		}
	}
	return nil
}
