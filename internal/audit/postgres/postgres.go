package postgres

import (
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"fmt"
	"strings"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/jackc/pgx/v5"
	pgxstdlib "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations
var migrationsFS embed.FS

// DB wraps a *sql.DB connected to the audit Postgres database.
type DB struct {
	db *sql.DB
}

// Open opens an audit Postgres database. tlsCfg may be nil for plain DSN auth;
// pass a *tls.Config carrying a client certificate for mTLS.
func Open(dsn string, tlsCfg *tls.Config) (*DB, error) {
	var sqldb *sql.DB
	if tlsCfg != nil {
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return nil, fmt.Errorf("parse audit postgres dsn: %w", err)
		}
		cfg.TLSConfig = tlsCfg
		sqldb = pgxstdlib.OpenDB(*cfg)
	} else {
		var err error
		sqldb, err = sql.Open("pgx", dsn)
		if err != nil {
			return nil, fmt.Errorf("open audit postgres: %w", err)
		}
	}
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("ping audit postgres: %w", err)
	}
	return &DB{db: sqldb}, nil
}

// Migrate runs all pending audit schema migrations against dsn using the
// owner/admin role. Call before Open. tlsCfg may be nil.
func Migrate(dsn string, tlsCfg *tls.Config) error {
	var db *sql.DB
	if tlsCfg != nil {
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return fmt.Errorf("parse audit postgres dsn: %w", err)
		}
		cfg.TLSConfig = tlsCfg
		db = pgxstdlib.OpenDB(*cfg)
	} else {
		var err error
		db, err = sql.Open("pgx", dsn)
		if err != nil {
			return fmt.Errorf("open audit postgres: %w", err)
		}
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping audit postgres: %w", err)
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

func (d *DB) UpsertAuditLog(ctx context.Context, e audit.Entry) error {
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, action, actor_id, project_id, env_id, resource, metadata, ip, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
		e.ID, e.Action,
		nilIfEmpty(e.ActorID), nilIfEmpty(e.ProjectID), nilIfEmpty(e.EnvID),
		nilIfEmpty(e.Resource), nilIfEmpty(e.Metadata), nilIfEmpty(e.IP),
		e.OccurredAt,
	)
	return err
}

func (d *DB) ListAuditLogs(ctx context.Context, f audit.Filter) ([]*model.AuditLog, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}

	where := []string{"1=1"}
	args := []any{}
	n := 1

	if f.ProjectID != "" {
		where = append(where, fmt.Sprintf("project_id = $%d", n))
		args = append(args, f.ProjectID)
		n++
	}
	if f.EnvID != "" {
		where = append(where, fmt.Sprintf("env_id = $%d", n))
		args = append(args, f.EnvID)
		n++
	}
	if f.Action != "" {
		where = append(where, fmt.Sprintf("action = $%d", n))
		args = append(args, f.Action)
		n++
	}
	args = append(args, limit)

	q := fmt.Sprintf(
		`SELECT id, action, actor_id, project_id, env_id, resource, metadata, ip, created_at
		 FROM audit_logs WHERE %s ORDER BY created_at DESC LIMIT $%d`,
		strings.Join(where, " AND "), n,
	)
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.AuditLog
	for rows.Next() {
		e := &model.AuditLog{}
		if err := rows.Scan(&e.ID, &e.Action, &e.ActorID, &e.ProjectID, &e.EnvID,
			&e.Resource, &e.Metadata, &e.IP, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) Close() error { return d.db.Close() }

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
