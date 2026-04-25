package audit

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"strings"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/jackc/pgx/v5"
	pgxstdlib "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Filter controls which audit log entries ListAuditLogs returns.
type Filter struct {
	ProjectID string // empty = all projects
	EnvID     string // empty = all environments
	Action    string // empty = all actions
	Limit     int    // 0 = default (50)
}

// QueryStore is the read-only interface for the audit database. It is satisfied
// by *DB (with vault_audit_reader credentials) and by NoopQueryStore in tests.
type QueryStore interface {
	ListAuditLogs(ctx context.Context, f Filter) ([]*model.AuditLog, error)
	Close() error
}

// DB wraps a *sql.DB connected to the dedicated audit database. It serves two
// roles depending on which credential opened it:
//   - vault_audit_reader (SELECT-only) → used by the API server for queries
//   - vault_audit_writer (INSERT-only) → used by the audit-consumer for upserts
//
// Use OpenPostgres or OpenSQLite to construct.
type DB struct {
	db   *sql.DB
	lite bool // true → SQLite (? placeholders); false → Postgres ($N placeholders)
}

// OpenPostgres opens an audit Postgres database. tlsCfg may be nil for a plain
// DSN connection; pass a *tls.Config carrying a client certificate for mTLS.
// The DSN should encode the appropriate role credentials (vault_audit_reader
// for the server, vault_audit_writer for the consumer). Schema is managed by
// postgres/audit-db-init.sh which runs at first postgres startup.
func OpenPostgres(dsn string, tlsCfg *tls.Config) (*DB, error) {
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

// OpenSQLite opens (or creates) an audit SQLite database at path. The schema
// is created if absent. SQLite enforces single-writer by capping open conns.
func OpenSQLite(path string) (*DB, error) {
	sqldb, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open audit sqlite: %w", err)
	}
	sqldb.SetMaxOpenConns(1)
	if _, err := sqldb.Exec(`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;`); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("audit sqlite pragmas: %w", err)
	}
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("ping audit sqlite: %w", err)
	}
	d := &DB{db: sqldb, lite: true}
	if err := d.ensureSchema(context.Background()); err != nil {
		sqldb.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) ensureSchema(ctx context.Context) error {
	tsType := "TIMESTAMPTZ"
	if d.lite {
		tsType = "DATETIME"
	}
	_, err := d.db.ExecContext(ctx, fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS audit_logs (
    id         TEXT    PRIMARY KEY,
    action     TEXT    NOT NULL,
    actor_id   TEXT,
    project_id TEXT,
    env_id     TEXT,
    resource   TEXT,
    metadata   TEXT,
    ip         TEXT,
    created_at %s NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_project_id ON audit_logs(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_env_id     ON audit_logs(env_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_logs(action);`, tsType))
	if err != nil {
		return fmt.Errorf("audit schema: %w", err)
	}
	return nil
}

// ph returns the SQL placeholder for argument position n.
// Postgres uses positional $N; SQLite uses ? for every position.
func (d *DB) ph(n int) string {
	if d.lite {
		return "?"
	}
	return fmt.Sprintf("$%d", n)
}

// UpsertAuditLog inserts e into the audit database. ON CONFLICT (id) DO NOTHING
// makes the operation idempotent: JetStream at-least-once redelivery is handled
// safely without producing duplicate rows.
func (d *DB) UpsertAuditLog(ctx context.Context, e Entry) error {
	q := fmt.Sprintf(
		`INSERT INTO audit_logs (id, action, actor_id, project_id, env_id, resource, metadata, ip, created_at)
		 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING`,
		d.ph(1), d.ph(2), d.ph(3), d.ph(4), d.ph(5), d.ph(6), d.ph(7), d.ph(8), d.ph(9),
	)
	_, err := d.db.ExecContext(ctx, q,
		e.ID, e.Action,
		nilIfEmpty(e.ActorID), nilIfEmpty(e.ProjectID), nilIfEmpty(e.EnvID),
		nilIfEmpty(e.Resource), nilIfEmpty(e.Metadata), nilIfEmpty(e.IP),
		e.OccurredAt,
	)
	return err
}

// ListAuditLogs returns audit entries matching f, ordered by created_at DESC.
func (d *DB) ListAuditLogs(ctx context.Context, f Filter) ([]*model.AuditLog, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}

	where := []string{"1=1"}
	args := []any{}
	n := 1

	if f.ProjectID != "" {
		where = append(where, "project_id = "+d.ph(n))
		args = append(args, f.ProjectID)
		n++
	}
	if f.EnvID != "" {
		where = append(where, "env_id = "+d.ph(n))
		args = append(args, f.EnvID)
		n++
	}
	if f.Action != "" {
		where = append(where, "action = "+d.ph(n))
		args = append(args, f.Action)
		n++
	}
	args = append(args, limit)

	q := fmt.Sprintf(
		`SELECT id, action, actor_id, project_id, env_id, resource, metadata, ip, created_at
		 FROM audit_logs WHERE %s ORDER BY created_at DESC LIMIT %s`,
		strings.Join(where, " AND "), d.ph(n),
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

// Close closes the underlying database connection pool.
func (d *DB) Close() error { return d.db.Close() }

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// NoopQueryStore implements QueryStore with empty results. Use in tests.
type NoopQueryStore struct{}

func (NoopQueryStore) ListAuditLogs(_ context.Context, _ Filter) ([]*model.AuditLog, error) {
	return nil, nil
}
func (NoopQueryStore) Close() error { return nil }
