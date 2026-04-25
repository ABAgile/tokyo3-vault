package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/model"
	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB connected to an audit SQLite database.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) an audit SQLite database at path. The schema is
// created inline if absent. SQLite enforces single-writer by capping open conns.
func Open(path string) (*DB, error) {
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
	d := &DB{db: sqldb}
	if err := d.ensureSchema(context.Background()); err != nil {
		sqldb.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) ensureSchema(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS audit_logs (
    id         TEXT     PRIMARY KEY,
    action     TEXT     NOT NULL,
    actor_id   TEXT,
    project_id TEXT,
    env_id     TEXT,
    resource   TEXT,
    metadata   TEXT,
    ip         TEXT,
    created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_project_id ON audit_logs(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_env_id     ON audit_logs(env_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_logs(action);`)
	if err != nil {
		return fmt.Errorf("audit schema: %w", err)
	}
	return nil
}

func (d *DB) UpsertAuditLog(ctx context.Context, e audit.Entry) error {
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, action, actor_id, project_id, env_id, resource, metadata, ip, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING`,
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

	if f.ProjectID != "" {
		where = append(where, "project_id = ?")
		args = append(args, f.ProjectID)
	}
	if f.EnvID != "" {
		where = append(where, "env_id = ?")
		args = append(args, f.EnvID)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	args = append(args, limit)

	q := fmt.Sprintf(
		`SELECT id, action, actor_id, project_id, env_id, resource, metadata, ip, created_at
		 FROM audit_logs WHERE %s ORDER BY created_at DESC LIMIT ?`,
		strings.Join(where, " AND "),
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
