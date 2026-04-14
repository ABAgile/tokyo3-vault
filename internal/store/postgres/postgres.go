// Package postgres implements store.Store using PostgreSQL via pgx/v5.
// Connect via VAULT_DATABASE_URL (standard DSN or postgres:// URL).
//
// Swap from SQLite to Postgres by changing the store constructor in cmd/vaultd/main.go —
// nothing else changes because the Store interface is the only contract.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
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
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
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

// ── Users ────────────────────────────────────────────────────────────────────

func (s *DB) CreateUser(ctx context.Context, email, passwordHash, role string) (*model.User, error) {
	u := &model.User{
		ID:           uuid.NewString(),
		Email:        email,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, role, created_at) VALUES ($1, $2, $3, $4, $5)`,
		u.ID, u.Email, u.PasswordHash, u.Role, u.CreatedAt,
	)
	if err != nil {
		if isUnique(err) {
			return nil, store.ErrConflict
		}
		return nil, err
	}
	return u, nil
}

func (s *DB) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	u := &model.User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, role, created_at FROM users WHERE email = $1`, email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return u, err
}

func (s *DB) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	u := &model.User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, role, created_at FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return u, err
}

func (s *DB) ListUsers(ctx context.Context) ([]*model.User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, password_hash, role, created_at FROM users ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*model.User
	for rows.Next() {
		u := &model.User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *DB) HasAdminUser(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&n)
	return n > 0, err
}

func (s *DB) UpdateUserPassword(ctx context.Context, userID, passwordHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = $1 WHERE id = $2`, passwordHash, userID,
	)
	return err
}

// ── Tokens ───────────────────────────────────────────────────────────────────

func (s *DB) CreateToken(ctx context.Context, t *model.Token) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, user_id, token_hash, name, project_id, env_id, read_only, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		t.ID, t.UserID, t.TokenHash, t.Name, t.ProjectID, t.EnvID, t.ReadOnly, t.ExpiresAt, t.CreatedAt,
	)
	return err
}

func (s *DB) GetTokenByHash(ctx context.Context, hash string) (*model.Token, error) {
	t := &model.Token{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, name, project_id, env_id, read_only, expires_at, created_at
		 FROM tokens WHERE token_hash = $1`, hash,
	).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.Name, &t.ProjectID, &t.EnvID, &t.ReadOnly, &t.ExpiresAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return t, err
}

func (s *DB) ListTokens(ctx context.Context, userID string) ([]*model.Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, token_hash, name, project_id, env_id, read_only, expires_at, created_at
		 FROM tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []*model.Token
	for rows.Next() {
		t := &model.Token{}
		if err := rows.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.Name, &t.ProjectID, &t.EnvID, &t.ReadOnly, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *DB) DeleteToken(ctx context.Context, id, userID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE id = $1 AND user_id = $2`, id, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── Projects ─────────────────────────────────────────────────────────────────

func (s *DB) CreateProject(ctx context.Context, name, slug string) (*model.Project, error) {
	p := &model.Project{
		ID:        uuid.NewString(),
		Name:      name,
		Slug:      slug,
		CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO projects (id, name, slug, created_at) VALUES ($1, $2, $3, $4)`,
		p.ID, p.Name, p.Slug, p.CreatedAt,
	)
	if err != nil {
		if isUnique(err) {
			return nil, store.ErrConflict
		}
		return nil, err
	}
	return p, nil
}

func (s *DB) GetProject(ctx context.Context, slug string) (*model.Project, error) {
	p := &model.Project{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, slug, created_at FROM projects WHERE slug = $1`, slug,
	).Scan(&p.ID, &p.Name, &p.Slug, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (s *DB) ListProjectsByMember(ctx context.Context, userID string) ([]*model.Project, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT p.id, p.name, p.slug, p.created_at
		 FROM projects p
		 JOIN project_members pm ON pm.project_id = p.id
		 WHERE pm.user_id = $1
		 ORDER BY p.name`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var projects []*model.Project
	for rows.Next() {
		p := &model.Project{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.CreatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

func (s *DB) ListProjects(ctx context.Context) ([]*model.Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, slug, created_at FROM projects ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var projects []*model.Project
	for rows.Next() {
		p := &model.Project{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.CreatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

func (s *DB) DeleteProject(ctx context.Context, slug string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE slug = $1`, slug)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── Project members ───────────────────────────────────────────────────────────

func (s *DB) AddProjectMember(ctx context.Context, projectID, userID, role string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO project_members (project_id, user_id, role)
		 VALUES ($1, $2, $3)
		 ON CONFLICT(project_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		projectID, userID, role,
	)
	return err
}

func (s *DB) GetProjectMember(ctx context.Context, projectID, userID string) (*model.ProjectMember, error) {
	m := &model.ProjectMember{}
	err := s.db.QueryRowContext(ctx,
		`SELECT project_id, user_id, role, created_at FROM project_members
		 WHERE project_id = $1 AND user_id = $2`, projectID, userID,
	).Scan(&m.ProjectID, &m.UserID, &m.Role, &m.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return m, err
}

func (s *DB) ListProjectMembers(ctx context.Context, projectID string) ([]*model.ProjectMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT project_id, user_id, role, created_at FROM project_members
		 WHERE project_id = $1 ORDER BY created_at`, projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []*model.ProjectMember
	for rows.Next() {
		m := &model.ProjectMember{}
		if err := rows.Scan(&m.ProjectID, &m.UserID, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *DB) UpdateProjectMember(ctx context.Context, projectID, userID, role string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE project_members SET role = $1 WHERE project_id = $2 AND user_id = $3`,
		role, projectID, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) RemoveProjectMember(ctx context.Context, projectID, userID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM project_members WHERE project_id = $1 AND user_id = $2`,
		projectID, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── Environments ─────────────────────────────────────────────────────────────

func (s *DB) CreateEnvironment(ctx context.Context, projectID, name, slug string) (*model.Environment, error) {
	e := &model.Environment{
		ID:        uuid.NewString(),
		ProjectID: projectID,
		Name:      name,
		Slug:      slug,
		CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO environments (id, project_id, name, slug, created_at) VALUES ($1, $2, $3, $4, $5)`,
		e.ID, e.ProjectID, e.Name, e.Slug, e.CreatedAt,
	)
	if err != nil {
		if isUnique(err) {
			return nil, store.ErrConflict
		}
		return nil, err
	}
	return e, nil
}

func (s *DB) GetEnvironment(ctx context.Context, projectID, slug string) (*model.Environment, error) {
	e := &model.Environment{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, name, slug, created_at FROM environments WHERE project_id = $1 AND slug = $2`,
		projectID, slug,
	).Scan(&e.ID, &e.ProjectID, &e.Name, &e.Slug, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return e, err
}

func (s *DB) ListEnvironments(ctx context.Context, projectID string) ([]*model.Environment, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, name, slug, created_at FROM environments WHERE project_id = $1 ORDER BY name`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var envs []*model.Environment
	for rows.Next() {
		e := &model.Environment{}
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.Name, &e.Slug, &e.CreatedAt); err != nil {
			return nil, err
		}
		envs = append(envs, e)
	}
	return envs, rows.Err()
}

func (s *DB) DeleteEnvironment(ctx context.Context, projectID, slug string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM environments WHERE project_id = $1 AND slug = $2`, projectID, slug,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── Secrets ──────────────────────────────────────────────────────────────────

func (s *DB) SetSecret(ctx context.Context, projectID, envID, key string, comment *string, encryptedValue, encryptedDEK []byte, createdBy *string) (*model.SecretVersion, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	now := time.Now().UTC()

	var secretID string
	var nextVersion int
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM secrets WHERE project_id = $1 AND env_id = $2 AND key = $3`,
		projectID, envID, key,
	).Scan(&secretID)

	if err == sql.ErrNoRows {
		secretID = uuid.NewString()
		nextVersion = 1
		initialComment := ""
		if comment != nil {
			initialComment = *comment
		}
		// position uses DEFAULT nextval('secrets_position_seq') — no explicit value needed.
		_, err = tx.ExecContext(ctx,
			`INSERT INTO secrets (id, project_id, env_id, key, comment, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			secretID, projectID, envID, key, initialComment, now, now,
		)
		if err != nil {
			return nil, fmt.Errorf("insert secret: %w", err)
		}
	} else if err != nil {
		return nil, err
	} else {
		err = tx.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(version), 0) + 1 FROM secret_versions WHERE secret_id = $1`, secretID,
		).Scan(&nextVersion)
		if err != nil {
			return nil, fmt.Errorf("compute version: %w", err)
		}
	}

	sv := &model.SecretVersion{
		ID:             uuid.NewString(),
		SecretID:       secretID,
		EncryptedValue: encryptedValue,
		EncryptedDEK:   encryptedDEK,
		Version:        nextVersion,
		CreatedAt:      now,
		CreatedBy:      createdBy,
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO secret_versions (id, secret_id, encrypted_value, encrypted_dek, version, created_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sv.ID, sv.SecretID, sv.EncryptedValue, sv.EncryptedDEK, sv.Version, sv.CreatedAt, sv.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("insert secret_version: %w", err)
	}
	// Update current version; optionally update comment (COALESCE: NULL = keep existing).
	_, err = tx.ExecContext(ctx,
		`UPDATE secrets SET current_version_id = $1, updated_at = $2, comment = COALESCE($3, comment) WHERE id = $4`,
		sv.ID, now, comment, secretID,
	)
	if err != nil {
		return nil, fmt.Errorf("update current_version_id: %w", err)
	}
	return sv, tx.Commit()
}

func (s *DB) GetSecret(ctx context.Context, projectID, envID, key string) (*model.Secret, *model.SecretVersion, error) {
	sec := &model.Secret{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, env_id, key, comment, position, current_version_id, created_at, updated_at
		 FROM secrets WHERE project_id = $1 AND env_id = $2 AND key = $3`,
		projectID, envID, key,
	).Scan(&sec.ID, &sec.ProjectID, &sec.EnvID, &sec.Key, &sec.Comment, &sec.Position, &sec.CurrentVersionID, &sec.CreatedAt, &sec.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil, store.ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if sec.CurrentVersionID == nil {
		return sec, nil, nil
	}
	sv := &model.SecretVersion{}
	err = s.db.QueryRowContext(ctx,
		`SELECT id, secret_id, encrypted_value, encrypted_dek, version, created_at, created_by
		 FROM secret_versions WHERE id = $1`, *sec.CurrentVersionID,
	).Scan(&sv.ID, &sv.SecretID, &sv.EncryptedValue, &sv.EncryptedDEK, &sv.Version, &sv.CreatedAt, &sv.CreatedBy)
	if err != nil {
		return nil, nil, err
	}
	return sec, sv, nil
}

func (s *DB) ListSecrets(ctx context.Context, projectID, envID string) ([]*model.Secret, []*model.SecretVersion, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT s.id, s.project_id, s.env_id, s.key, s.comment, s.position, s.current_version_id, s.created_at, s.updated_at,
		        sv.id, sv.secret_id, sv.encrypted_value, sv.encrypted_dek, sv.version, sv.created_at, sv.created_by
		 FROM secrets s
		 LEFT JOIN secret_versions sv ON sv.id = s.current_version_id
		 WHERE s.project_id = $1 AND s.env_id = $2
		 ORDER BY s.position ASC, s.key ASC`,
		projectID, envID,
	)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var secrets []*model.Secret
	var versions []*model.SecretVersion
	for rows.Next() {
		sec := &model.Secret{}
		sv := &model.SecretVersion{}
		var svID, svSecretID *string
		var svEncVal, svEncDEK []byte
		var svVersion *int
		var svCreatedAt *time.Time
		var svCreatedBy *string

		err := rows.Scan(
			&sec.ID, &sec.ProjectID, &sec.EnvID, &sec.Key, &sec.Comment, &sec.Position, &sec.CurrentVersionID, &sec.CreatedAt, &sec.UpdatedAt,
			&svID, &svSecretID, &svEncVal, &svEncDEK, &svVersion, &svCreatedAt, &svCreatedBy,
		)
		if err != nil {
			return nil, nil, err
		}
		secrets = append(secrets, sec)
		if svID != nil {
			sv.ID = *svID
			sv.SecretID = *svSecretID
			sv.EncryptedValue = svEncVal
			sv.EncryptedDEK = svEncDEK
			sv.Version = *svVersion
			sv.CreatedAt = *svCreatedAt
			sv.CreatedBy = svCreatedBy
			versions = append(versions, sv)
		} else {
			versions = append(versions, nil)
		}
	}
	return secrets, versions, rows.Err()
}

func (s *DB) DeleteSecret(ctx context.Context, projectID, envID, key string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM secrets WHERE project_id = $1 AND env_id = $2 AND key = $3`,
		projectID, envID, key,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) ListSecretVersions(ctx context.Context, secretID string) ([]*model.SecretVersion, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, secret_id, encrypted_value, encrypted_dek, version, created_at, created_by
		 FROM secret_versions WHERE secret_id = $1 ORDER BY version DESC`, secretID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []*model.SecretVersion
	for rows.Next() {
		sv := &model.SecretVersion{}
		if err := rows.Scan(&sv.ID, &sv.SecretID, &sv.EncryptedValue, &sv.EncryptedDEK, &sv.Version, &sv.CreatedAt, &sv.CreatedBy); err != nil {
			return nil, err
		}
		versions = append(versions, sv)
	}
	return versions, rows.Err()
}

func (s *DB) RollbackSecret(ctx context.Context, secretID, versionID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE secrets SET current_version_id = $1, updated_at = $2 WHERE id = $3`,
		versionID, time.Now().UTC(), secretID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func (s *DB) CreateAuditLog(ctx context.Context, entry *model.AuditLog) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, action, actor_id, project_id, resource, metadata, ip, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		entry.ID, entry.Action, entry.ActorID, entry.ProjectID,
		entry.Resource, entry.Metadata, entry.IP, entry.CreatedAt,
	)
	return err
}

func (s *DB) ListAuditLogs(ctx context.Context, filter store.AuditFilter) ([]*model.AuditLog, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	// Build query with positional parameters for Postgres.
	conds := []string{"1=1"}
	args := []any{}
	n := 1

	if filter.ProjectID != "" {
		conds = append(conds, fmt.Sprintf("project_id = $%d", n))
		args = append(args, filter.ProjectID)
		n++
	}
	if filter.Action != "" {
		conds = append(conds, fmt.Sprintf("action = $%d", n))
		args = append(args, filter.Action)
		n++
	}
	args = append(args, limit)
	query := fmt.Sprintf(
		`SELECT id, action, actor_id, project_id, resource, metadata, ip, created_at
		 FROM audit_logs WHERE %s ORDER BY created_at DESC LIMIT $%d`,
		strings.Join(conds, " AND "), n,
	)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*model.AuditLog
	for rows.Next() {
		e := &model.AuditLog{}
		if err := rows.Scan(&e.ID, &e.Action, &e.ActorID, &e.ProjectID,
			&e.Resource, &e.Metadata, &e.IP, &e.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, e)
	}
	return logs, rows.Err()
}

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
