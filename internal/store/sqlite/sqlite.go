// Package sqlite implements the store.Store interface using SQLite via modernc.org/sqlite.
// Migrations are embedded and run automatically on Open.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

//go:embed migrations
var migrationsFS embed.FS

// DB wraps sql.DB and implements store.Store.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and runs migrations.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite is single-writer; one connection avoids locking contention.
	db.SetMaxOpenConns(1)

	// PRAGMAs must run outside any transaction — WAL mode change inside a
	// transaction is rejected by SQLite with "cannot change into wal mode
	// from within a transaction".
	if _, err := db.Exec(`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;`); err != nil {
		return nil, fmt.Errorf("sqlite pragmas: %w", err)
	}

	s := &DB{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *DB) migrate() error {
	// Tracking table: records which migration files have been applied.
	// Created before any migrations so it is always present.
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&already)
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
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, version); err != nil {
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

const userCols = `id, email, password_hash, role, oidc_issuer, oidc_subject, active, scim_external_id, created_at`

func scanUser(row interface{ Scan(...any) error }) (*model.User, error) {
	var (
		u       model.User
		hash    sql.NullString
		issuer  sql.NullString
		subject sql.NullString
		extID   sql.NullString
	)
	if err := row.Scan(&u.ID, &u.Email, &hash, &u.Role, &issuer, &subject, &u.Active, &extID, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.PasswordHash = hash.String
	if issuer.Valid {
		u.OIDCIssuer = &issuer.String
	}
	if subject.Valid {
		u.OIDCSubject = &subject.String
	}
	if extID.Valid {
		u.SCIMExternalID = &extID.String
	}
	return &u, nil
}

func (s *DB) CreateUser(ctx context.Context, email, passwordHash, role string) (*model.User, error) {
	u := &model.User{
		ID:           uuid.NewString(),
		Email:        email,
		PasswordHash: passwordHash,
		Role:         role,
		Active:       true,
		CreatedAt:    time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, role, active, created_at) VALUES (?, ?, ?, ?, 1, ?)`,
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

func (s *DB) CreateOIDCUser(ctx context.Context, email, oidcIssuer, oidcSubject, role string) (*model.User, error) {
	u := &model.User{
		ID:          uuid.NewString(),
		Email:       email,
		Role:        role,
		Active:      true,
		OIDCIssuer:  &oidcIssuer,
		OIDCSubject: &oidcSubject,
		CreatedAt:   time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, role, oidc_issuer, oidc_subject, active, created_at)
		 VALUES (?, ?, NULL, ?, ?, ?, 1, ?)`,
		u.ID, u.Email, u.Role, oidcIssuer, oidcSubject, u.CreatedAt,
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
	row := s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email = ?`, email)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return u, err
}

func (s *DB) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return u, err
}

func (s *DB) GetUserByOIDCSubject(ctx context.Context, issuer, subject string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE oidc_issuer = ? AND oidc_subject = ?`, issuer, subject)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return u, err
}

func (s *DB) ListUsers(ctx context.Context) ([]*model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
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
		`UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, userID,
	)
	return err
}

func (s *DB) SetUserOIDCIdentity(ctx context.Context, userID, issuer, subject string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET oidc_issuer = ?, oidc_subject = ? WHERE id = ?`, issuer, subject, userID,
	)
	if err != nil && isUnique(err) {
		return store.ErrConflict
	}
	return err
}

func (s *DB) SetUserActive(ctx context.Context, userID string, active bool) error {
	v := 0
	if active {
		v = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET active = ? WHERE id = ?`, v, userID)
	return err
}

func (s *DB) DeleteAllTokensForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE user_id = ?`, userID)
	return err
}

// ── SCIM tokens ───────────────────────────────────────────────────────────────

func (s *DB) CreateSCIMToken(ctx context.Context, t *model.SCIMToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scim_tokens (id, token_hash, description, created_at) VALUES (?, ?, ?, ?)`,
		t.ID, t.TokenHash, t.Description, t.CreatedAt,
	)
	if err != nil && isUnique(err) {
		return store.ErrConflict
	}
	return err
}

func (s *DB) GetSCIMTokenByHash(ctx context.Context, hash string) (*model.SCIMToken, error) {
	t := &model.SCIMToken{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, token_hash, description, created_at FROM scim_tokens WHERE token_hash = ?`, hash,
	).Scan(&t.ID, &t.TokenHash, &t.Description, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return t, err
}

func (s *DB) ListSCIMTokens(ctx context.Context) ([]*model.SCIMToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, token_hash, description, created_at FROM scim_tokens ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []*model.SCIMToken
	for rows.Next() {
		t := &model.SCIMToken{}
		if err := rows.Scan(&t.ID, &t.TokenHash, &t.Description, &t.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *DB) DeleteSCIMToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM scim_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── SCIM group roles ──────────────────────────────────────────────────────────

func (s *DB) SetSCIMGroupRole(ctx context.Context, groupID, displayName string, projectID, envID *string, role string) (*model.SCIMGroupRole, error) {
	r := &model.SCIMGroupRole{
		ID:          uuid.NewString(),
		GroupID:     groupID,
		DisplayName: displayName,
		ProjectID:   projectID,
		EnvID:       envID,
		Role:        role,
		CreatedAt:   time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scim_group_roles (id, group_id, display_name, project_id, env_id, role, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (group_id, project_id, env_id) DO UPDATE
		     SET display_name = excluded.display_name, role = excluded.role`,
		r.ID, r.GroupID, r.DisplayName, r.ProjectID, r.EnvID, r.Role, r.CreatedAt,
	)
	return r, err
}

func (s *DB) ListSCIMGroupRoles(ctx context.Context) ([]*model.SCIMGroupRole, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, group_id, display_name, project_id, env_id, role, created_at FROM scim_group_roles ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []*model.SCIMGroupRole
	for rows.Next() {
		r := &model.SCIMGroupRole{}
		if err := rows.Scan(&r.ID, &r.GroupID, &r.DisplayName, &r.ProjectID, &r.EnvID, &r.Role, &r.CreatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (s *DB) ListSCIMGroupRolesByGroup(ctx context.Context, groupID string) ([]*model.SCIMGroupRole, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, group_id, display_name, project_id, env_id, role, created_at FROM scim_group_roles WHERE group_id = ? ORDER BY created_at`, groupID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []*model.SCIMGroupRole
	for rows.Next() {
		r := &model.SCIMGroupRole{}
		if err := rows.Scan(&r.ID, &r.GroupID, &r.DisplayName, &r.ProjectID, &r.EnvID, &r.Role, &r.CreatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (s *DB) GetSCIMGroupRole(ctx context.Context, id string) (*model.SCIMGroupRole, error) {
	r := &model.SCIMGroupRole{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, group_id, display_name, project_id, env_id, role, created_at FROM scim_group_roles WHERE id = ?`, id,
	).Scan(&r.ID, &r.GroupID, &r.DisplayName, &r.ProjectID, &r.EnvID, &r.Role, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return r, err
}

func (s *DB) DeleteSCIMGroupRole(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM scim_group_roles WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── Tokens ───────────────────────────────────────────────────────────────────

func (s *DB) CreateToken(ctx context.Context, t *model.Token) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, user_id, token_hash, name, project_id, env_id, read_only, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.TokenHash, t.Name, t.ProjectID, t.EnvID, t.ReadOnly, t.ExpiresAt, t.CreatedAt,
	)
	return err
}

func (s *DB) GetTokenByHash(ctx context.Context, hash string) (*model.Token, error) {
	t := &model.Token{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, name, project_id, env_id, read_only, expires_at, created_at
		 FROM tokens WHERE token_hash = ?`, hash,
	).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.Name, &t.ProjectID, &t.EnvID, &t.ReadOnly, &t.ExpiresAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return t, err
}

func (s *DB) ListTokens(ctx context.Context, userID string) ([]*model.Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, token_hash, name, project_id, env_id, read_only, expires_at, created_at
		 FROM tokens WHERE user_id = ? ORDER BY created_at DESC`, userID,
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

func (s *DB) ListTokensWithAccess(ctx context.Context, projectID, envID string) ([]*model.Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, token_hash, name, project_id, env_id, read_only, expires_at, created_at
		 FROM tokens
		 WHERE
		   (project_id = ? AND env_id = ?)
		   OR (project_id = ? AND env_id IS NULL)
		   OR (project_id IS NULL AND user_id IN (
		         SELECT user_id FROM project_members WHERE project_id = ?
		       ))
		 ORDER BY created_at DESC`, projectID, envID, projectID, projectID,
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
		`DELETE FROM tokens WHERE id = ? AND user_id = ?`, id, userID,
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
		`INSERT INTO projects (id, name, slug, created_at) VALUES (?, ?, ?, ?)`,
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
		`SELECT id, name, slug, encrypted_pek, created_at FROM projects WHERE slug = ?`, slug,
	).Scan(&p.ID, &p.Name, &p.Slug, &p.EncryptedPEK, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (s *DB) GetProjectByID(ctx context.Context, id string) (*model.Project, error) {
	p := &model.Project{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, slug, encrypted_pek, created_at FROM projects WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.Slug, &p.EncryptedPEK, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (s *DB) ListProjectsByMember(ctx context.Context, userID string) ([]*model.Project, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT p.id, p.name, p.slug, p.encrypted_pek, p.created_at
		 FROM projects p
		 JOIN project_members pm ON pm.project_id = p.id
		 WHERE pm.user_id = ?
		 ORDER BY p.name`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var projects []*model.Project
	for rows.Next() {
		p := &model.Project{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.EncryptedPEK, &p.CreatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

func (s *DB) ListProjects(ctx context.Context) ([]*model.Project, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, slug, encrypted_pek, created_at FROM projects ORDER BY name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var projects []*model.Project
	for rows.Next() {
		p := &model.Project{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.EncryptedPEK, &p.CreatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

func (s *DB) SetProjectKey(ctx context.Context, projectID string, encPEK []byte) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE projects SET encrypted_pek = ? WHERE id = ?`, encPEK, projectID,
	)
	return err
}

func (s *DB) RewrapProjectDEKs(ctx context.Context, projectID string, rewrap func([]byte) ([]byte, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Re-wrap all secret version DEKs for this project.
	svRows, err := tx.QueryContext(ctx,
		`SELECT sv.id, sv.encrypted_dek
		 FROM secret_versions sv
		 JOIN secrets s ON sv.secret_id = s.id
		 WHERE s.project_id = ?`, projectID,
	)
	if err != nil {
		return err
	}
	type idDEK struct {
		id  string
		dek []byte
	}
	var svs []idDEK
	for svRows.Next() {
		var r idDEK
		if err := svRows.Scan(&r.id, &r.dek); err != nil {
			svRows.Close()
			return err
		}
		svs = append(svs, r)
	}
	svRows.Close()
	if err := svRows.Err(); err != nil {
		return err
	}
	for _, r := range svs {
		newDEK, err := rewrap(r.dek)
		if err != nil {
			return fmt.Errorf("rewrap secret_version %s: %w", r.id, err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE secret_versions SET encrypted_dek = ? WHERE id = ?`, newDEK, r.id,
		); err != nil {
			return err
		}
	}

	// Re-wrap all dynamic backend config DEKs for this project.
	dbRows, err := tx.QueryContext(ctx,
		`SELECT id, encrypted_config_dek FROM dynamic_backends WHERE project_id = ?`, projectID,
	)
	if err != nil {
		return err
	}
	var dbs []idDEK
	for dbRows.Next() {
		var r idDEK
		if err := dbRows.Scan(&r.id, &r.dek); err != nil {
			dbRows.Close()
			return err
		}
		dbs = append(dbs, r)
	}
	dbRows.Close()
	if err := dbRows.Err(); err != nil {
		return err
	}
	for _, r := range dbs {
		newDEK, err := rewrap(r.dek)
		if err != nil {
			return fmt.Errorf("rewrap dynamic_backend %s: %w", r.id, err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE dynamic_backends SET encrypted_config_dek = ? WHERE id = ?`, newDEK, r.id,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *DB) DeleteProject(ctx context.Context, slug string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE slug = ?`, slug)
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

func (s *DB) AddProjectMember(ctx context.Context, projectID, userID, role string, envID *string) error {
	if envID == nil {
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO project_members (project_id, user_id, env_id, role)
			 VALUES (?, ?, NULL, ?)
			 ON CONFLICT(project_id, user_id) WHERE env_id IS NULL
			 DO UPDATE SET role = excluded.role`,
			projectID, userID, role,
		)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO project_members (project_id, user_id, env_id, role)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(project_id, user_id, env_id) WHERE env_id IS NOT NULL
		 DO UPDATE SET role = excluded.role`,
		projectID, userID, *envID, role,
	)
	return err
}

func (s *DB) GetProjectMember(ctx context.Context, projectID, userID string) (*model.ProjectMember, error) {
	m := &model.ProjectMember{}
	err := s.db.QueryRowContext(ctx,
		`SELECT project_id, user_id, env_id, role, created_at FROM project_members
		 WHERE project_id = ? AND user_id = ? AND env_id IS NULL`, projectID, userID,
	).Scan(&m.ProjectID, &m.UserID, &m.EnvID, &m.Role, &m.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return m, err
}

func (s *DB) GetProjectMemberForEnv(ctx context.Context, projectID, envID, userID string) (*model.ProjectMember, error) {
	m := &model.ProjectMember{}
	err := s.db.QueryRowContext(ctx,
		`SELECT project_id, user_id, env_id, role, created_at FROM project_members
		 WHERE project_id = ? AND user_id = ? AND (env_id = ? OR env_id IS NULL)
		 ORDER BY CASE WHEN env_id IS NULL THEN 1 ELSE 0 END
		 LIMIT 1`,
		projectID, userID, envID,
	).Scan(&m.ProjectID, &m.UserID, &m.EnvID, &m.Role, &m.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return m, err
}

func (s *DB) ListProjectMembers(ctx context.Context, projectID string) ([]*model.ProjectMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT project_id, user_id, env_id, role, created_at FROM project_members
		 WHERE project_id = ? ORDER BY created_at`, projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []*model.ProjectMember
	for rows.Next() {
		m := &model.ProjectMember{}
		if err := rows.Scan(&m.ProjectID, &m.UserID, &m.EnvID, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *DB) ListProjectMembersWithAccess(ctx context.Context, projectID, envID string) ([]*model.ProjectMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT project_id, user_id, env_id, role, created_at FROM project_members
		 WHERE project_id = ? AND (env_id IS NULL OR env_id = ?)
		 ORDER BY created_at`,
		projectID, envID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []*model.ProjectMember
	for rows.Next() {
		m := &model.ProjectMember{}
		if err := rows.Scan(&m.ProjectID, &m.UserID, &m.EnvID, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *DB) UpdateProjectMember(ctx context.Context, projectID, userID, role string, envID *string) error {
	var res sql.Result
	var err error
	if envID == nil {
		res, err = s.db.ExecContext(ctx,
			`UPDATE project_members SET role = ? WHERE project_id = ? AND user_id = ? AND env_id IS NULL`,
			role, projectID, userID,
		)
	} else {
		res, err = s.db.ExecContext(ctx,
			`UPDATE project_members SET role = ? WHERE project_id = ? AND user_id = ? AND env_id = ?`,
			role, projectID, userID, *envID,
		)
	}
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) RemoveProjectMember(ctx context.Context, projectID, userID string, envID *string) error {
	var res sql.Result
	var err error
	if envID == nil {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM project_members WHERE project_id = ? AND user_id = ? AND env_id IS NULL`,
			projectID, userID,
		)
	} else {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM project_members WHERE project_id = ? AND user_id = ? AND env_id = ?`,
			projectID, userID, *envID,
		)
	}
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
		`INSERT INTO environments (id, project_id, name, slug, created_at) VALUES (?, ?, ?, ?, ?)`,
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
		`SELECT id, project_id, name, slug, created_at FROM environments WHERE project_id = ? AND slug = ?`,
		projectID, slug,
	).Scan(&e.ID, &e.ProjectID, &e.Name, &e.Slug, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return e, err
}

func (s *DB) ListEnvironments(ctx context.Context, projectID string) ([]*model.Environment, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, name, slug, created_at FROM environments WHERE project_id = ? ORDER BY name`,
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
		`DELETE FROM environments WHERE project_id = ? AND slug = ?`, projectID, slug,
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

	// Upsert the secret row (insert or get existing).
	var secretID string
	var nextVersion int
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM secrets WHERE project_id = ? AND env_id = ? AND key = ?`,
		projectID, envID, key,
	).Scan(&secretID)

	if err == sql.ErrNoRows {
		// New secret — rowid is assigned automatically by SQLite (no position column needed).
		secretID = uuid.NewString()
		nextVersion = 1
		initialComment := ""
		if comment != nil {
			initialComment = *comment
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO secrets (id, project_id, env_id, key, comment, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			secretID, projectID, envID, key, initialComment, now, now,
		)
		if err != nil {
			return nil, fmt.Errorf("insert secret: %w", err)
		}
	} else if err != nil {
		return nil, err
	} else {
		// Existing secret — compute next version number.
		err = tx.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(version), 0) + 1 FROM secret_versions WHERE secret_id = ?`, secretID,
		).Scan(&nextVersion)
		if err != nil {
			return nil, fmt.Errorf("compute version: %w", err)
		}
	}

	// Insert the new version (append-only).
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
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sv.ID, sv.SecretID, sv.EncryptedValue, sv.EncryptedDEK, sv.Version, sv.CreatedAt, sv.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("insert secret_version: %w", err)
	}

	// Update current version; optionally update comment (COALESCE: NULL = keep existing).
	_, err = tx.ExecContext(ctx,
		`UPDATE secrets SET current_version_id = ?, updated_at = ?, comment = COALESCE(?, comment) WHERE id = ?`,
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
		`SELECT id, project_id, env_id, key, comment, rowid, current_version_id, created_at, updated_at
		 FROM secrets WHERE project_id = ? AND env_id = ? AND key = ?`,
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
		 FROM secret_versions WHERE id = ?`, *sec.CurrentVersionID,
	).Scan(&sv.ID, &sv.SecretID, &sv.EncryptedValue, &sv.EncryptedDEK, &sv.Version, &sv.CreatedAt, &sv.CreatedBy)
	if err != nil {
		return nil, nil, err
	}
	return sec, sv, nil
}

func (s *DB) ListSecrets(ctx context.Context, projectID, envID string) ([]*model.Secret, []*model.SecretVersion, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT s.id, s.project_id, s.env_id, s.key, s.comment, s.rowid, s.current_version_id, s.created_at, s.updated_at,
		        sv.id, sv.secret_id, sv.encrypted_value, sv.encrypted_dek, sv.version, sv.created_at, sv.created_by
		 FROM secrets s
		 LEFT JOIN secret_versions sv ON sv.id = s.current_version_id
		 WHERE s.project_id = ? AND s.env_id = ?
		 ORDER BY s.rowid ASC`,
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
		`DELETE FROM secrets WHERE project_id = ? AND env_id = ? AND key = ?`,
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
		 FROM secret_versions WHERE secret_id = ? ORDER BY version DESC`, secretID,
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
		`UPDATE secrets SET current_version_id = ?, updated_at = ? WHERE id = ?`,
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
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
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

	query := `SELECT id, action, actor_id, project_id, resource, metadata, ip, created_at
	          FROM audit_logs WHERE 1=1`
	args := []any{}

	if filter.ProjectID != "" {
		query += " AND project_id = ?"
		args = append(args, filter.ProjectID)
	}
	if filter.Action != "" {
		query += " AND action = ?"
		args = append(args, filter.Action)
	}
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

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

// ── helpers ──────────────────────────────────────────────────────────────────

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
