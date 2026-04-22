package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

// ── Dynamic backends ─────────────────────────────────────────────────────────

func (s *DB) SetDynamicBackend(ctx context.Context, projectID, envID, slug, backendType string, encConfig, encConfigDEK []byte, defaultTTL, maxTTL int) (*model.DynamicBackend, error) {
	now := time.Now().UTC()
	id := uuid.NewString()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dynamic_backends
		    (id, project_id, env_id, slug, type, encrypted_config, encrypted_config_dek, default_ttl, max_ttl, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, env_id, slug) DO UPDATE SET
		    type                 = excluded.type,
		    encrypted_config     = excluded.encrypted_config,
		    encrypted_config_dek = excluded.encrypted_config_dek,
		    default_ttl          = excluded.default_ttl,
		    max_ttl              = excluded.max_ttl,
		    updated_at           = excluded.updated_at`,
		id, projectID, envID, slug, backendType, encConfig, encConfigDEK, defaultTTL, maxTTL, now, now,
	)
	if err != nil {
		return nil, err
	}
	return s.GetDynamicBackend(ctx, projectID, envID, slug)
}

func (s *DB) GetDynamicBackend(ctx context.Context, projectID, envID, slug string) (*model.DynamicBackend, error) {
	b := &model.DynamicBackend{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, env_id, slug, type, encrypted_config, encrypted_config_dek,
		       default_ttl, max_ttl, created_at, updated_at
		FROM dynamic_backends WHERE project_id = ? AND env_id = ? AND slug = ?`,
		projectID, envID, slug,
	).Scan(&b.ID, &b.ProjectID, &b.EnvID, &b.Slug, &b.Type, &b.EncryptedConfig, &b.EncryptedConfigDEK,
		&b.DefaultTTL, &b.MaxTTL, &b.CreatedAt, &b.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return b, err
}

func (s *DB) GetDynamicBackendByID(ctx context.Context, id string) (*model.DynamicBackend, error) {
	b := &model.DynamicBackend{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, env_id, slug, type, encrypted_config, encrypted_config_dek,
		       default_ttl, max_ttl, created_at, updated_at
		FROM dynamic_backends WHERE id = ?`, id,
	).Scan(&b.ID, &b.ProjectID, &b.EnvID, &b.Slug, &b.Type, &b.EncryptedConfig, &b.EncryptedConfigDEK,
		&b.DefaultTTL, &b.MaxTTL, &b.CreatedAt, &b.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return b, err
}

func (s *DB) DeleteDynamicBackend(ctx context.Context, projectID, envID, slug string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM dynamic_backends WHERE project_id = ? AND env_id = ? AND slug = ?`,
		projectID, envID, slug)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── Dynamic roles ─────────────────────────────────────────────────────────────

func (s *DB) SetDynamicRole(ctx context.Context, backendID, name, creationTmpl, revocationTmpl string, ttl *int) (*model.DynamicRole, error) {
	id := uuid.NewString()
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dynamic_roles
		    (id, backend_id, name, creation_tmpl, revocation_tmpl, ttl, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(backend_id, name) DO UPDATE SET
		    creation_tmpl   = excluded.creation_tmpl,
		    revocation_tmpl = excluded.revocation_tmpl,
		    ttl             = excluded.ttl`,
		id, backendID, name, creationTmpl, revocationTmpl, ttl, now,
	)
	if err != nil {
		return nil, err
	}
	return s.GetDynamicRole(ctx, backendID, name)
}

func (s *DB) GetDynamicRole(ctx context.Context, backendID, name string) (*model.DynamicRole, error) {
	r := &model.DynamicRole{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, backend_id, name, creation_tmpl, revocation_tmpl, ttl, created_at
		FROM dynamic_roles WHERE backend_id = ? AND name = ?`,
		backendID, name,
	).Scan(&r.ID, &r.BackendID, &r.Name, &r.CreationTmpl, &r.RevocationTmpl, &r.TTL, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return r, err
}

func (s *DB) ListDynamicRoles(ctx context.Context, backendID string) ([]*model.DynamicRole, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, backend_id, name, creation_tmpl, revocation_tmpl, ttl, created_at
		FROM dynamic_roles WHERE backend_id = ? ORDER BY name`,
		backendID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.DynamicRole
	for rows.Next() {
		r := &model.DynamicRole{}
		if err := rows.Scan(&r.ID, &r.BackendID, &r.Name, &r.CreationTmpl, &r.RevocationTmpl, &r.TTL, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if out == nil {
		out = []*model.DynamicRole{}
	}
	return out, rows.Err()
}

func (s *DB) DeleteDynamicRole(ctx context.Context, backendID, name string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM dynamic_roles WHERE backend_id = ? AND name = ?`,
		backendID, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── Dynamic leases ───────────────────────────────────────────────────────────

func (s *DB) CreateDynamicLease(ctx context.Context, projectID, envID, backendID, roleID, roleName, username, revocationTmpl string, expiresAt time.Time, createdBy *string) (*model.DynamicLease, error) {
	l := &model.DynamicLease{
		ID:             uuid.NewString(),
		ProjectID:      projectID,
		EnvID:          envID,
		BackendID:      backendID,
		RoleID:         roleID,
		RoleName:       roleName,
		Username:       username,
		RevocationTmpl: revocationTmpl,
		ExpiresAt:      expiresAt,
		CreatedBy:      createdBy,
		CreatedAt:      time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dynamic_leases
		    (id, project_id, env_id, backend_id, role_id, role_name, username,
		     revocation_tmpl, expires_at, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.ProjectID, l.EnvID, l.BackendID, l.RoleID, l.RoleName, l.Username,
		l.RevocationTmpl, l.ExpiresAt, l.CreatedBy, l.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (s *DB) GetDynamicLease(ctx context.Context, id string) (*model.DynamicLease, error) {
	l := &model.DynamicLease{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, env_id, backend_id, role_id, role_name, username,
		       revocation_tmpl, expires_at, revoked_at, created_by, created_at
		FROM dynamic_leases WHERE id = ?`, id,
	).Scan(&l.ID, &l.ProjectID, &l.EnvID, &l.BackendID, &l.RoleID, &l.RoleName,
		&l.Username, &l.RevocationTmpl, &l.ExpiresAt, &l.RevokedAt, &l.CreatedBy, &l.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return l, err
}

func (s *DB) ListDynamicLeases(ctx context.Context, projectID, envID string) ([]*model.DynamicLease, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, env_id, backend_id, role_id, role_name, username,
		       revocation_tmpl, expires_at, revoked_at, created_by, created_at
		FROM dynamic_leases WHERE project_id = ? AND env_id = ?
		ORDER BY created_at DESC`,
		projectID, envID)
	if err != nil {
		return nil, err
	}
	return scanLeases(rows)
}

func (s *DB) RevokeDynamicLease(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE dynamic_leases SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) ListExpiredDynamicLeases(ctx context.Context) ([]*model.DynamicLease, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, env_id, backend_id, role_id, role_name, username,
		       revocation_tmpl, expires_at, revoked_at, created_by, created_at
		FROM dynamic_leases
		WHERE revoked_at IS NULL AND expires_at <= ?`,
		time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return scanLeases(rows)
}

func scanLeases(rows *sql.Rows) ([]*model.DynamicLease, error) {
	defer rows.Close()
	var out []*model.DynamicLease
	for rows.Next() {
		l := &model.DynamicLease{}
		if err := rows.Scan(&l.ID, &l.ProjectID, &l.EnvID, &l.BackendID, &l.RoleID, &l.RoleName,
			&l.Username, &l.RevocationTmpl, &l.ExpiresAt, &l.RevokedAt, &l.CreatedBy, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if out == nil {
		out = []*model.DynamicLease{}
	}
	return out, rows.Err()
}
