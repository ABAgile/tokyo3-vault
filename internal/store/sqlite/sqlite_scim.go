package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

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
