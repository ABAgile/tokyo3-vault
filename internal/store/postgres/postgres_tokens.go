package postgres

import (
	"context"
	"database/sql"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

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

func (s *DB) ListTokensWithAccess(ctx context.Context, projectID, envID string) ([]*model.Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, token_hash, name, project_id, env_id, read_only, expires_at, created_at
		 FROM tokens
		 WHERE
		   (project_id = $1 AND env_id = $2)
		   OR (project_id = $1 AND env_id IS NULL)
		   OR (project_id IS NULL AND user_id IN (
		         SELECT user_id FROM project_members WHERE project_id = $1
		       ))
		 ORDER BY created_at DESC`, projectID, envID,
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
