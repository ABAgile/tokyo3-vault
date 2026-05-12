package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

const tokenCols = `id, user_id, token_hash, name, project_id, env_id, read_only, is_session, expires_at, auth_time, oidc_session_id, created_at`

func scanToken(s interface{ Scan(...any) error }) (*model.Token, error) {
	t := &model.Token{}
	err := s.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.Name, &t.ProjectID, &t.EnvID, &t.ReadOnly, &t.IsSession, &t.ExpiresAt, &t.AuthTime, &t.OIDCSessionID, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return t, err
}

func (s *DB) CreateToken(ctx context.Context, t *model.Token) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, user_id, token_hash, name, project_id, env_id, read_only, is_session, expires_at, auth_time, oidc_session_id, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		t.ID, t.UserID, t.TokenHash, t.Name, t.ProjectID, t.EnvID, t.ReadOnly, t.IsSession, t.ExpiresAt, t.AuthTime, t.OIDCSessionID, t.CreatedAt,
	)
	return err
}

func (s *DB) GetTokenByHash(ctx context.Context, hash string) (*model.Token, error) {
	return scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE token_hash = $1`, hash))
}

func (s *DB) ListTokens(ctx context.Context, userID string) ([]*model.Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+tokenCols+` FROM tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []*model.Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *DB) ListTokensWithAccess(ctx context.Context, projectID, envID string) ([]*model.Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+tokenCols+` FROM tokens
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
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *DB) DeleteTokensByOIDCSession(ctx context.Context, oidcSessionID string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE oidc_session_id = $1`, oidcSessionID,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *DB) ExtendTokenExpiry(ctx context.Context, tokenHash string, newExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET expires_at = $1 WHERE token_hash = $2 AND is_session = true`,
		newExpiry, tokenHash,
	)
	return err
}

func (s *DB) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at < NOW()`,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
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
