package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

// ── SPIFFE/mTLS certificate principals ───────────────────────────────────────

func (s *DB) CreateCertPrincipal(ctx context.Context, p *model.CertPrincipal) error {
	p.ID = uuid.NewString()
	p.CreatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cert_principals
		    (id, user_id, description, spiffe_id, project_id, env_id, read_only, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.UserID, p.Description, p.SPIFFEID, p.ProjectID, p.EnvID, p.ReadOnly, p.ExpiresAt, p.CreatedAt,
	)
	if err != nil {
		if isUnique(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

func (s *DB) GetCertPrincipalBySPIFFEID(ctx context.Context, spiffeID string) (*model.CertPrincipal, error) {
	p := &model.CertPrincipal{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, description, spiffe_id, project_id, env_id, read_only, expires_at, created_at
		FROM cert_principals WHERE spiffe_id = ?`, spiffeID,
	).Scan(&p.ID, &p.UserID, &p.Description, &p.SPIFFEID, &p.ProjectID, &p.EnvID, &p.ReadOnly, &p.ExpiresAt, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (s *DB) ListCertPrincipals(ctx context.Context, userID string) ([]*model.CertPrincipal, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, description, spiffe_id, project_id, env_id, read_only, expires_at, created_at
		FROM cert_principals WHERE user_id = ? ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.CertPrincipal
	for rows.Next() {
		p := &model.CertPrincipal{}
		if err := rows.Scan(&p.ID, &p.UserID, &p.Description, &p.SPIFFEID, &p.ProjectID, &p.EnvID, &p.ReadOnly, &p.ExpiresAt, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *DB) DeleteCertPrincipal(ctx context.Context, id, userID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM cert_principals WHERE id = ? AND user_id = ?`, id, userID,
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
