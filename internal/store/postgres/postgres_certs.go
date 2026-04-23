package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

// ── cert principals ───────────────────────────────────────────────────────────

const certCols = `id, user_id, description, spiffe_id, email_san, project_id, env_id, read_only, expires_at, created_at`

func scanCertPrincipal(row interface{ Scan(...any) error }) (*model.CertPrincipal, error) {
	p := &model.CertPrincipal{}
	var spiffeID, emailSAN sql.NullString
	err := row.Scan(&p.ID, &p.UserID, &p.Description, &spiffeID, &emailSAN,
		&p.ProjectID, &p.EnvID, &p.ReadOnly, &p.ExpiresAt, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	if spiffeID.Valid {
		p.SPIFFEID = &spiffeID.String
	}
	if emailSAN.Valid {
		p.EmailSAN = &emailSAN.String
	}
	return p, nil
}

func (s *DB) CreateCertPrincipal(ctx context.Context, p *model.CertPrincipal) error {
	p.ID = uuid.NewString()
	p.CreatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cert_principals
		    (id, user_id, description, spiffe_id, email_san, project_id, env_id, read_only, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		p.ID, p.UserID, p.Description, p.SPIFFEID, p.EmailSAN,
		p.ProjectID, p.EnvID, p.ReadOnly, p.ExpiresAt, p.CreatedAt,
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
	p, err := scanCertPrincipal(s.db.QueryRowContext(ctx,
		`SELECT `+certCols+` FROM cert_principals WHERE spiffe_id = $1`, spiffeID,
	))
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (s *DB) GetCertPrincipalByEmailSAN(ctx context.Context, emailSAN string) (*model.CertPrincipal, error) {
	p, err := scanCertPrincipal(s.db.QueryRowContext(ctx,
		`SELECT `+certCols+` FROM cert_principals WHERE email_san = $1`, emailSAN,
	))
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (s *DB) ListCertPrincipals(ctx context.Context, userID string) ([]*model.CertPrincipal, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+certCols+` FROM cert_principals WHERE user_id = $1 ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.CertPrincipal
	for rows.Next() {
		p, err := scanCertPrincipal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *DB) ListCertPrincipalsWithAccess(ctx context.Context, projectID, envID string) ([]*model.CertPrincipal, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+certCols+`
		FROM cert_principals
		WHERE (
		  (project_id = $1 AND env_id = $2)
		  OR (project_id = $1 AND env_id IS NULL)
		  OR (project_id IS NULL AND user_id IN (
		        SELECT user_id FROM project_members WHERE project_id = $1
		      ))
		)
		AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at DESC`, projectID, envID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.CertPrincipal
	for rows.Next() {
		p, err := scanCertPrincipal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *DB) DeleteCertPrincipal(ctx context.Context, id, userID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM cert_principals WHERE id = $1 AND user_id = $2`, id, userID,
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
