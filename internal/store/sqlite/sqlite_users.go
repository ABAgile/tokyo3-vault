package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

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

func (s *DB) GetUserBySCIMExternalID(ctx context.Context, externalID string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE scim_external_id = ?`, externalID)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return u, err
}

func (s *DB) SetUserSCIMExternalID(ctx context.Context, userID, externalID string) error {
	var arg any
	if externalID == "" {
		arg = nil
	} else {
		arg = externalID
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET scim_external_id = ? WHERE id = ?`, arg, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
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

func (s *DB) SetUserRole(ctx context.Context, userID, role string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) CountAdminUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&n)
	return n, err
}

func (s *DB) DeleteAllTokensForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE user_id = ?`, userID)
	return err
}
