package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

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

func (s *DB) GetSecretVersion(ctx context.Context, secretID, versionID string) (*model.SecretVersion, error) {
	sv := &model.SecretVersion{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, secret_id, encrypted_value, encrypted_dek, version, created_at, created_by
		 FROM secret_versions WHERE id = ? AND secret_id = ?`, versionID, secretID,
	).Scan(&sv.ID, &sv.SecretID, &sv.EncryptedValue, &sv.EncryptedDEK, &sv.Version, &sv.CreatedAt, &sv.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return sv, err
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

func (s *DB) ListSecretsForPrune(ctx context.Context) ([][2]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(current_version_id, '') FROM secrets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var pair [2]string
		if err := rows.Scan(&pair[0], &pair[1]); err != nil {
			return nil, err
		}
		out = append(out, pair)
	}
	return out, rows.Err()
}

func (s *DB) PruneSecretVersions(ctx context.Context, secretID, currentVersionID string, maxCount int, cutoff time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		WITH ranked AS (
			SELECT id,
			       ROW_NUMBER() OVER (ORDER BY version DESC) AS rn,
			       created_at
			FROM secret_versions
			WHERE secret_id = ?
			  AND id != ?
		)
		DELETE FROM secret_versions
		WHERE id IN (
			SELECT id FROM ranked
			WHERE rn > ? AND created_at < ?
		)`, secretID, currentVersionID, maxCount, cutoff)
	return err
}
