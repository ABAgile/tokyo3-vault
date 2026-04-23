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
