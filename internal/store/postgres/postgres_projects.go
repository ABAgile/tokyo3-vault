package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

func (s *DB) CreateProject(ctx context.Context, name, slug string) (*model.Project, error) {
	p := &model.Project{
		ID:        uuid.NewString(),
		Name:      name,
		Slug:      slug,
		CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO projects (id, name, slug, created_at) VALUES ($1, $2, $3, $4)`,
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
		`SELECT id, name, slug, encrypted_pek, created_at FROM projects WHERE slug = $1`, slug,
	).Scan(&p.ID, &p.Name, &p.Slug, &p.EncryptedPEK, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (s *DB) GetProjectByID(ctx context.Context, id string) (*model.Project, error) {
	p := &model.Project{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, slug, encrypted_pek, created_at FROM projects WHERE id = $1`, id,
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
		 WHERE pm.user_id = $1
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, slug, encrypted_pek, created_at FROM projects ORDER BY name`)
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
		`UPDATE projects SET encrypted_pek = $1 WHERE id = $2`, encPEK, projectID,
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
		 WHERE s.project_id = $1`, projectID,
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
			`UPDATE secret_versions SET encrypted_dek = $1 WHERE id = $2`, newDEK, r.id,
		); err != nil {
			return err
		}
	}

	// Re-wrap all dynamic backend config DEKs for this project.
	dbRows, err := tx.QueryContext(ctx,
		`SELECT id, encrypted_config_dek FROM dynamic_backends WHERE project_id = $1`, projectID,
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
			`UPDATE dynamic_backends SET encrypted_config_dek = $1 WHERE id = $2`, newDEK, r.id,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *DB) DeleteProject(ctx context.Context, slug string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE slug = $1`, slug)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) AddProjectMember(ctx context.Context, projectID, userID, role string, envID *string) error {
	if envID == nil {
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO project_members (project_id, user_id, env_id, role)
			 VALUES ($1, $2, NULL, $3)
			 ON CONFLICT(project_id, user_id) WHERE env_id IS NULL
			 DO UPDATE SET role = EXCLUDED.role`,
			projectID, userID, role,
		)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO project_members (project_id, user_id, env_id, role)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT(project_id, user_id, env_id) WHERE env_id IS NOT NULL
		 DO UPDATE SET role = EXCLUDED.role`,
		projectID, userID, *envID, role,
	)
	return err
}

func (s *DB) GetProjectMember(ctx context.Context, projectID, userID string) (*model.ProjectMember, error) {
	m := &model.ProjectMember{}
	err := s.db.QueryRowContext(ctx,
		`SELECT project_id, user_id, env_id, role, created_at FROM project_members
		 WHERE project_id = $1 AND user_id = $2 AND env_id IS NULL`, projectID, userID,
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
		 WHERE project_id = $1 AND user_id = $2 AND (env_id = $3 OR env_id IS NULL)
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
		 WHERE project_id = $1 ORDER BY created_at`, projectID,
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
		 WHERE project_id = $1 AND (env_id IS NULL OR env_id = $2)
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
			`UPDATE project_members SET role = $1 WHERE project_id = $2 AND user_id = $3 AND env_id IS NULL`,
			role, projectID, userID,
		)
	} else {
		res, err = s.db.ExecContext(ctx,
			`UPDATE project_members SET role = $1 WHERE project_id = $2 AND user_id = $3 AND env_id = $4`,
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
			`DELETE FROM project_members WHERE project_id = $1 AND user_id = $2 AND env_id IS NULL`,
			projectID, userID,
		)
	} else {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM project_members WHERE project_id = $1 AND user_id = $2 AND env_id = $3`,
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

func (s *DB) CreateEnvironment(ctx context.Context, projectID, name, slug string) (*model.Environment, error) {
	e := &model.Environment{
		ID:        uuid.NewString(),
		ProjectID: projectID,
		Name:      name,
		Slug:      slug,
		CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO environments (id, project_id, name, slug, created_at) VALUES ($1, $2, $3, $4, $5)`,
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
		`SELECT id, project_id, name, slug, created_at FROM environments WHERE project_id = $1 AND slug = $2`,
		projectID, slug,
	).Scan(&e.ID, &e.ProjectID, &e.Name, &e.Slug, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return e, err
}

func (s *DB) ListEnvironments(ctx context.Context, projectID string) ([]*model.Environment, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, name, slug, created_at FROM environments WHERE project_id = $1 ORDER BY name`,
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
		`DELETE FROM environments WHERE project_id = $1 AND slug = $2`, projectID, slug,
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
