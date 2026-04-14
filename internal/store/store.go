package store

import (
	"context"
	"errors"

	"github.com/abagile/tokyo3-vault/internal/model"
)

// ErrNotFound is returned when a requested resource does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a uniqueness constraint is violated.
var ErrConflict = errors.New("conflict")

// Store defines all persistence operations for Vault.
// The interface is intentionally narrow — call sites only depend on this,
// making it straightforward to swap SQLite for Postgres later.
type Store interface {
	// Users
	CreateUser(ctx context.Context, email, passwordHash, role string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	ListUsers(ctx context.Context) ([]*model.User, error)
	HasAdminUser(ctx context.Context) (bool, error)
	UpdateUserPassword(ctx context.Context, userID, passwordHash string) error

	// Tokens (user session tokens and machine tokens)
	CreateToken(ctx context.Context, t *model.Token) error
	GetTokenByHash(ctx context.Context, hash string) (*model.Token, error)
	ListTokens(ctx context.Context, userID string) ([]*model.Token, error)
	DeleteToken(ctx context.Context, id, userID string) error

	// Projects
	CreateProject(ctx context.Context, name, slug string) (*model.Project, error)
	GetProject(ctx context.Context, slug string) (*model.Project, error)
	ListProjects(ctx context.Context) ([]*model.Project, error)
	ListProjectsByMember(ctx context.Context, userID string) ([]*model.Project, error)
	DeleteProject(ctx context.Context, slug string) error

	// Project members
	AddProjectMember(ctx context.Context, projectID, userID, role string) error
	GetProjectMember(ctx context.Context, projectID, userID string) (*model.ProjectMember, error)
	ListProjectMembers(ctx context.Context, projectID string) ([]*model.ProjectMember, error)
	UpdateProjectMember(ctx context.Context, projectID, userID, role string) error
	RemoveProjectMember(ctx context.Context, projectID, userID string) error

	// Environments
	CreateEnvironment(ctx context.Context, projectID, name, slug string) (*model.Environment, error)
	GetEnvironment(ctx context.Context, projectID, slug string) (*model.Environment, error)
	ListEnvironments(ctx context.Context, projectID string) ([]*model.Environment, error)
	DeleteEnvironment(ctx context.Context, projectID, slug string) error

	// Secrets
	// SetSecret creates or updates a secret, always inserting a new version row.
	// comment is optional: nil leaves an existing comment unchanged; a non-nil pointer
	// (including pointer-to-empty-string) overwrites the stored comment.
	SetSecret(ctx context.Context, projectID, envID, key string, comment *string, encryptedValue, encryptedDEK []byte, createdBy *string) (*model.SecretVersion, error)
	// GetSecret returns the secret metadata and its current (active) version.
	GetSecret(ctx context.Context, projectID, envID, key string) (*model.Secret, *model.SecretVersion, error)
	// ListSecrets returns all secrets and their current versions for a project+env.
	ListSecrets(ctx context.Context, projectID, envID string) ([]*model.Secret, []*model.SecretVersion, error)
	DeleteSecret(ctx context.Context, projectID, envID, key string) error
	ListSecretVersions(ctx context.Context, secretID string) ([]*model.SecretVersion, error)
	// RollbackSecret points current_version_id at a previous version.
	RollbackSecret(ctx context.Context, secretID, versionID string) error

	// Audit
	CreateAuditLog(ctx context.Context, entry *model.AuditLog) error
	ListAuditLogs(ctx context.Context, filter AuditFilter) ([]*model.AuditLog, error)
}

// AuditFilter controls which audit log entries are returned.
type AuditFilter struct {
	ProjectID string // empty = all projects
	Action    string // empty = all actions
	Limit     int    // 0 = default (50)
}
