package store

import (
	"context"
	"errors"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
)

// ErrNotFound is returned when a requested resource does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a uniqueness constraint is violated.
var ErrConflict = errors.New("conflict")

// Store is the full persistence interface used by all API handlers and
// background goroutines. It embeds seven focused sub-interfaces so that
// individual packages or tests can depend on only the methods they need.
type Store interface {
	UserStore
	TokenStore
	ProjectStore
	SecretStore
	DynamicStore
	SCIMStore
	CertStore
}

// UserStore covers user account management and OIDC identity linking.
type UserStore interface {
	CreateUser(ctx context.Context, email, passwordHash, role string) (*model.User, error)
	// CreateOIDCUser creates a user via OIDC JIT provisioning (no local password).
	// Returns ErrConflict if either the email or the oidcIssuer+oidcSubject pair already exists.
	CreateOIDCUser(ctx context.Context, email, oidcIssuer, oidcSubject, role string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	// GetUserByOIDCSubject looks up a user by their OIDC issuer+subject pair.
	GetUserByOIDCSubject(ctx context.Context, issuer, subject string) (*model.User, error)
	ListUsers(ctx context.Context) ([]*model.User, error)
	HasAdminUser(ctx context.Context) (bool, error)
	UpdateUserPassword(ctx context.Context, userID, passwordHash string) error
	// SetUserOIDCIdentity links an OIDC issuer+subject to an existing user.
	// Returns ErrConflict if the identity is already linked to a different user.
	SetUserOIDCIdentity(ctx context.Context, userID, issuer, subject string) error
	// SetUserActive sets the active flag. Callers should delete all tokens when deactivating.
	SetUserActive(ctx context.Context, userID string, active bool) error
}

// TokenStore covers bearer token issuance, lookup, and deletion.
type TokenStore interface {
	CreateToken(ctx context.Context, t *model.Token) error
	GetTokenByHash(ctx context.Context, hash string) (*model.Token, error)
	ListTokens(ctx context.Context, userID string) ([]*model.Token, error)
	// ListTokensWithAccess returns all non-expired tokens that can reach the given
	// project+env: explicitly scoped to it (project-only or project+env), and
	// unscoped tokens owned by project members.
	ListTokensWithAccess(ctx context.Context, projectID, envID string) ([]*model.Token, error)
	DeleteToken(ctx context.Context, id, userID string) error
	// DeleteAllTokensForUser removes every token owned by the given user (used during SCIM deactivation).
	DeleteAllTokensForUser(ctx context.Context, userID string) error
}

// ProjectStore covers projects, memberships, environments, and envelope key management.
type ProjectStore interface {
	CreateProject(ctx context.Context, name, slug string) (*model.Project, error)
	GetProject(ctx context.Context, slug string) (*model.Project, error)
	GetProjectByID(ctx context.Context, id string) (*model.Project, error)
	ListProjects(ctx context.Context) ([]*model.Project, error)
	ListProjectsByMember(ctx context.Context, userID string) ([]*model.Project, error)
	DeleteProject(ctx context.Context, slug string) error

	// AddProjectMember upserts a project-level (envID nil) or env-specific (envID non-nil) membership.
	AddProjectMember(ctx context.Context, projectID, userID, role string, envID *string) error
	// GetProjectMember returns the project-level (env_id IS NULL) membership row only.
	// Used for owner checks and unscoped auth. Returns ErrNotFound if absent.
	GetProjectMember(ctx context.Context, projectID, userID string) (*model.ProjectMember, error)
	// GetProjectMemberForEnv returns the most-specific membership for a user in a given
	// project+env: env-specific row (env_id = envID) preferred over project-level (env_id IS NULL).
	// Returns ErrNotFound if neither exists.
	GetProjectMemberForEnv(ctx context.Context, projectID, envID, userID string) (*model.ProjectMember, error)
	// ListProjectMembers returns all membership rows for a project (project-level and env-level).
	ListProjectMembers(ctx context.Context, projectID string) ([]*model.ProjectMember, error)
	// ListProjectMembersWithAccess returns membership rows that grant access to the given
	// project+env: project-level rows (env_id IS NULL) and env-specific rows for this env.
	ListProjectMembersWithAccess(ctx context.Context, projectID, envID string) ([]*model.ProjectMember, error)
	UpdateProjectMember(ctx context.Context, projectID, userID, role string, envID *string) error
	RemoveProjectMember(ctx context.Context, projectID, userID string, envID *string) error

	CreateEnvironment(ctx context.Context, projectID, name, slug string) (*model.Environment, error)
	GetEnvironment(ctx context.Context, projectID, slug string) (*model.Environment, error)
	ListEnvironments(ctx context.Context, projectID string) ([]*model.Environment, error)
	DeleteEnvironment(ctx context.Context, projectID, slug string) error

	// SetProjectKey stores the KEK-wrapped PEK and its creation timestamp for a project.
	SetProjectKey(ctx context.Context, projectID string, encPEK []byte, rotatedAt time.Time) error
	// RewrapProjectDEKs re-wraps every secret_versions.encrypted_dek and every
	// dynamic_backends.encrypted_config_dek for the project in one transaction,
	// applying rewrap(oldEncDEK) → newEncDEK to each row.
	RewrapProjectDEKs(ctx context.Context, projectID string, rewrap func([]byte) ([]byte, error)) error
	// RotateProjectPEK atomically re-wraps all DEKs under newEncPEK and updates the
	// project's encrypted_pek and pek_rotated_at in the same transaction.
	RotateProjectPEK(ctx context.Context, projectID string, newEncPEK []byte, rotatedAt time.Time, rewrap func([]byte) ([]byte, error)) error
	// ListProjectsForPEKRotation returns projects with a non-nil PEK whose
	// pek_rotated_at is NULL or before threshold, ordered oldest-first.
	ListProjectsForPEKRotation(ctx context.Context, threshold time.Time) ([]*model.Project, error)
}

// SecretStore covers secret CRUD and version management.
type SecretStore interface {
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
	// GetSecretVersion returns a specific version belonging to secretID.
	// Returns ErrNotFound if the version does not exist or belongs to a different secret.
	GetSecretVersion(ctx context.Context, secretID, versionID string) (*model.SecretVersion, error)
	// RollbackSecret points current_version_id at a previous version.
	RollbackSecret(ctx context.Context, secretID, versionID string) error
}

// DynamicStore covers dynamic credential backends, roles, and leases.
type DynamicStore interface {
	SetDynamicBackend(ctx context.Context, projectID, envID, slug, backendType string, encConfig, encConfigDEK []byte, defaultTTL, maxTTL int) (*model.DynamicBackend, error)
	GetDynamicBackend(ctx context.Context, projectID, envID, slug string) (*model.DynamicBackend, error)
	GetDynamicBackendByID(ctx context.Context, id string) (*model.DynamicBackend, error)
	DeleteDynamicBackend(ctx context.Context, projectID, envID, slug string) error

	SetDynamicRole(ctx context.Context, backendID, name, creationTmpl, revocationTmpl string, ttl *int) (*model.DynamicRole, error)
	GetDynamicRole(ctx context.Context, backendID, name string) (*model.DynamicRole, error)
	ListDynamicRoles(ctx context.Context, backendID string) ([]*model.DynamicRole, error)
	DeleteDynamicRole(ctx context.Context, backendID, name string) error

	CreateDynamicLease(ctx context.Context, projectID, envID, backendID, roleID, roleName, username, revocationTmpl string, expiresAt time.Time, createdBy *string) (*model.DynamicLease, error)
	GetDynamicLease(ctx context.Context, id string) (*model.DynamicLease, error)
	ListDynamicLeases(ctx context.Context, projectID, envID string) ([]*model.DynamicLease, error)
	RevokeDynamicLease(ctx context.Context, id string) error
	ListExpiredDynamicLeases(ctx context.Context) ([]*model.DynamicLease, error)
}

// SCIMStore covers SCIM bearer tokens and group→role mappings.
type SCIMStore interface {
	CreateSCIMToken(ctx context.Context, t *model.SCIMToken) error
	GetSCIMTokenByHash(ctx context.Context, hash string) (*model.SCIMToken, error)
	ListSCIMTokens(ctx context.Context) ([]*model.SCIMToken, error)
	DeleteSCIMToken(ctx context.Context, id string) error

	SetSCIMGroupRole(ctx context.Context, groupID, displayName string, projectID, envID *string, role string) (*model.SCIMGroupRole, error)
	ListSCIMGroupRoles(ctx context.Context) ([]*model.SCIMGroupRole, error)
	ListSCIMGroupRolesByGroup(ctx context.Context, groupID string) ([]*model.SCIMGroupRole, error)
	GetSCIMGroupRole(ctx context.Context, id string) (*model.SCIMGroupRole, error)
	DeleteSCIMGroupRole(ctx context.Context, id string) error
}

// CertStore covers SPIFFE/mTLS certificate principals.
type CertStore interface {
	CreateCertPrincipal(ctx context.Context, p *model.CertPrincipal) error
	GetCertPrincipalBySPIFFEID(ctx context.Context, spiffeID string) (*model.CertPrincipal, error)
	// GetCertPrincipalByEmailSAN looks up a principal registered with an email SAN.
	GetCertPrincipalByEmailSAN(ctx context.Context, emailSAN string) (*model.CertPrincipal, error)
	ListCertPrincipals(ctx context.Context, userID string) ([]*model.CertPrincipal, error)
	// ListCertPrincipalsWithAccess returns all non-expired principals that can reach
	// the given project+env: explicitly scoped to it, and unscoped principals owned
	// by project members.
	ListCertPrincipalsWithAccess(ctx context.Context, projectID, envID string) ([]*model.CertPrincipal, error)
	DeleteCertPrincipal(ctx context.Context, id, userID string) error
}
