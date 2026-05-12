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
	// GetUserBySCIMExternalID looks up a user by their IdP-side externalId,
	// used by SCIM list filters and for outbound-SCIM cache reconciliation.
	GetUserBySCIMExternalID(ctx context.Context, externalID string) (*model.User, error)
	// SetUserSCIMExternalID persists an IdP-side externalId for the user.
	// Pass empty string to clear. SCIM create/replace handlers call this so the
	// externalId is queryable via filter and stable across IdP re-syncs.
	SetUserSCIMExternalID(ctx context.Context, userID, externalID string) error
	ListUsers(ctx context.Context) ([]*model.User, error)
	HasAdminUser(ctx context.Context) (bool, error)
	UpdateUserPassword(ctx context.Context, userID, passwordHash string) error
	// SetUserOIDCIdentity links an OIDC issuer+subject to an existing user.
	// Returns ErrConflict if the identity is already linked to a different user.
	SetUserOIDCIdentity(ctx context.Context, userID, issuer, subject string) error
	// SetUserActive sets the active flag. Callers should delete all tokens when deactivating.
	SetUserActive(ctx context.Context, userID string, active bool) error
	// SetUserRole updates the server-level role (UserRoleAdmin | UserRoleMember).
	// Callers must enforce policy (e.g. last-admin guard); this is a raw setter.
	SetUserRole(ctx context.Context, userID, role string) error
	// CountAdminUsers returns the number of users with role = UserRoleAdmin.
	// Used by the role-change handler's last-admin guard.
	CountAdminUsers(ctx context.Context) (int, error)
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
	// DeleteTokensByOIDCSession removes every token row whose oidc_session_id
	// matches the IdP-supplied session identifier. Used by the back-channel
	// logout endpoint to target exactly the tokens chained to one OP session
	// (multiple vault tokens can share an OIDC sid because each silent-SSO
	// re-issuance mints a fresh vault token under the same OP session).
	// Returns the number of rows deleted.
	DeleteTokensByOIDCSession(ctx context.Context, oidcSessionID string) (int64, error)
	// ExtendTokenExpiry slides the expiry of a session token forward.
	// Only rows with is_session=true are updated; machine tokens are unaffected.
	ExtendTokenExpiry(ctx context.Context, tokenHash string, newExpiry time.Time) error
	// DeleteExpiredTokens removes all tokens whose expires_at is in the past.
	// Returns the number of rows deleted.
	DeleteExpiredTokens(ctx context.Context) (int64, error)
}

// ProjectStore covers projects, memberships, environments, and envelope key management.
type ProjectStore interface {
	CreateProject(ctx context.Context, name, slug string) (*model.Project, error)
	GetProject(ctx context.Context, slug string) (*model.Project, error)
	GetProjectByID(ctx context.Context, id string) (*model.Project, error)
	ListProjects(ctx context.Context) ([]*model.Project, error)
	ListProjectsByMember(ctx context.Context, userID string) ([]*model.Project, error)
	DeleteProject(ctx context.Context, slug string) error

	// AddProjectMember upserts the admin-managed (source_scim_external_id IS NULL)
	// row at the project level (envID nil) or env-specific level (envID non-nil).
	// Use UpsertSCIMProjectMember for SCIM-sourced rows.
	AddProjectMember(ctx context.Context, projectID, userID, role string, envID *string) error
	// GetProjectMember returns the highest-role project-level (env_id IS NULL)
	// membership row across all provenance sources (admin + each SCIM group),
	// max-merging the role rank. Used for project-wide checks (requireOwner,
	// requireWrite with envID="", and unscoped authorize). Returns ErrNotFound
	// if no row exists.
	GetProjectMember(ctx context.Context, projectID, userID string) (*model.ProjectMember, error)
	// GetProjectMemberForEnv returns the most-specific, highest-role membership
	// for a user in a given project+env: env-specific row preferred over
	// project-level, then max-merged across provenance sources within the
	// chosen layer. Returns ErrNotFound if neither layer has a row.
	GetProjectMemberForEnv(ctx context.Context, projectID, envID, userID string) (*model.ProjectMember, error)
	// ListProjectMembers returns every membership row for a project — both
	// admin-added (source NULL) and SCIM-sourced rows; multiple rows per user
	// are possible. Callers that want effective roles must aggregate.
	ListProjectMembers(ctx context.Context, projectID string) ([]*model.ProjectMember, error)
	// ListProjectMembersWithAccess returns membership rows that grant access to
	// the given project+env (project-level rows + env-specific rows for envID),
	// across all provenance sources. Multiple rows per user are possible.
	ListProjectMembersWithAccess(ctx context.Context, projectID, envID string) ([]*model.ProjectMember, error)
	// UpdateProjectMember updates only the admin row (source_scim_external_id IS NULL).
	UpdateProjectMember(ctx context.Context, projectID, userID, role string, envID *string) error
	// RemoveProjectMember removes only the admin row (source_scim_external_id IS NULL).
	RemoveProjectMember(ctx context.Context, projectID, userID string, envID *string) error
	// UpsertSCIMProjectMember inserts or updates a SCIM-sourced row keyed by
	// (project, user, env, scimExternalID). One row per source group; coexists
	// with admin rows and with rows from other groups.
	UpsertSCIMProjectMember(ctx context.Context, scimExternalID, projectID, userID, role string, envID *string) error
	// RemoveSCIMProjectMembersExcept deletes every row produced by the given
	// scimExternalID that targets (projectID, envID) except those for users
	// in keepUserIDs. Used by diff-based PUT sync to drop leavers.
	RemoveSCIMProjectMembersExcept(ctx context.Context, scimExternalID, projectID string, envID *string, keepUserIDs []string) error

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
	// RollbackSecret creates a NEW version that copies the encrypted value of
	// the source versionID, then sets current_version_id to that new version.
	// Forward-only: the current_version_id pointer never moves backward, so
	// version history stays monotonic. createdBy is the operator who triggered
	// the rollback (not the original author of versionID). Returns the new
	// version, or ErrNotFound if versionID does not exist or doesn't belong to
	// secretID.
	RollbackSecret(ctx context.Context, secretID, versionID string, createdBy *string) (*model.SecretVersion, error)
	// PruneSecretVersions deletes old versions of a secret that fall outside the
	// retention window. A version is pruned only when BOTH conditions are met:
	// its rank by version DESC exceeds maxCount AND its created_at is before cutoff.
	// currentVersionID is always preserved regardless of either condition.
	PruneSecretVersions(ctx context.Context, secretID, currentVersionID string, maxCount int, cutoff time.Time) error
	// ListSecretsForPrune returns [secretID, currentVersionID] for every secret.
	// currentVersionID is "" when the secret has no current version (skip pruning).
	// Used exclusively by the background version pruner.
	ListSecretsForPrune(ctx context.Context) ([][2]string, error)
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

	SetSCIMGroupRole(ctx context.Context, scimExternalID, displayName string, projectID, envID *string, role string) (*model.SCIMGroupRole, error)
	ListSCIMGroupRoles(ctx context.Context) ([]*model.SCIMGroupRole, error)
	ListSCIMGroupRolesByExternalID(ctx context.Context, scimExternalID string) ([]*model.SCIMGroupRole, error)
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
