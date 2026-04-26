package api

import (
	"context"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/abagile/tokyo3-vault/internal/testutil/mockstore"
)

// Ensure mockStore implements store.Store at compile time.
var _ store.Store = (*mockStore)(nil)

// mockStore implements store.Store. Embed mockstore.Stub for all no-op defaults;
// override specific methods via function fields for test-controlled responses.
// Only the overridable fields used by api tests are listed — add more as needed.
type mockStore struct {
	mockstore.Stub

	createUser                   func(ctx context.Context, email, hash, role string) (*model.User, error)
	getUserByEmail               func(ctx context.Context, email string) (*model.User, error)
	getUserByID                  func(ctx context.Context, id string) (*model.User, error)
	listUsers                    func(ctx context.Context) ([]*model.User, error)
	hasAdminUser                 func(ctx context.Context) (bool, error)
	updateUserPassword           func(ctx context.Context, userID, hash string) error
	deleteAllTokensForUser       func(ctx context.Context, userID string) error
	createToken                  func(ctx context.Context, t *model.Token) error
	getTokenByHash               func(ctx context.Context, hash string) (*model.Token, error)
	listTokens                   func(ctx context.Context, userID string) ([]*model.Token, error)
	deleteToken                  func(ctx context.Context, id, userID string) error
	createProject                func(ctx context.Context, name, slug string) (*model.Project, error)
	getProject                   func(ctx context.Context, slug string) (*model.Project, error)
	listProjects                 func(ctx context.Context) ([]*model.Project, error)
	listProjectsByMember         func(ctx context.Context, userID string) ([]*model.Project, error)
	deleteProject                func(ctx context.Context, slug string) error
	addProjectMember             func(ctx context.Context, projectID, userID, role string, envID *string) error
	getProjectMember             func(ctx context.Context, projectID, userID string) (*model.ProjectMember, error)
	getProjectMemberForEnv       func(ctx context.Context, projectID, envID, userID string) (*model.ProjectMember, error)
	listProjectMembers           func(ctx context.Context, projectID string) ([]*model.ProjectMember, error)
	listProjectMembersWithAccess func(ctx context.Context, projectID, envID string) ([]*model.ProjectMember, error)
	updateProjectMember          func(ctx context.Context, projectID, userID, role string, envID *string) error
	removeProjectMember          func(ctx context.Context, projectID, userID string, envID *string) error
	createEnvironment            func(ctx context.Context, projectID, name, slug string) (*model.Environment, error)
	getEnvironment               func(ctx context.Context, projectID, slug string) (*model.Environment, error)
	listEnvironments             func(ctx context.Context, projectID string) ([]*model.Environment, error)
	deleteEnvironment            func(ctx context.Context, projectID, slug string) error
	setSecret                    func(ctx context.Context, projectID, envID, key string, comment *string, encVal, encDEK []byte, createdBy *string) (*model.SecretVersion, error)
	getSecret                    func(ctx context.Context, projectID, envID, key string) (*model.Secret, *model.SecretVersion, error)
	listSecrets                  func(ctx context.Context, projectID, envID string) ([]*model.Secret, []*model.SecretVersion, error)
	deleteSecret                 func(ctx context.Context, projectID, envID, key string) error
	listSecretVersions           func(ctx context.Context, secretID string) ([]*model.SecretVersion, error)
	getSecretVersion             func(ctx context.Context, secretID, versionID string) (*model.SecretVersion, error)
	rollbackSecret               func(ctx context.Context, secretID, versionID string) error
	pruneSecretVersions          func(ctx context.Context, secretID, currentVersionID string, maxCount int, cutoff time.Time) error

	// Cert principals
	createCertPrincipal          func(ctx context.Context, p *model.CertPrincipal) error
	listCertPrincipals           func(ctx context.Context, userID string) ([]*model.CertPrincipal, error)
	deleteCertPrincipal          func(ctx context.Context, id, userID string) error
	listTokensWithAccess         func(ctx context.Context, projectID, envID string) ([]*model.Token, error)
	listCertPrincipalsWithAccess func(ctx context.Context, projectID, envID string) ([]*model.CertPrincipal, error)

	// Dynamic backends
	setDynamicBackend     func(ctx context.Context, projectID, envID, slug, backendType string, encConfig, encConfigDEK []byte, defaultTTL, maxTTL int) (*model.DynamicBackend, error)
	getDynamicBackend     func(ctx context.Context, projectID, envID, slug string) (*model.DynamicBackend, error)
	getDynamicBackendByID func(ctx context.Context, id string) (*model.DynamicBackend, error)
	deleteDynamicBackend  func(ctx context.Context, projectID, envID, slug string) error

	// Dynamic roles
	setDynamicRole    func(ctx context.Context, backendID, name, creationTmpl, revocationTmpl string, ttl *int) (*model.DynamicRole, error)
	getDynamicRole    func(ctx context.Context, backendID, name string) (*model.DynamicRole, error)
	listDynamicRoles  func(ctx context.Context, backendID string) ([]*model.DynamicRole, error)
	deleteDynamicRole func(ctx context.Context, backendID, name string) error

	// Dynamic leases
	listDynamicLeases  func(ctx context.Context, projectID, envID string) ([]*model.DynamicLease, error)
	revokeDynamicLease func(ctx context.Context, id string) error
	getDynamicLease    func(ctx context.Context, id string) (*model.DynamicLease, error)

	// SCIM tokens
	getSCIMTokenByHash func(ctx context.Context, hash string) (*model.SCIMToken, error)
	createSCIMToken    func(ctx context.Context, t *model.SCIMToken) error
	listSCIMTokens     func(ctx context.Context) ([]*model.SCIMToken, error)
	deleteSCIMToken    func(ctx context.Context, id string) error

	// SCIM group roles
	listSCIMGroupRoles        func(ctx context.Context) ([]*model.SCIMGroupRole, error)
	listSCIMGroupRolesByGroup func(ctx context.Context, groupID string) ([]*model.SCIMGroupRole, error)
	getSCIMGroupRole          func(ctx context.Context, id string) (*model.SCIMGroupRole, error)
	setSCIMGroupRole          func(ctx context.Context, groupID, displayName string, projectID, envID *string, role string) (*model.SCIMGroupRole, error)
	deleteSCIMGroupRole       func(ctx context.Context, id string) error
}

func (m *mockStore) CreateUser(ctx context.Context, email, hash, role string) (*model.User, error) {
	if m.createUser != nil {
		return m.createUser(ctx, email, hash, role)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	if m.getUserByEmail != nil {
		return m.getUserByEmail(ctx, email)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	if m.getUserByID != nil {
		return m.getUserByID(ctx, id)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) ListUsers(ctx context.Context) ([]*model.User, error) {
	if m.listUsers != nil {
		return m.listUsers(ctx)
	}
	return nil, nil
}
func (m *mockStore) HasAdminUser(ctx context.Context) (bool, error) {
	if m.hasAdminUser != nil {
		return m.hasAdminUser(ctx)
	}
	return false, nil
}
func (m *mockStore) UpdateUserPassword(ctx context.Context, userID, hash string) error {
	if m.updateUserPassword != nil {
		return m.updateUserPassword(ctx, userID, hash)
	}
	return nil
}
func (m *mockStore) DeleteAllTokensForUser(ctx context.Context, userID string) error {
	if m.deleteAllTokensForUser != nil {
		return m.deleteAllTokensForUser(ctx, userID)
	}
	return nil
}
func (m *mockStore) CreateToken(ctx context.Context, t *model.Token) error {
	if m.createToken != nil {
		return m.createToken(ctx, t)
	}
	return nil
}
func (m *mockStore) GetTokenByHash(ctx context.Context, hash string) (*model.Token, error) {
	if m.getTokenByHash != nil {
		return m.getTokenByHash(ctx, hash)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) ListTokens(ctx context.Context, userID string) ([]*model.Token, error) {
	if m.listTokens != nil {
		return m.listTokens(ctx, userID)
	}
	return nil, nil
}
func (m *mockStore) DeleteToken(ctx context.Context, id, userID string) error {
	if m.deleteToken != nil {
		return m.deleteToken(ctx, id, userID)
	}
	return nil
}
func (m *mockStore) CreateProject(ctx context.Context, name, slug string) (*model.Project, error) {
	if m.createProject != nil {
		return m.createProject(ctx, name, slug)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) GetProject(ctx context.Context, slug string) (*model.Project, error) {
	if m.getProject != nil {
		return m.getProject(ctx, slug)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) ListProjects(ctx context.Context) ([]*model.Project, error) {
	if m.listProjects != nil {
		return m.listProjects(ctx)
	}
	return nil, nil
}
func (m *mockStore) ListProjectsByMember(ctx context.Context, userID string) ([]*model.Project, error) {
	if m.listProjectsByMember != nil {
		return m.listProjectsByMember(ctx, userID)
	}
	return nil, nil
}
func (m *mockStore) DeleteProject(ctx context.Context, slug string) error {
	if m.deleteProject != nil {
		return m.deleteProject(ctx, slug)
	}
	return nil
}
func (m *mockStore) AddProjectMember(ctx context.Context, projectID, userID, role string, envID *string) error {
	if m.addProjectMember != nil {
		return m.addProjectMember(ctx, projectID, userID, role, envID)
	}
	return nil
}
func (m *mockStore) GetProjectMember(ctx context.Context, projectID, userID string) (*model.ProjectMember, error) {
	if m.getProjectMember != nil {
		return m.getProjectMember(ctx, projectID, userID)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) GetProjectMemberForEnv(ctx context.Context, projectID, envID, userID string) (*model.ProjectMember, error) {
	if m.getProjectMemberForEnv != nil {
		return m.getProjectMemberForEnv(ctx, projectID, envID, userID)
	}
	// Fall back to project-level lookup so existing tests that set getProjectMember continue to work.
	return m.GetProjectMember(ctx, projectID, userID)
}
func (m *mockStore) ListProjectMembers(ctx context.Context, projectID string) ([]*model.ProjectMember, error) {
	if m.listProjectMembers != nil {
		return m.listProjectMembers(ctx, projectID)
	}
	return nil, nil
}
func (m *mockStore) ListProjectMembersWithAccess(ctx context.Context, projectID, envID string) ([]*model.ProjectMember, error) {
	if m.listProjectMembersWithAccess != nil {
		return m.listProjectMembersWithAccess(ctx, projectID, envID)
	}
	return nil, nil
}
func (m *mockStore) UpdateProjectMember(ctx context.Context, projectID, userID, role string, envID *string) error {
	if m.updateProjectMember != nil {
		return m.updateProjectMember(ctx, projectID, userID, role, envID)
	}
	return nil
}
func (m *mockStore) RemoveProjectMember(ctx context.Context, projectID, userID string, envID *string) error {
	if m.removeProjectMember != nil {
		return m.removeProjectMember(ctx, projectID, userID, envID)
	}
	return nil
}
func (m *mockStore) CreateEnvironment(ctx context.Context, projectID, name, slug string) (*model.Environment, error) {
	if m.createEnvironment != nil {
		return m.createEnvironment(ctx, projectID, name, slug)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) GetEnvironment(ctx context.Context, projectID, slug string) (*model.Environment, error) {
	if m.getEnvironment != nil {
		return m.getEnvironment(ctx, projectID, slug)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) ListEnvironments(ctx context.Context, projectID string) ([]*model.Environment, error) {
	if m.listEnvironments != nil {
		return m.listEnvironments(ctx, projectID)
	}
	return nil, nil
}
func (m *mockStore) DeleteEnvironment(ctx context.Context, projectID, slug string) error {
	if m.deleteEnvironment != nil {
		return m.deleteEnvironment(ctx, projectID, slug)
	}
	return nil
}
func (m *mockStore) SetSecret(ctx context.Context, projectID, envID, key string, comment *string, encVal, encDEK []byte, createdBy *string) (*model.SecretVersion, error) {
	if m.setSecret != nil {
		return m.setSecret(ctx, projectID, envID, key, comment, encVal, encDEK, createdBy)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) GetSecret(ctx context.Context, projectID, envID, key string) (*model.Secret, *model.SecretVersion, error) {
	if m.getSecret != nil {
		return m.getSecret(ctx, projectID, envID, key)
	}
	return nil, nil, store.ErrNotFound
}
func (m *mockStore) ListSecrets(ctx context.Context, projectID, envID string) ([]*model.Secret, []*model.SecretVersion, error) {
	if m.listSecrets != nil {
		return m.listSecrets(ctx, projectID, envID)
	}
	return nil, nil, nil
}
func (m *mockStore) DeleteSecret(ctx context.Context, projectID, envID, key string) error {
	if m.deleteSecret != nil {
		return m.deleteSecret(ctx, projectID, envID, key)
	}
	return store.ErrNotFound
}
func (m *mockStore) ListSecretVersions(ctx context.Context, secretID string) ([]*model.SecretVersion, error) {
	if m.listSecretVersions != nil {
		return m.listSecretVersions(ctx, secretID)
	}
	return nil, nil
}
func (m *mockStore) GetSecretVersion(ctx context.Context, secretID, versionID string) (*model.SecretVersion, error) {
	if m.getSecretVersion != nil {
		return m.getSecretVersion(ctx, secretID, versionID)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) RollbackSecret(ctx context.Context, secretID, versionID string) error {
	if m.rollbackSecret != nil {
		return m.rollbackSecret(ctx, secretID, versionID)
	}
	return nil
}
func (m *mockStore) PruneSecretVersions(ctx context.Context, secretID, currentVersionID string, maxCount int, cutoff time.Time) error {
	if m.pruneSecretVersions != nil {
		return m.pruneSecretVersions(ctx, secretID, currentVersionID, maxCount, cutoff)
	}
	return nil
}

// Cert principals

func (m *mockStore) CreateCertPrincipal(ctx context.Context, p *model.CertPrincipal) error {
	if m.createCertPrincipal != nil {
		return m.createCertPrincipal(ctx, p)
	}
	return nil
}
func (m *mockStore) ListCertPrincipals(ctx context.Context, userID string) ([]*model.CertPrincipal, error) {
	if m.listCertPrincipals != nil {
		return m.listCertPrincipals(ctx, userID)
	}
	return nil, nil
}
func (m *mockStore) DeleteCertPrincipal(ctx context.Context, id, userID string) error {
	if m.deleteCertPrincipal != nil {
		return m.deleteCertPrincipal(ctx, id, userID)
	}
	return nil
}
func (m *mockStore) ListTokensWithAccess(ctx context.Context, projectID, envID string) ([]*model.Token, error) {
	if m.listTokensWithAccess != nil {
		return m.listTokensWithAccess(ctx, projectID, envID)
	}
	return nil, nil
}
func (m *mockStore) ListCertPrincipalsWithAccess(ctx context.Context, projectID, envID string) ([]*model.CertPrincipal, error) {
	if m.listCertPrincipalsWithAccess != nil {
		return m.listCertPrincipalsWithAccess(ctx, projectID, envID)
	}
	return nil, nil
}

// Dynamic backends

func (m *mockStore) SetDynamicBackend(ctx context.Context, projectID, envID, slug, backendType string, encConfig, encConfigDEK []byte, defaultTTL, maxTTL int) (*model.DynamicBackend, error) {
	if m.setDynamicBackend != nil {
		return m.setDynamicBackend(ctx, projectID, envID, slug, backendType, encConfig, encConfigDEK, defaultTTL, maxTTL)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) GetDynamicBackend(ctx context.Context, projectID, envID, slug string) (*model.DynamicBackend, error) {
	if m.getDynamicBackend != nil {
		return m.getDynamicBackend(ctx, projectID, envID, slug)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) GetDynamicBackendByID(ctx context.Context, id string) (*model.DynamicBackend, error) {
	if m.getDynamicBackendByID != nil {
		return m.getDynamicBackendByID(ctx, id)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) DeleteDynamicBackend(ctx context.Context, projectID, envID, slug string) error {
	if m.deleteDynamicBackend != nil {
		return m.deleteDynamicBackend(ctx, projectID, envID, slug)
	}
	return nil
}

// Dynamic roles

func (m *mockStore) SetDynamicRole(ctx context.Context, backendID, name, creationTmpl, revocationTmpl string, ttl *int) (*model.DynamicRole, error) {
	if m.setDynamicRole != nil {
		return m.setDynamicRole(ctx, backendID, name, creationTmpl, revocationTmpl, ttl)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) GetDynamicRole(ctx context.Context, backendID, name string) (*model.DynamicRole, error) {
	if m.getDynamicRole != nil {
		return m.getDynamicRole(ctx, backendID, name)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) ListDynamicRoles(ctx context.Context, backendID string) ([]*model.DynamicRole, error) {
	if m.listDynamicRoles != nil {
		return m.listDynamicRoles(ctx, backendID)
	}
	return []*model.DynamicRole{}, nil
}
func (m *mockStore) DeleteDynamicRole(ctx context.Context, backendID, name string) error {
	if m.deleteDynamicRole != nil {
		return m.deleteDynamicRole(ctx, backendID, name)
	}
	return nil
}

// Dynamic leases

func (m *mockStore) ListDynamicLeases(ctx context.Context, projectID, envID string) ([]*model.DynamicLease, error) {
	if m.listDynamicLeases != nil {
		return m.listDynamicLeases(ctx, projectID, envID)
	}
	return nil, nil
}
func (m *mockStore) RevokeDynamicLease(ctx context.Context, id string) error {
	if m.revokeDynamicLease != nil {
		return m.revokeDynamicLease(ctx, id)
	}
	return nil
}
func (m *mockStore) GetDynamicLease(ctx context.Context, id string) (*model.DynamicLease, error) {
	if m.getDynamicLease != nil {
		return m.getDynamicLease(ctx, id)
	}
	return nil, store.ErrNotFound
}

// SCIM tokens

func (m *mockStore) GetSCIMTokenByHash(ctx context.Context, hash string) (*model.SCIMToken, error) {
	if m.getSCIMTokenByHash != nil {
		return m.getSCIMTokenByHash(ctx, hash)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) CreateSCIMToken(ctx context.Context, t *model.SCIMToken) error {
	if m.createSCIMToken != nil {
		return m.createSCIMToken(ctx, t)
	}
	return nil
}
func (m *mockStore) ListSCIMTokens(ctx context.Context) ([]*model.SCIMToken, error) {
	if m.listSCIMTokens != nil {
		return m.listSCIMTokens(ctx)
	}
	return nil, nil
}
func (m *mockStore) DeleteSCIMToken(ctx context.Context, id string) error {
	if m.deleteSCIMToken != nil {
		return m.deleteSCIMToken(ctx, id)
	}
	return nil
}

// SCIM group roles

func (m *mockStore) ListSCIMGroupRoles(ctx context.Context) ([]*model.SCIMGroupRole, error) {
	if m.listSCIMGroupRoles != nil {
		return m.listSCIMGroupRoles(ctx)
	}
	return nil, nil
}
func (m *mockStore) ListSCIMGroupRolesByGroup(ctx context.Context, groupID string) ([]*model.SCIMGroupRole, error) {
	if m.listSCIMGroupRolesByGroup != nil {
		return m.listSCIMGroupRolesByGroup(ctx, groupID)
	}
	return nil, nil
}
func (m *mockStore) GetSCIMGroupRole(ctx context.Context, id string) (*model.SCIMGroupRole, error) {
	if m.getSCIMGroupRole != nil {
		return m.getSCIMGroupRole(ctx, id)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) SetSCIMGroupRole(ctx context.Context, groupID, displayName string, projectID, envID *string, role string) (*model.SCIMGroupRole, error) {
	if m.setSCIMGroupRole != nil {
		return m.setSCIMGroupRole(ctx, groupID, displayName, projectID, envID, role)
	}
	return nil, store.ErrNotFound
}
func (m *mockStore) DeleteSCIMGroupRole(ctx context.Context, id string) error {
	if m.deleteSCIMGroupRole != nil {
		return m.deleteSCIMGroupRole(ctx, id)
	}
	return nil
}

// All other store.Store methods (OIDC, project keys, SCIM tokens)
// are satisfied by the embedded mockstore.Stub with safe no-op defaults.
