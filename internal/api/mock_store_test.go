package api

import (
	"context"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/abagile/tokyo3-vault/internal/testutil/mockstore"
)

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
	rollbackSecret               func(ctx context.Context, secretID, versionID string) error
	createAuditLog               func(ctx context.Context, entry *model.AuditLog) error
	listAuditLogs                func(ctx context.Context, filter store.AuditFilter) ([]*model.AuditLog, error)
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
func (m *mockStore) RollbackSecret(ctx context.Context, secretID, versionID string) error {
	if m.rollbackSecret != nil {
		return m.rollbackSecret(ctx, secretID, versionID)
	}
	return nil
}
func (m *mockStore) CreateAuditLog(ctx context.Context, entry *model.AuditLog) error {
	if m.createAuditLog != nil {
		return m.createAuditLog(ctx, entry)
	}
	return nil
}
func (m *mockStore) ListAuditLogs(ctx context.Context, filter store.AuditFilter) ([]*model.AuditLog, error) {
	if m.listAuditLogs != nil {
		return m.listAuditLogs(ctx, filter)
	}
	return nil, nil
}

// All other store.Store methods (dynamic, SCIM, OIDC, certs, project keys)
// are satisfied by the embedded mockstore.Stub with safe no-op defaults.
