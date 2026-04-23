// Package mockstore provides a Stub that satisfies store.Store with safe no-op
// defaults. Embed it in test-local mocks so only the methods under test need to
// be defined. When store.Store gains a new method, only this file needs updating.
package mockstore

import (
	"context"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// Stub implements store.Store. Every method is a safe no-op:
//   - Get*/Find* methods return store.ErrNotFound
//   - List* methods return nil, nil (empty, no error)
//   - Create*/Set*/Update*/Delete*/Add*/Remove*/Revoke*/Rollback*/Rewrap* methods return nil
type Stub struct{}

// ── Users ─────────────────────────────────────────────────────────────────────

func (Stub) CreateUser(_ context.Context, _, _, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (Stub) CreateOIDCUser(_ context.Context, _, _, _, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetUserByEmail(_ context.Context, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetUserByID(_ context.Context, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetUserByOIDCSubject(_ context.Context, _, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListUsers(_ context.Context) ([]*model.User, error)          { return nil, nil }
func (Stub) HasAdminUser(_ context.Context) (bool, error)                { return false, nil }
func (Stub) UpdateUserPassword(_ context.Context, _, _ string) error     { return nil }
func (Stub) SetUserOIDCIdentity(_ context.Context, _, _, _ string) error { return nil }
func (Stub) SetUserActive(_ context.Context, _ string, _ bool) error     { return nil }
func (Stub) DeleteAllTokensForUser(_ context.Context, _ string) error    { return nil }

// ── Tokens ────────────────────────────────────────────────────────────────────

func (Stub) CreateToken(_ context.Context, _ *model.Token) error { return nil }
func (Stub) GetTokenByHash(_ context.Context, _ string) (*model.Token, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListTokens(_ context.Context, _ string) ([]*model.Token, error) { return nil, nil }
func (Stub) ListTokensWithAccess(_ context.Context, _, _ string) ([]*model.Token, error) {
	return nil, nil
}
func (Stub) DeleteToken(_ context.Context, _, _ string) error { return nil }

// ── Projects ──────────────────────────────────────────────────────────────────

func (Stub) CreateProject(_ context.Context, _, _ string) (*model.Project, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetProject(_ context.Context, _ string) (*model.Project, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetProjectByID(_ context.Context, _ string) (*model.Project, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListProjects(_ context.Context) ([]*model.Project, error) { return nil, nil }
func (Stub) ListProjectsByMember(_ context.Context, _ string) ([]*model.Project, error) {
	return nil, nil
}
func (Stub) DeleteProject(_ context.Context, _ string) error           { return nil }
func (Stub) SetProjectKey(_ context.Context, _ string, _ []byte) error { return nil }
func (Stub) RewrapProjectDEKs(_ context.Context, _ string, _ func([]byte) ([]byte, error)) error {
	return nil
}

// ── Project members ───────────────────────────────────────────────────────────

func (Stub) AddProjectMember(_ context.Context, _, _, _ string, _ *string) error { return nil }
func (Stub) GetProjectMember(_ context.Context, _, _ string) (*model.ProjectMember, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetProjectMemberForEnv(_ context.Context, _, _, _ string) (*model.ProjectMember, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListProjectMembers(_ context.Context, _ string) ([]*model.ProjectMember, error) {
	return nil, nil
}
func (Stub) ListProjectMembersWithAccess(_ context.Context, _, _ string) ([]*model.ProjectMember, error) {
	return nil, nil
}
func (Stub) UpdateProjectMember(_ context.Context, _, _, _ string, _ *string) error { return nil }
func (Stub) RemoveProjectMember(_ context.Context, _, _ string, _ *string) error    { return nil }

// ── Environments ──────────────────────────────────────────────────────────────

func (Stub) CreateEnvironment(_ context.Context, _, _, _ string) (*model.Environment, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetEnvironment(_ context.Context, _, _ string) (*model.Environment, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListEnvironments(_ context.Context, _ string) ([]*model.Environment, error) {
	return nil, nil
}
func (Stub) DeleteEnvironment(_ context.Context, _, _ string) error { return nil }

// ── Secrets ───────────────────────────────────────────────────────────────────

func (Stub) SetSecret(_ context.Context, _, _, _ string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetSecret(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
	return nil, nil, store.ErrNotFound
}
func (Stub) ListSecrets(_ context.Context, _, _ string) ([]*model.Secret, []*model.SecretVersion, error) {
	return nil, nil, nil
}
func (Stub) DeleteSecret(_ context.Context, _, _, _ string) error { return nil }
func (Stub) ListSecretVersions(_ context.Context, _ string) ([]*model.SecretVersion, error) {
	return nil, nil
}
func (Stub) RollbackSecret(_ context.Context, _, _ string) error { return nil }

// ── Audit ─────────────────────────────────────────────────────────────────────

func (Stub) CreateAuditLog(_ context.Context, _ *model.AuditLog) error { return nil }
func (Stub) ListAuditLogs(_ context.Context, _ store.AuditFilter) ([]*model.AuditLog, error) {
	return nil, nil
}

// ── Dynamic backends ──────────────────────────────────────────────────────────

func (Stub) SetDynamicBackend(_ context.Context, _, _, _, _ string, _, _ []byte, _, _ int) (*model.DynamicBackend, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetDynamicBackend(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetDynamicBackendByID(_ context.Context, _ string) (*model.DynamicBackend, error) {
	return nil, store.ErrNotFound
}
func (Stub) DeleteDynamicBackend(_ context.Context, _, _, _ string) error { return nil }

// ── Dynamic roles ─────────────────────────────────────────────────────────────

func (Stub) SetDynamicRole(_ context.Context, _, _, _, _ string, _ *int) (*model.DynamicRole, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetDynamicRole(_ context.Context, _, _ string) (*model.DynamicRole, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListDynamicRoles(_ context.Context, _ string) ([]*model.DynamicRole, error) {
	return nil, nil
}
func (Stub) DeleteDynamicRole(_ context.Context, _, _ string) error { return nil }

// ── Dynamic leases ────────────────────────────────────────────────────────────

func (Stub) CreateDynamicLease(_ context.Context, _, _, _, _, _, _, _ string, _ time.Time, _ *string) (*model.DynamicLease, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetDynamicLease(_ context.Context, _ string) (*model.DynamicLease, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListDynamicLeases(_ context.Context, _, _ string) ([]*model.DynamicLease, error) {
	return nil, nil
}
func (Stub) RevokeDynamicLease(_ context.Context, _ string) error { return nil }
func (Stub) ListExpiredDynamicLeases(_ context.Context) ([]*model.DynamicLease, error) {
	return nil, nil
}

// ── SCIM tokens ───────────────────────────────────────────────────────────────

func (Stub) CreateSCIMToken(_ context.Context, _ *model.SCIMToken) error { return nil }
func (Stub) GetSCIMTokenByHash(_ context.Context, _ string) (*model.SCIMToken, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListSCIMTokens(_ context.Context) ([]*model.SCIMToken, error) { return nil, nil }
func (Stub) DeleteSCIMToken(_ context.Context, _ string) error            { return nil }

// ── SCIM group roles ──────────────────────────────────────────────────────────

func (Stub) SetSCIMGroupRole(_ context.Context, _, _ string, _, _ *string, _ string) (*model.SCIMGroupRole, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListSCIMGroupRoles(_ context.Context) ([]*model.SCIMGroupRole, error) { return nil, nil }
func (Stub) ListSCIMGroupRolesByGroup(_ context.Context, _ string) ([]*model.SCIMGroupRole, error) {
	return nil, nil
}
func (Stub) GetSCIMGroupRole(_ context.Context, _ string) (*model.SCIMGroupRole, error) {
	return nil, store.ErrNotFound
}
func (Stub) DeleteSCIMGroupRole(_ context.Context, _ string) error { return nil }

// ── Cert principals ───────────────────────────────────────────────────────────

func (Stub) CreateCertPrincipal(_ context.Context, _ *model.CertPrincipal) error { return nil }
func (Stub) GetCertPrincipalBySPIFFEID(_ context.Context, _ string) (*model.CertPrincipal, error) {
	return nil, store.ErrNotFound
}
func (Stub) GetCertPrincipalByEmailSAN(_ context.Context, _ string) (*model.CertPrincipal, error) {
	return nil, store.ErrNotFound
}
func (Stub) ListCertPrincipals(_ context.Context, _ string) ([]*model.CertPrincipal, error) {
	return nil, nil
}
func (Stub) ListCertPrincipalsWithAccess(_ context.Context, _, _ string) ([]*model.CertPrincipal, error) {
	return nil, nil
}
func (Stub) DeleteCertPrincipal(_ context.Context, _, _ string) error { return nil }
