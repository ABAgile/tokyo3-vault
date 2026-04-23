package auth

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// ── minimal mock store ────────────────────────────────────────────────────────

type mockStore struct {
	tokens    map[string]*model.Token // hash → token
	createErr error
}

func newMockStore() *mockStore { return &mockStore{tokens: map[string]*model.Token{}} }

func (m *mockStore) CreateToken(_ context.Context, t *model.Token) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.tokens[t.TokenHash] = t
	return nil
}

func (m *mockStore) GetTokenByHash(_ context.Context, hash string) (*model.Token, error) {
	if t, ok := m.tokens[hash]; ok {
		return t, nil
	}
	return nil, store.ErrNotFound
}

// The store.Store interface has many more methods; satisfy them with no-ops.
func (m *mockStore) CreateUser(_ context.Context, _, _, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetUserByEmail(_ context.Context, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetUserByID(_ context.Context, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) ListUsers(_ context.Context) ([]*model.User, error)      { return nil, nil }
func (m *mockStore) HasAdminUser(_ context.Context) (bool, error)            { return false, nil }
func (m *mockStore) UpdateUserPassword(_ context.Context, _, _ string) error { return nil }
func (m *mockStore) ListTokens(_ context.Context, _ string) ([]*model.Token, error) {
	return nil, nil
}
func (m *mockStore) ListTokensWithAccess(_ context.Context, _, _ string) ([]*model.Token, error) {
	return nil, nil
}
func (m *mockStore) DeleteToken(_ context.Context, _, _ string) error { return nil }
func (m *mockStore) CreateProject(_ context.Context, _, _ string) (*model.Project, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetProject(_ context.Context, _ string) (*model.Project, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetProjectByID(_ context.Context, _ string) (*model.Project, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) ListProjects(_ context.Context) ([]*model.Project, error) { return nil, nil }
func (m *mockStore) ListProjectsByMember(_ context.Context, _ string) ([]*model.Project, error) {
	return nil, nil
}
func (m *mockStore) DeleteProject(_ context.Context, _ string) error { return nil }
func (m *mockStore) AddProjectMember(_ context.Context, _, _, _ string, _ *string) error {
	return nil
}
func (m *mockStore) GetProjectMember(_ context.Context, _, _ string) (*model.ProjectMember, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetProjectMemberForEnv(_ context.Context, _, _, _ string) (*model.ProjectMember, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) ListProjectMembers(_ context.Context, _ string) ([]*model.ProjectMember, error) {
	return nil, nil
}
func (m *mockStore) ListProjectMembersWithAccess(_ context.Context, _, _ string) ([]*model.ProjectMember, error) {
	return nil, nil
}
func (m *mockStore) UpdateProjectMember(_ context.Context, _, _, _ string, _ *string) error {
	return nil
}
func (m *mockStore) RemoveProjectMember(_ context.Context, _, _ string, _ *string) error {
	return nil
}
func (m *mockStore) CreateEnvironment(_ context.Context, _, _, _ string) (*model.Environment, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetEnvironment(_ context.Context, _, _ string) (*model.Environment, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) ListEnvironments(_ context.Context, _ string) ([]*model.Environment, error) {
	return nil, nil
}
func (m *mockStore) DeleteEnvironment(_ context.Context, _, _ string) error { return nil }
func (m *mockStore) SetSecret(_ context.Context, _, _, _ string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetSecret(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
	return nil, nil, store.ErrNotFound
}
func (m *mockStore) ListSecrets(_ context.Context, _, _ string) ([]*model.Secret, []*model.SecretVersion, error) {
	return nil, nil, nil
}
func (m *mockStore) DeleteSecret(_ context.Context, _, _, _ string) error { return nil }
func (m *mockStore) ListSecretVersions(_ context.Context, _ string) ([]*model.SecretVersion, error) {
	return nil, nil
}
func (m *mockStore) RollbackSecret(_ context.Context, _, _ string) error       { return nil }
func (m *mockStore) CreateAuditLog(_ context.Context, _ *model.AuditLog) error { return nil }
func (m *mockStore) ListAuditLogs(_ context.Context, _ store.AuditFilter) ([]*model.AuditLog, error) {
	return nil, nil
}
func (m *mockStore) SetDynamicBackend(_ context.Context, _, _, _, _ string, _, _ []byte, _, _ int) (*model.DynamicBackend, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetDynamicBackend(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetDynamicBackendByID(_ context.Context, _ string) (*model.DynamicBackend, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) DeleteDynamicBackend(_ context.Context, _, _, _ string) error { return nil }
func (m *mockStore) SetDynamicRole(_ context.Context, _, _, _, _ string, _ *int) (*model.DynamicRole, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetDynamicRole(_ context.Context, _, _ string) (*model.DynamicRole, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) ListDynamicRoles(_ context.Context, _ string) ([]*model.DynamicRole, error) {
	return nil, nil
}
func (m *mockStore) DeleteDynamicRole(_ context.Context, _, _ string) error { return nil }
func (m *mockStore) CreateDynamicLease(_ context.Context, _, _, _, _, _, _, _ string, _ time.Time, _ *string) (*model.DynamicLease, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetDynamicLease(_ context.Context, _ string) (*model.DynamicLease, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) ListDynamicLeases(_ context.Context, _, _ string) ([]*model.DynamicLease, error) {
	return nil, nil
}
func (m *mockStore) RevokeDynamicLease(_ context.Context, _ string) error { return nil }
func (m *mockStore) ListExpiredDynamicLeases(_ context.Context) ([]*model.DynamicLease, error) {
	return nil, nil
}
func (m *mockStore) CreateCertPrincipal(_ context.Context, _ *model.CertPrincipal) error {
	return store.ErrNotFound
}
func (m *mockStore) GetCertPrincipalBySPIFFEID(_ context.Context, _ string) (*model.CertPrincipal, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetCertPrincipalByEmailSAN(_ context.Context, _ string) (*model.CertPrincipal, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) ListCertPrincipals(_ context.Context, _ string) ([]*model.CertPrincipal, error) {
	return nil, nil
}
func (m *mockStore) ListCertPrincipalsWithAccess(_ context.Context, _, _ string) ([]*model.CertPrincipal, error) {
	return nil, nil
}
func (m *mockStore) DeleteCertPrincipal(_ context.Context, _, _ string) error  { return nil }
func (m *mockStore) SetProjectKey(_ context.Context, _ string, _ []byte) error { return nil }
func (m *mockStore) RewrapProjectDEKs(_ context.Context, _ string, _ func([]byte) ([]byte, error)) error {
	return nil
}
func (m *mockStore) CreateOIDCUser(_ context.Context, _, _, _, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) GetUserByOIDCSubject(_ context.Context, _, _ string) (*model.User, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) SetUserOIDCIdentity(_ context.Context, _, _, _ string) error { return nil }
func (m *mockStore) SetUserActive(_ context.Context, _ string, _ bool) error     { return nil }
func (m *mockStore) DeleteAllTokensForUser(_ context.Context, _ string) error    { return nil }
func (m *mockStore) CreateSCIMToken(_ context.Context, _ *model.SCIMToken) error { return nil }
func (m *mockStore) GetSCIMTokenByHash(_ context.Context, _ string) (*model.SCIMToken, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) ListSCIMTokens(_ context.Context) ([]*model.SCIMToken, error) { return nil, nil }
func (m *mockStore) DeleteSCIMToken(_ context.Context, _ string) error            { return nil }
func (m *mockStore) SetSCIMGroupRole(_ context.Context, _, _ string, _, _ *string, _ string) (*model.SCIMGroupRole, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) ListSCIMGroupRoles(_ context.Context) ([]*model.SCIMGroupRole, error) {
	return nil, nil
}
func (m *mockStore) ListSCIMGroupRolesByGroup(_ context.Context, _ string) ([]*model.SCIMGroupRole, error) {
	return nil, nil
}
func (m *mockStore) GetSCIMGroupRole(_ context.Context, _ string) (*model.SCIMGroupRole, error) {
	return nil, store.ErrNotFound
}
func (m *mockStore) DeleteSCIMGroupRole(_ context.Context, _ string) error { return nil }

// ── IssueUserToken ────────────────────────────────────────────────────────────

func TestIssueUserToken(t *testing.T) {
	st := newMockStore()
	raw, tok, err := IssueUserToken(context.Background(), st, "user-1", "session")
	if err != nil {
		t.Fatalf("IssueUserToken: %v", err)
	}
	if raw == "" {
		t.Error("raw token is empty")
	}
	if tok.ID == "" {
		t.Error("token ID is empty")
	}
	if tok.UserID == nil || *tok.UserID != "user-1" {
		t.Errorf("UserID = %v, want user-1", tok.UserID)
	}
	// Hash stored in DB must match HashToken(raw).
	if tok.TokenHash != HashToken(raw) {
		t.Error("stored hash does not match hash of raw token")
	}
	// Token should be retrievable.
	found, err := st.GetTokenByHash(context.Background(), HashToken(raw))
	if err != nil || found.ID != tok.ID {
		t.Errorf("token not findable in store: %v", err)
	}
}

func TestIssueUserToken_TwoCallsProduceDifferentTokens(t *testing.T) {
	st := newMockStore()
	raw1, _, _ := IssueUserToken(context.Background(), st, "u1", "s")
	raw2, _, _ := IssueUserToken(context.Background(), st, "u1", "s")
	if raw1 == raw2 {
		t.Error("two IssueUserToken calls produced the same raw token")
	}
}

// ── IssueMachineToken ─────────────────────────────────────────────────────────

func TestIssueMachineToken_Unscoped(t *testing.T) {
	st := newMockStore()
	raw, tok, err := IssueMachineToken(context.Background(), st, "u1", "ci", "", "", false, 0)
	if err != nil {
		t.Fatalf("IssueMachineToken: %v", err)
	}
	if raw == "" || tok.ID == "" {
		t.Error("empty raw token or ID")
	}
	if tok.ProjectID != nil || tok.EnvID != nil {
		t.Error("unscoped token should have nil ProjectID and EnvID")
	}
	if tok.ExpiresAt != nil {
		t.Error("no-expiry token should have nil ExpiresAt")
	}
}

func TestIssueMachineToken_Scoped(t *testing.T) {
	st := newMockStore()
	_, tok, err := IssueMachineToken(context.Background(), st, "u1", "deploy", "proj-1", "env-1", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if tok.ProjectID == nil || *tok.ProjectID != "proj-1" {
		t.Errorf("ProjectID = %v, want proj-1", tok.ProjectID)
	}
	if tok.EnvID == nil || *tok.EnvID != "env-1" {
		t.Errorf("EnvID = %v, want env-1", tok.EnvID)
	}
	if !tok.ReadOnly {
		t.Error("token should be read-only")
	}
}

func TestIssueMachineToken_WithExpiry(t *testing.T) {
	st := newMockStore()
	_, tok, err := IssueMachineToken(context.Background(), st, "u1", "temp", "", "", false, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tok.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil")
	}
	remaining := time.Until(*tok.ExpiresAt)
	if remaining < 23*time.Hour || remaining > 25*time.Hour {
		t.Errorf("ExpiresAt too far off: remaining %v", remaining)
	}
}

// ── Validate ──────────────────────────────────────────────────────────────────

func TestValidate_OK(t *testing.T) {
	st := newMockStore()
	raw, issued, _ := IssueUserToken(context.Background(), st, "u1", "s")

	found, err := Validate(context.Background(), st, raw)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if found.ID != issued.ID {
		t.Errorf("ID = %q, want %q", found.ID, issued.ID)
	}
}

func TestValidate_InvalidToken(t *testing.T) {
	st := newMockStore()
	_, err := Validate(context.Background(), st, "not-a-real-token")
	if err != store.ErrNotFound {
		t.Errorf("err = %v, want store.ErrNotFound", err)
	}
}
