package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// TestGetSecretVersion tests GetSecretVersion.
func TestGetSecretVersion(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	pID, eID := setupProjectEnv(t, db)

	db.SetSecret(ctx, pID, eID, "VER_KEY", nil, []byte("v1"), []byte("dek"), nil)
	sec, sv, _ := db.GetSecret(ctx, pID, eID, "VER_KEY")

	got, err := db.GetSecretVersion(ctx, sec.ID, sv.ID)
	if err != nil {
		t.Fatalf("GetSecretVersion: %v", err)
	}
	if got.ID != sv.ID {
		t.Errorf("ID = %q, want %q", got.ID, sv.ID)
	}

	_, err = db.GetSecretVersion(ctx, sec.ID, "no-such")
	if err != store.ErrNotFound {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}
}

// TestPruneSecretVersions tests PruneSecretVersions.
func TestPruneSecretVersions(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	pID, eID := setupProjectEnv(t, db)

	// Create 5 versions.
	var curSV *model.SecretVersion
	for i := range 5 {
		sv, err := db.SetSecret(ctx, pID, eID, "PRUNE_KEY", nil, []byte{byte(i)}, []byte("dek"), nil)
		if err != nil {
			t.Fatalf("SetSecret v%d: %v", i, err)
		}
		curSV = sv
	}
	sec, _, _ := db.GetSecret(ctx, pID, eID, "PRUNE_KEY")

	// Prune keeping minCount=3, anything older than cutoff in the past.
	cutoff := time.Now().UTC().Add(time.Minute) // all versions are old enough
	if err := db.PruneSecretVersions(ctx, sec.ID, curSV.ID, 3, cutoff); err != nil {
		t.Fatalf("PruneSecretVersions: %v", err)
	}

	versions, err := db.ListSecretVersions(ctx, sec.ID)
	if err != nil {
		t.Fatalf("ListSecretVersions after prune: %v", err)
	}
	if len(versions) < 3 {
		t.Errorf("after prune: expected at least 3 versions, got %d", len(versions))
	}
}

// TestListSecretsForPrune tests ListSecretsForPrune returns secret IDs and current version IDs.
func TestListSecretsForPrune(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	pID, eID := setupProjectEnv(t, db)

	db.SetSecret(ctx, pID, eID, "KEY_A", nil, []byte("a"), []byte("dek"), nil)
	db.SetSecret(ctx, pID, eID, "KEY_B", nil, []byte("b"), []byte("dek"), nil)

	pairs, err := db.ListSecretsForPrune(ctx)
	if err != nil {
		t.Fatalf("ListSecretsForPrune: %v", err)
	}
	if len(pairs) != 2 {
		t.Errorf("expected 2 pairs, got %d", len(pairs))
	}
}

// TestListTokensWithAccess tests ListTokensWithAccess.
func TestListTokensWithAccess(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, _ := db.CreateUser(ctx, "twa@example.com", "h", model.UserRoleMember)
	p, _ := db.CreateProject(ctx, "TWA", "twa")
	e, _ := db.CreateEnvironment(ctx, p.ID, "Dev", "dev")

	// Project-scoped token.
	tok1 := &model.Token{ID: "t1", UserID: &u.ID, TokenHash: "h1", Name: "proj", ProjectID: &p.ID, CreatedAt: time.Now().UTC()}
	db.CreateToken(ctx, tok1)

	// Env-scoped token.
	tok2 := &model.Token{ID: "t2", UserID: &u.ID, TokenHash: "h2", Name: "env", ProjectID: &p.ID, EnvID: &e.ID, CreatedAt: time.Now().UTC()}
	db.CreateToken(ctx, tok2)

	// Unscoped token (should not appear).
	tok3 := &model.Token{ID: "t3", UserID: &u.ID, TokenHash: "h3", Name: "unscoped", CreatedAt: time.Now().UTC()}
	db.CreateToken(ctx, tok3)

	tokens, err := db.ListTokensWithAccess(ctx, p.ID, e.ID)
	if err != nil {
		t.Fatalf("ListTokensWithAccess: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens (proj + env scoped), got %d", len(tokens))
	}
}

// TestGetProjectMemberForEnv tests env-scoped member lookup.
func TestGetProjectMemberForEnv(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, _ := db.CreateUser(ctx, "envmem@example.com", "h", model.UserRoleMember)
	p, _ := db.CreateProject(ctx, "EnvMem", "env-mem")
	e, _ := db.CreateEnvironment(ctx, p.ID, "Dev", "dev")

	// Add project-level member.
	db.AddProjectMember(ctx, p.ID, u.ID, model.RoleViewer, nil)

	m, err := db.GetProjectMemberForEnv(ctx, p.ID, e.ID, u.ID)
	if err != nil {
		t.Fatalf("GetProjectMemberForEnv: %v", err)
	}
	if m.Role != model.RoleViewer {
		t.Errorf("role = %q, want viewer", m.Role)
	}

	// Add env-specific member.
	db.AddProjectMember(ctx, p.ID, u.ID, model.RoleEditor, &e.ID)
	m2, err := db.GetProjectMemberForEnv(ctx, p.ID, e.ID, u.ID)
	if err != nil {
		t.Fatalf("GetProjectMemberForEnv env-scoped: %v", err)
	}
	// Env-specific should win (lower value = more specific).
	if m2.Role != model.RoleEditor {
		t.Errorf("env-specific role = %q, want editor", m2.Role)
	}
}

// TestListProjectMembersWithAccess tests project+env access listing.
func TestListProjectMembersWithAccess(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u1, _ := db.CreateUser(ctx, "lpmwa1@example.com", "h", model.UserRoleMember)
	u2, _ := db.CreateUser(ctx, "lpmwa2@example.com", "h", model.UserRoleMember)
	p, _ := db.CreateProject(ctx, "LPMWA", "lpmwa")
	e, _ := db.CreateEnvironment(ctx, p.ID, "Dev", "dev")

	// u1 project-level.
	db.AddProjectMember(ctx, p.ID, u1.ID, model.RoleViewer, nil)
	// u2 env-level.
	db.AddProjectMember(ctx, p.ID, u2.ID, model.RoleEditor, &e.ID)

	members, err := db.ListProjectMembersWithAccess(ctx, p.ID, e.ID)
	if err != nil {
		t.Fatalf("ListProjectMembersWithAccess: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("expected 2 members, got %d", len(members))
	}
}

// TestSetUserActive tests SetUserActive.
func TestSetUserActive(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, _ := db.CreateUser(ctx, "active@example.com", "h", model.UserRoleMember)

	if err := db.SetUserActive(ctx, u.ID, false); err != nil {
		t.Fatalf("SetUserActive false: %v", err)
	}
	got, _ := db.GetUserByID(ctx, u.ID)
	if got.Active {
		t.Error("user should be inactive")
	}

	if err := db.SetUserActive(ctx, u.ID, true); err != nil {
		t.Fatalf("SetUserActive true: %v", err)
	}
	got, _ = db.GetUserByID(ctx, u.ID)
	if !got.Active {
		t.Error("user should be active")
	}
}

// TestDeleteAllTokensForUser tests DeleteAllTokensForUser.
func TestDeleteAllTokensForUser(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, _ := db.CreateUser(ctx, "deltok@example.com", "h", model.UserRoleMember)
	db.CreateToken(ctx, &model.Token{ID: "t1", UserID: &u.ID, TokenHash: "h1", Name: "a", CreatedAt: time.Now().UTC()})
	db.CreateToken(ctx, &model.Token{ID: "t2", UserID: &u.ID, TokenHash: "h2", Name: "b", CreatedAt: time.Now().UTC()})

	if err := db.DeleteAllTokensForUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteAllTokensForUser: %v", err)
	}

	tokens, _ := db.ListTokens(ctx, u.ID)
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens after delete, got %d", len(tokens))
	}
}

// TestSCIMTokens_CRUD tests SCIM token CRUD operations.
func TestSCIMTokens_CRUD(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	tok := &model.SCIMToken{
		ID:          "scim-1",
		TokenHash:   "scim-hash-abc",
		Description: "SCIM provisioner",
		CreatedAt:   time.Now().UTC(),
	}

	if err := db.CreateSCIMToken(ctx, tok); err != nil {
		t.Fatalf("CreateSCIMToken: %v", err)
	}

	got, err := db.GetSCIMTokenByHash(ctx, "scim-hash-abc")
	if err != nil {
		t.Fatalf("GetSCIMTokenByHash: %v", err)
	}
	if got.ID != "scim-1" {
		t.Errorf("ID = %q, want scim-1", got.ID)
	}

	_, err = db.GetSCIMTokenByHash(ctx, "no-such")
	if err != store.ErrNotFound {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}

	tokens, err := db.ListSCIMTokens(ctx)
	if err != nil || len(tokens) != 1 {
		t.Errorf("ListSCIMTokens: len=%d err=%v", len(tokens), err)
	}

	if err := db.DeleteSCIMToken(ctx, "scim-1"); err != nil {
		t.Errorf("DeleteSCIMToken: %v", err)
	}

	tokens, _ = db.ListSCIMTokens(ctx)
	if len(tokens) != 0 {
		t.Errorf("after delete: expected 0 tokens, got %d", len(tokens))
	}
}

// TestSCIMGroupRoles_CRUD tests SCIM group role CRUD.
func TestSCIMGroupRoles_CRUD(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	p, _ := db.CreateProject(ctx, "SCIM App", "scim-app")

	gr, err := db.SetSCIMGroupRole(ctx, "group-123", "Engineers", &p.ID, nil, model.RoleEditor)
	if err != nil {
		t.Fatalf("SetSCIMGroupRole: %v", err)
	}
	if gr.ID == "" || gr.GroupID != "group-123" {
		t.Errorf("unexpected group role: %+v", gr)
	}

	// GetSCIMGroupRole.
	got, err := db.GetSCIMGroupRole(ctx, gr.ID)
	if err != nil {
		t.Fatalf("GetSCIMGroupRole: %v", err)
	}
	if got.Role != model.RoleEditor {
		t.Errorf("role = %q, want editor", got.Role)
	}

	// ListSCIMGroupRoles.
	roles, err := db.ListSCIMGroupRoles(ctx)
	if err != nil || len(roles) != 1 {
		t.Errorf("ListSCIMGroupRoles: len=%d err=%v", len(roles), err)
	}

	// ListSCIMGroupRolesByGroup.
	byGroup, err := db.ListSCIMGroupRolesByGroup(ctx, "group-123")
	if err != nil || len(byGroup) != 1 {
		t.Errorf("ListSCIMGroupRolesByGroup: len=%d err=%v", len(byGroup), err)
	}

	// DeleteSCIMGroupRole.
	if err := db.DeleteSCIMGroupRole(ctx, gr.ID); err != nil {
		t.Errorf("DeleteSCIMGroupRole: %v", err)
	}
	if err := db.DeleteSCIMGroupRole(ctx, gr.ID); err != store.ErrNotFound {
		t.Errorf("delete missing: got %v, want ErrNotFound", err)
	}
}

// TestOIDCUser tests CreateOIDCUser and GetUserByOIDCSubject.
func TestOIDCUser(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, err := db.CreateOIDCUser(ctx, "oidc@example.com", "google", "sub-123", "ext-456")
	if err != nil {
		t.Fatalf("CreateOIDCUser: %v", err)
	}
	if u.OIDCIssuer == nil || *u.OIDCIssuer != "google" {
		t.Errorf("OIDCIssuer = %v", u.OIDCIssuer)
	}

	got, err := db.GetUserByOIDCSubject(ctx, "google", "sub-123")
	if err != nil {
		t.Fatalf("GetUserByOIDCSubject: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("ID = %q, want %q", got.ID, u.ID)
	}

	_, err = db.GetUserByOIDCSubject(ctx, "google", "no-such")
	if err != store.ErrNotFound {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}
}

// TestSetUserOIDCIdentity tests SetUserOIDCIdentity.
func TestSetUserOIDCIdentity(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, _ := db.CreateUser(ctx, "local@example.com", "h", model.UserRoleMember)
	if err := db.SetUserOIDCIdentity(ctx, u.ID, "github", "gh-sub-789"); err != nil {
		t.Fatalf("SetUserOIDCIdentity: %v", err)
	}

	got, _ := db.GetUserByID(ctx, u.ID)
	if got.OIDCIssuer == nil || *got.OIDCIssuer != "github" {
		t.Errorf("OIDCIssuer = %v", got.OIDCIssuer)
	}
}
