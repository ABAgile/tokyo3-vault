package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// openTestDB returns an in-memory SQLite store with all migrations applied.
func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ── migrate ───────────────────────────────────────────────────────────────────

func TestMigrate_Idempotent(t *testing.T) {
	db := openTestDB(t)
	// Running migrate a second time should be a no-op.
	if err := db.migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// ── Users ─────────────────────────────────────────────────────────────────────

func TestUsers_CRUD(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// HasAdminUser — empty DB.
	has, err := db.HasAdminUser(ctx)
	if err != nil || has {
		t.Fatalf("HasAdminUser empty: %v, %v", has, err)
	}

	// CreateUser.
	u, err := db.CreateUser(ctx, "alice@example.com", "hash1", model.UserRoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == "" || u.Email != "alice@example.com" || u.Role != model.UserRoleAdmin {
		t.Errorf("unexpected user: %+v", u)
	}

	// Duplicate email → ErrConflict.
	_, err = db.CreateUser(ctx, "alice@example.com", "hash2", model.UserRoleMember)
	if err != store.ErrConflict {
		t.Errorf("duplicate email: err = %v, want ErrConflict", err)
	}

	// HasAdminUser — now true.
	has, err = db.HasAdminUser(ctx)
	if err != nil || !has {
		t.Fatalf("HasAdminUser after create: %v, %v", has, err)
	}

	// GetUserByEmail.
	got, err := db.GetUserByEmail(ctx, "alice@example.com")
	if err != nil || got.ID != u.ID {
		t.Errorf("GetUserByEmail: %v %v", got, err)
	}
	_, err = db.GetUserByEmail(ctx, "nobody@example.com")
	if err != store.ErrNotFound {
		t.Errorf("GetUserByEmail missing: err = %v, want ErrNotFound", err)
	}

	// GetUserByID.
	got, err = db.GetUserByID(ctx, u.ID)
	if err != nil || got.Email != "alice@example.com" {
		t.Errorf("GetUserByID: %v %v", got, err)
	}
	_, err = db.GetUserByID(ctx, "no-such-id")
	if err != store.ErrNotFound {
		t.Errorf("GetUserByID missing: err = %v, want ErrNotFound", err)
	}

	// ListUsers.
	db.CreateUser(ctx, "bob@example.com", "hash3", model.UserRoleMember)
	users, err := db.ListUsers(ctx)
	if err != nil || len(users) != 2 {
		t.Errorf("ListUsers: len=%d err=%v", len(users), err)
	}

	// UpdateUserPassword.
	if err := db.UpdateUserPassword(ctx, u.ID, "newhash"); err != nil {
		t.Errorf("UpdateUserPassword: %v", err)
	}
	refreshed, _ := db.GetUserByID(ctx, u.ID)
	if refreshed.PasswordHash != "newhash" {
		t.Errorf("password not updated: %q", refreshed.PasswordHash)
	}
}

// ── Tokens ────────────────────────────────────────────────────────────────────

func TestTokens_CRUD(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, _ := db.CreateUser(ctx, "tok@example.com", "h", model.UserRoleMember)

	tok := &model.Token{
		ID:        "tok-1",
		UserID:    &u.ID,
		TokenHash: "hash-abc",
		Name:      "ci",
		CreatedAt: time.Now().UTC(),
	}
	if err := db.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	// GetTokenByHash.
	got, err := db.GetTokenByHash(ctx, "hash-abc")
	if err != nil || got.ID != "tok-1" {
		t.Errorf("GetTokenByHash: %v %v", got, err)
	}
	_, err = db.GetTokenByHash(ctx, "no-such-hash")
	if err != store.ErrNotFound {
		t.Errorf("GetTokenByHash missing: err = %v, want ErrNotFound", err)
	}

	// ListTokens.
	tok2 := &model.Token{ID: "tok-2", UserID: &u.ID, TokenHash: "hash-xyz", Name: "deploy", CreatedAt: time.Now().UTC()}
	db.CreateToken(ctx, tok2)
	tokens, err := db.ListTokens(ctx, u.ID)
	if err != nil || len(tokens) != 2 {
		t.Errorf("ListTokens: len=%d err=%v", len(tokens), err)
	}

	// DeleteToken.
	if err := db.DeleteToken(ctx, "tok-1", u.ID); err != nil {
		t.Errorf("DeleteToken: %v", err)
	}
	if err := db.DeleteToken(ctx, "tok-1", u.ID); err != store.ErrNotFound {
		t.Errorf("DeleteToken missing: err = %v, want ErrNotFound", err)
	}
}

func TestToken_WithExpiry(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, _ := db.CreateUser(ctx, "exp@example.com", "h", model.UserRoleMember)
	exp := time.Now().UTC().Add(24 * time.Hour)
	tok := &model.Token{
		ID: "exp-tok", UserID: &u.ID, TokenHash: "exp-hash",
		Name: "temp", ExpiresAt: &exp, CreatedAt: time.Now().UTC(),
	}
	if err := db.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken with expiry: %v", err)
	}
	got, err := db.GetTokenByHash(ctx, "exp-hash")
	if err != nil || got.ExpiresAt == nil {
		t.Errorf("ExpiresAt not persisted: %v %v", got, err)
	}
}

// ── Projects ──────────────────────────────────────────────────────────────────

func TestProjects_CRUD(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// CreateProject.
	p, err := db.CreateProject(ctx, "My App", "my-app")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if p.ID == "" || p.Slug != "my-app" {
		t.Errorf("unexpected project: %+v", p)
	}

	// Duplicate slug → ErrConflict.
	_, err = db.CreateProject(ctx, "My App 2", "my-app")
	if err != store.ErrConflict {
		t.Errorf("duplicate slug: err = %v, want ErrConflict", err)
	}

	// GetProject.
	got, err := db.GetProject(ctx, "my-app")
	if err != nil || got.ID != p.ID {
		t.Errorf("GetProject: %v %v", got, err)
	}
	_, err = db.GetProject(ctx, "missing")
	if err != store.ErrNotFound {
		t.Errorf("GetProject missing: err = %v, want ErrNotFound", err)
	}

	// ListProjects.
	db.CreateProject(ctx, "Other", "other")
	projects, err := db.ListProjects(ctx)
	if err != nil || len(projects) != 2 {
		t.Errorf("ListProjects: len=%d err=%v", len(projects), err)
	}

	// DeleteProject.
	if err := db.DeleteProject(ctx, "my-app"); err != nil {
		t.Errorf("DeleteProject: %v", err)
	}
	if err := db.DeleteProject(ctx, "my-app"); err != store.ErrNotFound {
		t.Errorf("DeleteProject missing: err = %v, want ErrNotFound", err)
	}
}

func TestListProjectsByMember(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, _ := db.CreateUser(ctx, "member@example.com", "h", model.UserRoleMember)
	p1, _ := db.CreateProject(ctx, "Alpha", "alpha")
	p2, _ := db.CreateProject(ctx, "Beta", "beta")
	db.CreateProject(ctx, "Gamma", "gamma") // not a member

	db.AddProjectMember(ctx, p1.ID, u.ID, model.RoleViewer, nil)
	db.AddProjectMember(ctx, p2.ID, u.ID, model.RoleViewer, nil)

	projects, err := db.ListProjectsByMember(ctx, u.ID)
	if err != nil || len(projects) != 2 {
		t.Errorf("ListProjectsByMember: len=%d err=%v", len(projects), err)
	}
}

// ── Project members ───────────────────────────────────────────────────────────

func TestProjectMembers_CRUD(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, _ := db.CreateUser(ctx, "pm@example.com", "h", model.UserRoleMember)
	p, _ := db.CreateProject(ctx, "PM Project", "pm-proj")

	// AddProjectMember (project-level).
	if err := db.AddProjectMember(ctx, p.ID, u.ID, model.RoleOwner, nil); err != nil {
		t.Fatalf("AddProjectMember: %v", err)
	}

	// AddProjectMember is idempotent (upsert).
	if err := db.AddProjectMember(ctx, p.ID, u.ID, model.RoleEditor, nil); err != nil {
		t.Errorf("AddProjectMember upsert: %v", err)
	}

	// GetProjectMember (project-level only).
	m, err := db.GetProjectMember(ctx, p.ID, u.ID)
	if err != nil || m.Role != model.RoleEditor {
		t.Errorf("GetProjectMember: role=%q err=%v", m.Role, err)
	}
	_, err = db.GetProjectMember(ctx, p.ID, "no-user")
	if err != store.ErrNotFound {
		t.Errorf("GetProjectMember missing: err = %v, want ErrNotFound", err)
	}

	// ListProjectMembers.
	u2, _ := db.CreateUser(ctx, "pm2@example.com", "h", model.UserRoleMember)
	db.AddProjectMember(ctx, p.ID, u2.ID, model.RoleViewer, nil)
	members, err := db.ListProjectMembers(ctx, p.ID)
	if err != nil || len(members) != 2 {
		t.Errorf("ListProjectMembers: len=%d err=%v", len(members), err)
	}

	// UpdateProjectMember (project-level).
	if err := db.UpdateProjectMember(ctx, p.ID, u.ID, model.RoleViewer, nil); err != nil {
		t.Errorf("UpdateProjectMember: %v", err)
	}
	updated, _ := db.GetProjectMember(ctx, p.ID, u.ID)
	if updated.Role != model.RoleViewer {
		t.Errorf("role after update: %q", updated.Role)
	}
	if err := db.UpdateProjectMember(ctx, p.ID, "ghost", model.RoleViewer, nil); err != store.ErrNotFound {
		t.Errorf("UpdateProjectMember missing: err = %v, want ErrNotFound", err)
	}

	// RemoveProjectMember (project-level).
	if err := db.RemoveProjectMember(ctx, p.ID, u.ID, nil); err != nil {
		t.Errorf("RemoveProjectMember: %v", err)
	}
	if err := db.RemoveProjectMember(ctx, p.ID, u.ID, nil); err != store.ErrNotFound {
		t.Errorf("RemoveProjectMember missing: err = %v, want ErrNotFound", err)
	}
}

// ── Environments ──────────────────────────────────────────────────────────────

func TestEnvironments_CRUD(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	p, _ := db.CreateProject(ctx, "Env App", "env-app")

	// CreateEnvironment.
	e, err := db.CreateEnvironment(ctx, p.ID, "Production", "prod")
	if err != nil {
		t.Fatalf("CreateEnvironment: %v", err)
	}
	if e.ID == "" || e.Slug != "prod" || e.ProjectID != p.ID {
		t.Errorf("unexpected env: %+v", e)
	}

	// Duplicate slug within same project → ErrConflict.
	_, err = db.CreateEnvironment(ctx, p.ID, "Production 2", "prod")
	if err != store.ErrConflict {
		t.Errorf("duplicate env slug: err = %v, want ErrConflict", err)
	}

	// Same slug in a different project is allowed.
	p2, _ := db.CreateProject(ctx, "Other App", "other-app")
	if _, err := db.CreateEnvironment(ctx, p2.ID, "Production", "prod"); err != nil {
		t.Errorf("same slug different project: %v", err)
	}

	// GetEnvironment.
	got, err := db.GetEnvironment(ctx, p.ID, "prod")
	if err != nil || got.ID != e.ID {
		t.Errorf("GetEnvironment: %v %v", got, err)
	}
	_, err = db.GetEnvironment(ctx, p.ID, "missing")
	if err != store.ErrNotFound {
		t.Errorf("GetEnvironment missing: err = %v, want ErrNotFound", err)
	}

	// ListEnvironments.
	db.CreateEnvironment(ctx, p.ID, "Staging", "staging")
	envs, err := db.ListEnvironments(ctx, p.ID)
	if err != nil || len(envs) != 2 {
		t.Errorf("ListEnvironments: len=%d err=%v", len(envs), err)
	}

	// DeleteEnvironment.
	if err := db.DeleteEnvironment(ctx, p.ID, "prod"); err != nil {
		t.Errorf("DeleteEnvironment: %v", err)
	}
	if err := db.DeleteEnvironment(ctx, p.ID, "prod"); err != store.ErrNotFound {
		t.Errorf("DeleteEnvironment missing: err = %v, want ErrNotFound", err)
	}
}

// ── Secrets ───────────────────────────────────────────────────────────────────

func setupProjectEnv(t *testing.T, db *DB) (projectID, envID string) {
	t.Helper()
	ctx := context.Background()
	p, _ := db.CreateProject(ctx, "Secret App", "secret-app")
	e, _ := db.CreateEnvironment(ctx, p.ID, "Dev", "dev")
	return p.ID, e.ID
}

func TestSecrets_SetAndGet(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	pID, eID := setupProjectEnv(t, db)

	encVal := []byte("encrypted-value")
	encDEK := []byte("encrypted-dek")
	comment := "# database url"

	// SetSecret — new secret.
	sv, err := db.SetSecret(ctx, pID, eID, "DB_URL", &comment, encVal, encDEK, nil)
	if err != nil {
		t.Fatalf("SetSecret new: %v", err)
	}
	if sv.Version != 1 || sv.ID == "" {
		t.Errorf("unexpected version: %+v", sv)
	}

	// SetSecret — update same key → version 2.
	sv2, err := db.SetSecret(ctx, pID, eID, "DB_URL", nil, []byte("val2"), encDEK, nil)
	if err != nil {
		t.Fatalf("SetSecret update: %v", err)
	}
	if sv2.Version != 2 {
		t.Errorf("expected version 2, got %d", sv2.Version)
	}

	// GetSecret — returns current version.
	sec, curSV, err := db.GetSecret(ctx, pID, eID, "DB_URL")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if sec.Key != "DB_URL" {
		t.Errorf("key = %q", sec.Key)
	}
	if curSV == nil || curSV.Version != 2 {
		t.Errorf("expected current version 2: %v", curSV)
	}

	// GetSecret — not found.
	_, _, err = db.GetSecret(ctx, pID, eID, "MISSING")
	if err != store.ErrNotFound {
		t.Errorf("GetSecret missing: err = %v, want ErrNotFound", err)
	}
}

func TestSecrets_ListAndDelete(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	pID, eID := setupProjectEnv(t, db)

	db.SetSecret(ctx, pID, eID, "KEY_A", nil, []byte("a"), []byte("dek"), nil)
	db.SetSecret(ctx, pID, eID, "KEY_B", nil, []byte("b"), []byte("dek"), nil)

	// ListSecrets.
	secrets, versions, err := db.ListSecrets(ctx, pID, eID)
	if err != nil || len(secrets) != 2 || len(versions) != 2 {
		t.Fatalf("ListSecrets: len=%d err=%v", len(secrets), err)
	}
	if secrets[0].Key != "KEY_A" || secrets[1].Key != "KEY_B" {
		t.Errorf("unexpected order: %v %v", secrets[0].Key, secrets[1].Key)
	}

	// DeleteSecret.
	if err := db.DeleteSecret(ctx, pID, eID, "KEY_A"); err != nil {
		t.Errorf("DeleteSecret: %v", err)
	}
	if err := db.DeleteSecret(ctx, pID, eID, "KEY_A"); err != store.ErrNotFound {
		t.Errorf("DeleteSecret missing: err = %v, want ErrNotFound", err)
	}

	// List after delete.
	secrets, _, _ = db.ListSecrets(ctx, pID, eID)
	if len(secrets) != 1 || secrets[0].Key != "KEY_B" {
		t.Errorf("after delete: %v", secrets)
	}
}

func TestSecrets_Versions(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	pID, eID := setupProjectEnv(t, db)

	// Create 3 versions.
	for i := range 3 {
		db.SetSecret(ctx, pID, eID, "MY_KEY", nil, []byte{byte(i)}, []byte("dek"), nil)
	}

	sec, _, _ := db.GetSecret(ctx, pID, eID, "MY_KEY")
	versions, err := db.ListSecretVersions(ctx, sec.ID)
	if err != nil || len(versions) != 3 {
		t.Fatalf("ListSecretVersions: len=%d err=%v", len(versions), err)
	}
	// Ordered DESC — highest version first.
	if versions[0].Version != 3 || versions[2].Version != 1 {
		t.Errorf("unexpected order: v[0]=%d v[2]=%d", versions[0].Version, versions[2].Version)
	}

	// RollbackSecret to version 1.
	if err := db.RollbackSecret(ctx, sec.ID, versions[2].ID); err != nil {
		t.Errorf("RollbackSecret: %v", err)
	}
	_, curSV, _ := db.GetSecret(ctx, pID, eID, "MY_KEY")
	if curSV.Version != 1 {
		t.Errorf("after rollback current version = %d, want 1", curSV.Version)
	}

	// RollbackSecret — nonexistent secret ID.
	if err := db.RollbackSecret(ctx, "no-such-id", "v-id"); err != store.ErrNotFound {
		t.Errorf("RollbackSecret missing: err = %v, want ErrNotFound", err)
	}
}

func TestSetSecret_CommentPreservedOnUpdate(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	pID, eID := setupProjectEnv(t, db)

	c := "# original comment"
	db.SetSecret(ctx, pID, eID, "X", &c, []byte("v1"), []byte("dek"), nil)

	// Update without providing a comment — existing comment should be retained.
	db.SetSecret(ctx, pID, eID, "X", nil, []byte("v2"), []byte("dek"), nil)

	sec, _, _ := db.GetSecret(ctx, pID, eID, "X")
	if sec.Comment != c {
		t.Errorf("comment = %q, want %q", sec.Comment, c)
	}
}

// ── isUnique ──────────────────────────────────────────────────────────────────

func TestIsUnique(t *testing.T) {
	if isUnique(nil) {
		t.Error("isUnique(nil) should be false")
	}
	// Trigger a raw UNIQUE constraint error through the underlying db.Exec,
	// bypassing the isUnique→ErrConflict translation in the store methods.
	db := openTestDB(t)
	ctx := context.Background()
	db.CreateProject(ctx, "App", "app")
	// Insert a duplicate slug directly — this returns the raw SQLite error.
	_, err := db.db.ExecContext(ctx,
		`INSERT INTO projects (id, name, slug, created_at) VALUES ('x', 'App2', 'app', datetime('now'))`,
	)
	if !isUnique(err) {
		t.Errorf("expected isUnique true for raw constraint error: %v", err)
	}
}
