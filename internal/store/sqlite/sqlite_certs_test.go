package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// setupUserAndProject creates a user and project, returning their IDs.
func setupUserAndProject(t *testing.T, db *DB) (userID, projectID, envID string) {
	t.Helper()
	ctx := context.Background()
	u, err := db.CreateUser(ctx, "certuser@example.com", "hash", model.UserRoleMember)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	p, err := db.CreateProject(ctx, "CertApp", "cert-app")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	e, err := db.CreateEnvironment(ctx, p.ID, "Prod", "prod")
	if err != nil {
		t.Fatalf("CreateEnvironment: %v", err)
	}
	return u.ID, p.ID, e.ID
}

// TestCertPrincipals_SPIFFE tests Create/Get/List/Delete using a SPIFFE ID.
func TestCertPrincipals_SPIFFE(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	userID, _, _ := setupUserAndProject(t, db)

	spiffeID := "spiffe://cluster.local/ns/myapp/sa/server"
	p := &model.CertPrincipal{
		UserID:      &userID,
		Description: "my workload",
		SPIFFEID:    &spiffeID,
	}
	if err := db.CreateCertPrincipal(ctx, p); err != nil {
		t.Fatalf("CreateCertPrincipal SPIFFE: %v", err)
	}
	if p.ID == "" {
		t.Error("ID should be set after Create")
	}

	// GetCertPrincipalBySPIFFEID — found.
	got, err := db.GetCertPrincipalBySPIFFEID(ctx, spiffeID)
	if err != nil {
		t.Fatalf("GetBySPIFFEID: %v", err)
	}
	if got.SPIFFEID == nil || *got.SPIFFEID != spiffeID {
		t.Errorf("SPIFFE ID mismatch: got %v", got.SPIFFEID)
	}

	// GetCertPrincipalBySPIFFEID — not found.
	_, err = db.GetCertPrincipalBySPIFFEID(ctx, "spiffe://other")
	if err != store.ErrNotFound {
		t.Errorf("not found: got %v, want ErrNotFound", err)
	}

	// ListCertPrincipals.
	list, err := db.ListCertPrincipals(ctx, userID)
	if err != nil || len(list) != 1 {
		t.Errorf("ListCertPrincipals: len=%d err=%v", len(list), err)
	}

	// DeleteCertPrincipal — found.
	if err := db.DeleteCertPrincipal(ctx, p.ID, userID); err != nil {
		t.Errorf("DeleteCertPrincipal: %v", err)
	}
	// Idempotent delete → not found.
	if err := db.DeleteCertPrincipal(ctx, p.ID, userID); err != store.ErrNotFound {
		t.Errorf("DeleteCertPrincipal missing: got %v, want ErrNotFound", err)
	}
}

// TestCertPrincipals_Email tests Create/Get using an email SAN.
func TestCertPrincipals_Email(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	userID, _, _ := setupUserAndProject(t, db)

	email := "alice@corp.example.com"
	p := &model.CertPrincipal{
		UserID:      &userID,
		Description: "alice client cert",
		EmailSAN:    &email,
	}
	if err := db.CreateCertPrincipal(ctx, p); err != nil {
		t.Fatalf("CreateCertPrincipal email: %v", err)
	}

	// GetCertPrincipalByEmailSAN — found.
	got, err := db.GetCertPrincipalByEmailSAN(ctx, email)
	if err != nil {
		t.Fatalf("GetByEmailSAN: %v", err)
	}
	if got.EmailSAN == nil || *got.EmailSAN != email {
		t.Errorf("email SAN mismatch: got %v", got.EmailSAN)
	}

	// GetCertPrincipalByEmailSAN — not found.
	_, err = db.GetCertPrincipalByEmailSAN(ctx, "nobody@example.com")
	if err != store.ErrNotFound {
		t.Errorf("not found: got %v, want ErrNotFound", err)
	}
}

// TestCertPrincipals_Conflict tests that duplicate identifiers return ErrConflict.
func TestCertPrincipals_Conflict(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	userID, _, _ := setupUserAndProject(t, db)

	spiffeID := "spiffe://cluster.local/ns/dup/sa/server"
	p1 := &model.CertPrincipal{UserID: &userID, Description: "first", SPIFFEID: &spiffeID}
	p2 := &model.CertPrincipal{UserID: &userID, Description: "dup", SPIFFEID: &spiffeID}

	if err := db.CreateCertPrincipal(ctx, p1); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if err := db.CreateCertPrincipal(ctx, p2); err != store.ErrConflict {
		t.Errorf("duplicate: got %v, want ErrConflict", err)
	}
}

// TestCertPrincipals_ExpiresAt tests ExpiresAt persistence.
func TestCertPrincipals_ExpiresAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	userID, _, _ := setupUserAndProject(t, db)

	spiffeID := "spiffe://cluster.local/ns/exp/sa/server"
	exp := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	p := &model.CertPrincipal{
		UserID:      &userID,
		Description: "expiring",
		SPIFFEID:    &spiffeID,
		ExpiresAt:   &exp,
	}
	if err := db.CreateCertPrincipal(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := db.GetCertPrincipalBySPIFFEID(ctx, spiffeID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ExpiresAt == nil {
		t.Fatal("ExpiresAt not persisted")
	}
	if !got.ExpiresAt.Truncate(time.Second).Equal(exp) {
		t.Errorf("ExpiresAt mismatch: got %v, want %v", got.ExpiresAt, exp)
	}
}

// TestCertPrincipals_DeleteWrongUser verifies that deleting with wrong userID returns not found.
func TestCertPrincipals_DeleteWrongUser(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	userID, _, _ := setupUserAndProject(t, db)

	spiffeID := "spiffe://cluster.local/ns/wrong/sa/server"
	p := &model.CertPrincipal{UserID: &userID, Description: "wrong", SPIFFEID: &spiffeID}
	if err := db.CreateCertPrincipal(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := db.DeleteCertPrincipal(ctx, p.ID, "other-user"); err != store.ErrNotFound {
		t.Errorf("wrong user delete: got %v, want ErrNotFound", err)
	}
}

// TestListCertPrincipalsWithAccess tests env-scoped, project-scoped, and member unscoped.
func TestListCertPrincipalsWithAccess(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	userID, projectID, envID := setupUserAndProject(t, db)

	// Add user as project member to cover the unscoped path.
	if err := db.AddProjectMember(ctx, projectID, userID, model.RoleViewer, nil); err != nil {
		t.Fatalf("AddProjectMember: %v", err)
	}

	// Create env-scoped principal.
	s1 := "spiffe://cluster.local/ns/env/sa/svc"
	pEnv := &model.CertPrincipal{UserID: &userID, Description: "env-scoped", SPIFFEID: &s1, ProjectID: &projectID, EnvID: &envID}
	if err := db.CreateCertPrincipal(ctx, pEnv); err != nil {
		t.Fatalf("env-scoped create: %v", err)
	}

	// Create project-scoped principal (no env).
	s2 := "spiffe://cluster.local/ns/proj/sa/svc"
	pProj := &model.CertPrincipal{UserID: &userID, Description: "proj-scoped", SPIFFEID: &s2, ProjectID: &projectID}
	if err := db.CreateCertPrincipal(ctx, pProj); err != nil {
		t.Fatalf("proj-scoped create: %v", err)
	}

	// Create unscoped principal (member of project).
	s3 := "spiffe://cluster.local/ns/unscoped/sa/svc"
	pUnscoped := &model.CertPrincipal{UserID: &userID, Description: "unscoped", SPIFFEID: &s3}
	if err := db.CreateCertPrincipal(ctx, pUnscoped); err != nil {
		t.Fatalf("unscoped create: %v", err)
	}

	list, err := db.ListCertPrincipalsWithAccess(ctx, projectID, envID)
	if err != nil {
		t.Fatalf("ListCertPrincipalsWithAccess: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 principals, got %d", len(list))
	}
}
