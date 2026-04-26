package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/store"
)

// setupDynamicBackend creates a backend and returns its slug + the project/env IDs.
func setupDynamicBackend(t *testing.T, db *DB) (projectID, envID, slug string) {
	t.Helper()
	projectID, envID = setupProjectEnv(t, db)
	slug = "pg-primary"
	_, err := db.SetDynamicBackend(context.Background(),
		projectID, envID, slug, "postgresql",
		[]byte("enc-config"), []byte("enc-dek"), 3600, 86400,
	)
	if err != nil {
		t.Fatalf("SetDynamicBackend: %v", err)
	}
	return projectID, envID, slug
}

// TestDynamicBackend_SetAndGet tests upsert semantics and GetDynamicBackend.
func TestDynamicBackend_SetAndGet(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID := setupProjectEnv(t, db)

	// Create new backend.
	b, err := db.SetDynamicBackend(ctx, projectID, envID, "pg", "postgresql",
		[]byte("cfg1"), []byte("dek1"), 600, 3600)
	if err != nil {
		t.Fatalf("SetDynamicBackend new: %v", err)
	}
	if b.Slug != "pg" || b.Type != "postgresql" || b.DefaultTTL != 600 {
		t.Errorf("unexpected backend: %+v", b)
	}

	// Update existing backend.
	b2, err := db.SetDynamicBackend(ctx, projectID, envID, "pg", "postgresql",
		[]byte("cfg2"), []byte("dek2"), 1200, 7200)
	if err != nil {
		t.Fatalf("SetDynamicBackend update: %v", err)
	}
	if b2.DefaultTTL != 1200 {
		t.Errorf("updated DefaultTTL = %d, want 1200", b2.DefaultTTL)
	}

	// GetDynamicBackend — found.
	got, err := db.GetDynamicBackend(ctx, projectID, envID, "pg")
	if err != nil {
		t.Fatalf("GetDynamicBackend: %v", err)
	}
	if got.ID != b.ID {
		t.Errorf("ID mismatch after upsert: got %q, want %q", got.ID, b.ID)
	}

	// GetDynamicBackend — not found.
	_, err = db.GetDynamicBackend(ctx, projectID, envID, "missing")
	if err != store.ErrNotFound {
		t.Errorf("not found: got %v, want ErrNotFound", err)
	}
}

// TestDynamicBackend_GetByID tests GetDynamicBackendByID.
func TestDynamicBackend_GetByID(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID, slug := setupDynamicBackend(t, db)

	b, _ := db.GetDynamicBackend(ctx, projectID, envID, slug)

	got, err := db.GetDynamicBackendByID(ctx, b.ID)
	if err != nil {
		t.Fatalf("GetDynamicBackendByID: %v", err)
	}
	if got.ID != b.ID {
		t.Errorf("ID = %q, want %q", got.ID, b.ID)
	}

	_, err = db.GetDynamicBackendByID(ctx, "no-such-id")
	if err != store.ErrNotFound {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}
}

// TestDynamicBackend_Delete tests DeleteDynamicBackend.
func TestDynamicBackend_Delete(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID, slug := setupDynamicBackend(t, db)

	if err := db.DeleteDynamicBackend(ctx, projectID, envID, slug); err != nil {
		t.Errorf("DeleteDynamicBackend: %v", err)
	}
	if err := db.DeleteDynamicBackend(ctx, projectID, envID, slug); err != store.ErrNotFound {
		t.Errorf("second delete: got %v, want ErrNotFound", err)
	}
}

// TestDynamicRole_SetGetList tests SetDynamicRole, GetDynamicRole, ListDynamicRoles.
func TestDynamicRole_SetGetList(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID, slug := setupDynamicBackend(t, db)
	backend, _ := db.GetDynamicBackend(ctx, projectID, envID, slug)

	// Create role.
	ttl := 300
	r, err := db.SetDynamicRole(ctx, backend.ID, "readonly", "CREATE USER ...", "DROP USER ...", &ttl)
	if err != nil {
		t.Fatalf("SetDynamicRole create: %v", err)
	}
	if r.Name != "readonly" || r.TTL == nil || *r.TTL != 300 {
		t.Errorf("unexpected role: %+v", r)
	}

	// Update role.
	ttl2 := 600
	r2, err := db.SetDynamicRole(ctx, backend.ID, "readonly", "CREATE USER admin...", "DROP USER admin...", &ttl2)
	if err != nil {
		t.Fatalf("SetDynamicRole update: %v", err)
	}
	if *r2.TTL != 600 {
		t.Errorf("updated TTL = %d, want 600", *r2.TTL)
	}

	// GetDynamicRole — found.
	got, err := db.GetDynamicRole(ctx, backend.ID, "readonly")
	if err != nil {
		t.Fatalf("GetDynamicRole: %v", err)
	}
	if got.ID == "" {
		t.Error("ID should be set")
	}

	// GetDynamicRole — not found.
	_, err = db.GetDynamicRole(ctx, backend.ID, "missing")
	if err != store.ErrNotFound {
		t.Errorf("not found: got %v, want ErrNotFound", err)
	}

	// ListDynamicRoles.
	db.SetDynamicRole(ctx, backend.ID, "admin", "CREATE ...", "DROP ...", nil)
	roles, err := db.ListDynamicRoles(ctx, backend.ID)
	if err != nil || len(roles) != 2 {
		t.Errorf("ListDynamicRoles: len=%d err=%v", len(roles), err)
	}
	// Ordered by name: admin < readonly.
	if roles[0].Name != "admin" || roles[1].Name != "readonly" {
		t.Errorf("unexpected order: %v %v", roles[0].Name, roles[1].Name)
	}
}

// TestDynamicRole_ListEmpty tests that ListDynamicRoles returns empty slice (not nil).
func TestDynamicRole_ListEmpty(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID, slug := setupDynamicBackend(t, db)
	backend, _ := db.GetDynamicBackend(ctx, projectID, envID, slug)

	roles, err := db.ListDynamicRoles(ctx, backend.ID)
	if err != nil {
		t.Fatalf("ListDynamicRoles empty: %v", err)
	}
	if roles == nil {
		t.Error("expected empty slice, got nil")
	}
}

// TestDynamicRole_Delete tests DeleteDynamicRole.
func TestDynamicRole_Delete(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID, slug := setupDynamicBackend(t, db)
	backend, _ := db.GetDynamicBackend(ctx, projectID, envID, slug)

	db.SetDynamicRole(ctx, backend.ID, "myrole", "CREATE ...", "DROP ...", nil)

	if err := db.DeleteDynamicRole(ctx, backend.ID, "myrole"); err != nil {
		t.Errorf("DeleteDynamicRole: %v", err)
	}
	if err := db.DeleteDynamicRole(ctx, backend.ID, "myrole"); err != store.ErrNotFound {
		t.Errorf("second delete: got %v, want ErrNotFound", err)
	}
}

// TestDynamicLease_CreateAndGet tests CreateDynamicLease and GetDynamicLease.
func TestDynamicLease_CreateAndGet(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID, slug := setupDynamicBackend(t, db)
	backend, _ := db.GetDynamicBackend(ctx, projectID, envID, slug)

	db.SetDynamicRole(ctx, backend.ID, "ro", "C", "D", nil)
	role, _ := db.GetDynamicRole(ctx, backend.ID, "ro")

	exp := time.Now().UTC().Add(time.Hour)
	l, err := db.CreateDynamicLease(ctx, projectID, envID, backend.ID, role.ID, "ro", "usr123", "DROP USER ...", exp, nil)
	if err != nil {
		t.Fatalf("CreateDynamicLease: %v", err)
	}
	if l.ID == "" || l.Username != "usr123" {
		t.Errorf("unexpected lease: %+v", l)
	}

	// GetDynamicLease — found.
	got, err := db.GetDynamicLease(ctx, l.ID)
	if err != nil {
		t.Fatalf("GetDynamicLease: %v", err)
	}
	if got.Username != "usr123" {
		t.Errorf("username = %q, want usr123", got.Username)
	}

	// GetDynamicLease — not found.
	_, err = db.GetDynamicLease(ctx, "no-such")
	if err != store.ErrNotFound {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}
}

// TestDynamicLease_ListAndRevoke tests ListDynamicLeases and RevokeDynamicLease.
func TestDynamicLease_ListAndRevoke(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID, slug := setupDynamicBackend(t, db)
	backend, _ := db.GetDynamicBackend(ctx, projectID, envID, slug)
	db.SetDynamicRole(ctx, backend.ID, "ro", "C", "D", nil)
	role, _ := db.GetDynamicRole(ctx, backend.ID, "ro")

	exp := time.Now().UTC().Add(time.Hour)
	l1, _ := db.CreateDynamicLease(ctx, projectID, envID, backend.ID, role.ID, "ro", "user1", "DROP ...", exp, nil)
	l2, _ := db.CreateDynamicLease(ctx, projectID, envID, backend.ID, role.ID, "ro", "user2", "DROP ...", exp, nil)

	leases, err := db.ListDynamicLeases(ctx, projectID, envID)
	if err != nil || len(leases) != 2 {
		t.Errorf("ListDynamicLeases: len=%d err=%v", len(leases), err)
	}

	// Revoke l1.
	if err := db.RevokeDynamicLease(ctx, l1.ID); err != nil {
		t.Errorf("RevokeDynamicLease: %v", err)
	}
	// Already revoked → ErrNotFound.
	if err := db.RevokeDynamicLease(ctx, l1.ID); err != store.ErrNotFound {
		t.Errorf("already revoked: got %v, want ErrNotFound", err)
	}

	// l2 not revoked → not found by name.
	_ = l2
}

// TestDynamicLease_ListExpired tests ListExpiredDynamicLeases.
func TestDynamicLease_ListExpired(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID, slug := setupDynamicBackend(t, db)
	backend, _ := db.GetDynamicBackend(ctx, projectID, envID, slug)
	db.SetDynamicRole(ctx, backend.ID, "ro", "C", "D", nil)
	role, _ := db.GetDynamicRole(ctx, backend.ID, "ro")

	// Past expiry — should appear in ListExpiredDynamicLeases.
	pastExp := time.Now().UTC().Add(-time.Hour)
	l, err := db.CreateDynamicLease(ctx, projectID, envID, backend.ID, role.ID, "ro", "expired-user", "DROP ...", pastExp, nil)
	if err != nil {
		t.Fatalf("CreateDynamicLease expired: %v", err)
	}

	expired, err := db.ListExpiredDynamicLeases(ctx)
	if err != nil {
		t.Fatalf("ListExpiredDynamicLeases: %v", err)
	}
	found := false
	for _, e := range expired {
		if e.ID == l.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected lease %q in expired list", l.ID)
	}
}
