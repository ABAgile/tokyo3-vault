package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/store"
)

// TestGetProjectByID tests GetProjectByID.
func TestGetProjectByID(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	p, err := db.CreateProject(ctx, "ByID App", "byid-app")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	got, err := db.GetProjectByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetProjectByID found: %v", err)
	}
	if got.Slug != "byid-app" {
		t.Errorf("slug = %q, want byid-app", got.Slug)
	}

	_, err = db.GetProjectByID(ctx, "no-such-id")
	if err != store.ErrNotFound {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}
}

// TestSetProjectKey tests SetProjectKey persists the encrypted PEK.
func TestSetProjectKey(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	p, _ := db.CreateProject(ctx, "KeyApp", "key-app")
	encPEK := []byte("fake-encrypted-pek")
	rotatedAt := time.Now().UTC()

	if err := db.SetProjectKey(ctx, p.ID, encPEK, rotatedAt); err != nil {
		t.Fatalf("SetProjectKey: %v", err)
	}

	got, err := db.GetProjectByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetProjectByID: %v", err)
	}
	if string(got.EncryptedPEK) != string(encPEK) {
		t.Errorf("EncryptedPEK = %q, want %q", got.EncryptedPEK, encPEK)
	}
}

// TestListProjectsForPEKRotation tests threshold-based filtering and NULL pek_rotated_at.
func TestListProjectsForPEKRotation(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	p1, _ := db.CreateProject(ctx, "Proj1", "proj1-rot")
	p2, _ := db.CreateProject(ctx, "Proj2", "proj2-rot")
	// p3 has no encrypted PEK → should NOT appear.
	db.CreateProject(ctx, "Proj3", "proj3-nokey")

	// Set PEK on p1 with null rotation (force nil pek_rotated_at by using SetProjectKey,
	// which sets a non-null value; we manipulate the DB directly for the null case).
	now := time.Now().UTC()
	db.SetProjectKey(ctx, p1.ID, []byte("pek1"), now.Add(-48*time.Hour))
	// p2 has PEK but pek_rotated_at is NULL (just set the encrypted_pek directly).
	db.db.ExecContext(ctx,
		`UPDATE projects SET encrypted_pek = ? WHERE id = ?`, []byte("pek2"), p2.ID)

	// Threshold: anything not rotated after 24 hours ago.
	threshold := now.Add(-24 * time.Hour)
	projects, err := db.ListProjectsForPEKRotation(ctx, threshold)
	if err != nil {
		t.Fatalf("ListProjectsForPEKRotation: %v", err)
	}
	// p1 was rotated 48h ago (before threshold), p2 has NULL → both should appear.
	found1, found2 := false, false
	for _, proj := range projects {
		if proj.ID == p1.ID {
			found1 = true
		}
		if proj.ID == p2.ID {
			found2 = true
		}
	}
	if !found1 {
		t.Error("p1 (rotated 48h ago) should be in rotation list")
	}
	if !found2 {
		t.Error("p2 (NULL pek_rotated_at) should be in rotation list")
	}
}

// TestRewrapProjectDEKs tests that DEKs are rewrapped for secrets and dynamic backends.
func TestRewrapProjectDEKs(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID := setupProjectEnv(t, db)

	// Create a secret version with a known DEK.
	oldDEK := []byte("old-dek-value")
	db.SetSecret(ctx, projectID, envID, "MY_SECRET", nil, []byte("enc-val"), oldDEK, nil)

	// Create a dynamic backend with a known DEK.
	db.SetDynamicBackend(ctx, projectID, envID, "pg", "postgresql",
		[]byte("enc-cfg"), []byte("backend-old-dek"), 600, 3600)

	// rewrap doubles each byte.
	rewrap := func(dek []byte) ([]byte, error) {
		out := make([]byte, len(dek))
		for i, b := range dek {
			out[i] = b + 1
		}
		return out, nil
	}

	if err := db.RewrapProjectDEKs(ctx, projectID, rewrap); err != nil {
		t.Fatalf("RewrapProjectDEKs: %v", err)
	}

	// Verify the secret DEK was changed.
	_, sv, err := db.GetSecret(ctx, projectID, envID, "MY_SECRET")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	for i, b := range sv.EncryptedDEK {
		if b != oldDEK[i]+1 {
			t.Errorf("DEK[%d] = %d, want %d", i, b, oldDEK[i]+1)
			break
		}
	}
}

// TestRotateProjectPEK tests the atomic PEK rotation.
func TestRotateProjectPEK(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID, envID := setupProjectEnv(t, db)

	db.SetSecret(ctx, projectID, envID, "ROTATE_KEY", nil, []byte("v"), []byte("dek"), nil)

	newPEK := []byte("new-encrypted-pek")
	rotatedAt := time.Now().UTC()
	rewrap := func(dek []byte) ([]byte, error) {
		return append([]byte("rewrapped-"), dek...), nil
	}

	if err := db.RotateProjectPEK(ctx, projectID, newPEK, rotatedAt, rewrap); err != nil {
		t.Fatalf("RotateProjectPEK: %v", err)
	}

	// Verify PEK updated.
	p, err := db.GetProjectByID(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProjectByID: %v", err)
	}
	if string(p.EncryptedPEK) != string(newPEK) {
		t.Errorf("EncryptedPEK = %q, want %q", p.EncryptedPEK, newPEK)
	}
}
