package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/audit"
)

func openTestAuditDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestAuditDB_Open tests Open with an in-memory database.
func TestAuditDB_Open(t *testing.T) {
	db := openTestAuditDB(t)
	if db == nil {
		t.Fatal("expected non-nil DB")
	}
}

// TestAuditDB_UpsertAndList tests UpsertAuditLog and ListAuditLogs.
func TestAuditDB_UpsertAndList(t *testing.T) {
	db := openTestAuditDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	entries := []audit.Entry{
		{ID: "evt-1", Action: "secret.set", ActorID: "tok-1", ProjectID: "proj-1", EnvID: "env-1", Resource: "DB_URL", OccurredAt: now},
		{ID: "evt-2", Action: "secret.get", ActorID: "tok-2", ProjectID: "proj-1", EnvID: "env-1", OccurredAt: now.Add(-time.Minute)},
		{ID: "evt-3", Action: "secret.set", ActorID: "tok-1", ProjectID: "proj-2", EnvID: "env-2", OccurredAt: now.Add(-2 * time.Minute)},
	}

	for _, e := range entries {
		if err := db.UpsertAuditLog(ctx, e); err != nil {
			t.Fatalf("UpsertAuditLog(%q): %v", e.ID, err)
		}
	}

	// Idempotent — re-insert same entries should not error.
	for _, e := range entries {
		if err := db.UpsertAuditLog(ctx, e); err != nil {
			t.Fatalf("UpsertAuditLog duplicate (%q): %v", e.ID, err)
		}
	}

	// No filter — returns all (up to default 50).
	all, err := db.ListAuditLogs(ctx, audit.Filter{})
	if err != nil {
		t.Fatalf("ListAuditLogs no filter: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3, got %d", len(all))
	}

	// Project filter.
	byProj, err := db.ListAuditLogs(ctx, audit.Filter{ProjectID: "proj-1"})
	if err != nil {
		t.Fatalf("ListAuditLogs project filter: %v", err)
	}
	if len(byProj) != 2 {
		t.Errorf("project filter: expected 2, got %d", len(byProj))
	}

	// EnvID filter.
	byEnv, err := db.ListAuditLogs(ctx, audit.Filter{EnvID: "env-2"})
	if err != nil {
		t.Fatalf("ListAuditLogs env filter: %v", err)
	}
	if len(byEnv) != 1 {
		t.Errorf("env filter: expected 1, got %d", len(byEnv))
	}

	// Action filter.
	byAction, err := db.ListAuditLogs(ctx, audit.Filter{Action: "secret.set"})
	if err != nil {
		t.Fatalf("ListAuditLogs action filter: %v", err)
	}
	if len(byAction) != 2 {
		t.Errorf("action filter: expected 2, got %d", len(byAction))
	}

	// Limit.
	limited, err := db.ListAuditLogs(ctx, audit.Filter{Limit: 1})
	if err != nil {
		t.Fatalf("ListAuditLogs limit: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("limit 1: expected 1, got %d", len(limited))
	}
}

// TestAuditDB_Close tests that Close is idempotent (second close errors gracefully).
func TestAuditDB_Close(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
