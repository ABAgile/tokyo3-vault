package auth

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/abagile/tokyo3-vault/internal/testutil/mockstore"
)

// ── minimal mock store ────────────────────────────────────────────────────────

// mockStore embeds mockstore.Stub for all no-op defaults and adds an in-memory
// token map so IssueUserToken / IssueMachineToken / Validate work end-to-end.
type mockStore struct {
	mockstore.Stub
	tokens    map[string]*model.Token
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
