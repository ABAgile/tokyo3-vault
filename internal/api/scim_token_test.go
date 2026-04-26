package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// TestHandleCreateSCIMToken tests the SCIM token creation handler.
func TestHandleCreateSCIMToken(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "valid",
			body:       `{"description":"IdP provisioner"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "missing description",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid JSON",
			body:       `{bad`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := adminStore()
			srv := newTestServer(t, st)
			w := call(t, srv.handleCreateSCIMToken, http.MethodPost, "/", tc.body, adminTok())
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// TestHandleListSCIMTokens tests the SCIM token list handler.
func TestHandleListSCIMTokens(t *testing.T) {
	st := adminStore()
	// Default stub returns nil, nil for ListSCIMTokens.
	srv := newTestServer(t, st)
	w := call(t, srv.handleListSCIMTokens, http.MethodGet, "/", "", adminTok())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
}

// TestHandleDeleteSCIMToken tests the SCIM token delete handler.
func TestHandleDeleteSCIMToken(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name:       "success",
			wantStatus: http.StatusNoContent,
		},
		{
			name: "not found",
			setup: func(m *mockStore) {
				m.deleteSCIMToken = func(_ context.Context, _ string) error { return store.ErrNotFound }
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "db error",
			setup: func(m *mockStore) {
				m.deleteSCIMToken = func(_ context.Context, _ string) error { return errDB }
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := adminStore()
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleDeleteSCIMToken, http.MethodDelete, "/", "", adminTok(), "id", "scim-tok-1")
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// TestHandleListSCIMTokens_WithData tests with actual token data.
func TestHandleListSCIMTokens_WithData(t *testing.T) {
	now := time.Now().UTC()
	_ = now

	// Non-admin should get 403. Use baseStore() which returns UserRoleMember.
	st := baseStore()
	srv := newTestServer(t, st)
	w := call(t, srv.handleListSCIMTokens, http.MethodGet, "/", "", ownerTok())
	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", w.Code)
	}

	// Test that ListSCIMTokens response includes at least an empty list.
	st2 := adminStore()
	srv2 := newTestServer(t, st2)
	w2 := call(t, srv2.handleListSCIMTokens, http.MethodGet, "/", "", adminTok())
	if w2.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200", w2.Code)
	}
	var out []map[string]string
	if err := json.NewDecoder(w2.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	_ = out

	// Build a mock with a response for list.
	st3 := adminStore()
	st3.listSCIMTokens = func(_ context.Context) ([]*model.SCIMToken, error) {
		return []*model.SCIMToken{
			{ID: "s1", Description: "Okta", CreatedAt: time.Now().UTC()},
		}, nil
	}
	srv3 := newTestServer(t, st3)
	w3 := call(t, srv3.handleListSCIMTokens, http.MethodGet, "/", "", adminTok())
	if w3.Code != http.StatusOK {
		t.Fatalf("status = %d", w3.Code)
	}
}
