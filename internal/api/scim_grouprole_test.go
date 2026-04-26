package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// TestIsValidGroupRole tests the isValidGroupRole helper.
func TestIsValidGroupRole(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{model.RoleViewer, true},
		{model.RoleEditor, true},
		{model.RoleOwner, true},
		{"superadmin", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := isValidGroupRole(tc.role); got != tc.want {
			t.Errorf("isValidGroupRole(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}
}

// TestHandleCreateSCIMGroupRole tests the SCIM group role creation handler.
func TestHandleCreateSCIMGroupRole(t *testing.T) {
	now := model.SCIMGroupRole{ID: "gr-1", GroupID: "grp-123", DisplayName: "Engineers", Role: model.RoleEditor}
	_ = now

	tests := []struct {
		name       string
		body       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name: "valid with env",
			body: `{"group_id":"grp-1","project_slug":"myapp","env_slug":"prod","role":"editor"}`,
			setup: func(m *mockStore) {
				m.setSCIMGroupRole = func(_ context.Context, _, _ string, _, _ *string, _ string) (*model.SCIMGroupRole, error) {
					return &model.SCIMGroupRole{ID: "gr-1", GroupID: "grp-1", Role: model.RoleEditor}, nil
				}
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "valid without env",
			body: `{"group_id":"grp-2","project_slug":"myapp","role":"viewer"}`,
			setup: func(m *mockStore) {
				m.setSCIMGroupRole = func(_ context.Context, _, _ string, _, _ *string, _ string) (*model.SCIMGroupRole, error) {
					return &model.SCIMGroupRole{ID: "gr-2", GroupID: "grp-2", Role: model.RoleViewer}, nil
				}
			},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "missing required fields",
			body:       `{"group_id":"grp-1","role":"editor"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid role",
			body:       `{"group_id":"grp-1","project_slug":"myapp","role":"superadmin"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "project not found",
			body:       `{"group_id":"grp-1","project_slug":"no-such-project","role":"editor"}`,
			wantStatus: http.StatusNotFound,
		},
		{
			name: "env not found",
			body: `{"group_id":"grp-1","project_slug":"myapp","env_slug":"no-such-env","role":"editor"}`,
			setup: func(m *mockStore) {
				m.getEnvironment = func(_ context.Context, _, slug string) (*model.Environment, error) {
					return nil, store.ErrNotFound
				}
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "invalid JSON",
			body:       `{bad json`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := adminStore()
			// Wire up project/env resolution (needed by handleCreateSCIMGroupRole).
			st.getProject = baseStore().getProject
			st.getEnvironment = baseStore().getEnvironment
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleCreateSCIMGroupRole, http.MethodPost, "/", tc.body, adminTok())
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// TestHandleListSCIMGroupRoles tests the list handler.
func TestHandleListSCIMGroupRoles(t *testing.T) {
	st := adminStore()
	// Stub returns nil,nil for ListSCIMGroupRoles by default.
	srv := newTestServer(t, st)
	w := call(t, srv.handleListSCIMGroupRoles, http.MethodGet, "/", "", adminTok())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
}

// TestHandleDeleteSCIMGroupRole tests the delete handler.
func TestHandleDeleteSCIMGroupRole(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name:       "ok",
			wantStatus: http.StatusNoContent,
		},
		{
			name: "not found",
			setup: func(m *mockStore) {
				m.deleteSCIMGroupRole = func(_ context.Context, _ string) error { return store.ErrNotFound }
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "db error",
			setup: func(m *mockStore) {
				m.deleteSCIMGroupRole = func(_ context.Context, _ string) error { return errDB }
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
			w := call(t, srv.handleDeleteSCIMGroupRole, http.MethodDelete, "/", "", adminTok(), "id", "gr-1")
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// TestHandleListSCIMGroupRoles_DBError tests the list handler db error path.
func TestHandleListSCIMGroupRoles_DBError(t *testing.T) {
	st := adminStore()
	st.listSCIMGroupRoles = func(_ context.Context) ([]*model.SCIMGroupRole, error) {
		return nil, errDB
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListSCIMGroupRoles, http.MethodGet, "/", "", adminTok())
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}

// TestHandleListSCIMGroupRoles_WithData tests listing with actual data.
func TestHandleListSCIMGroupRoles_WithData(t *testing.T) {
	p := testProjID
	st := adminStore()
	st.listSCIMGroupRoles = func(_ context.Context) ([]*model.SCIMGroupRole, error) {
		return []*model.SCIMGroupRole{
			{ID: "gr-1", GroupID: "g1", DisplayName: "Eng", ProjectID: &p, Role: model.RoleEditor},
			{ID: "gr-2", GroupID: "g2", DisplayName: "Ops", Role: model.RoleViewer},
		}, nil
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListSCIMGroupRoles, http.MethodGet, "/", "", adminTok())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 2 {
		t.Errorf("len = %d, want 2", len(resp))
	}
}
