package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// ownerStore is a store pre-wired for a single owner on testProjID.
func ownerStore() *mockStore {
	return &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleOwner}, nil
		},
		createAuditLog: func(_ context.Context, _ *model.AuditLog) error { return nil },
	}
}

// ── validRole ─────────────────────────────────────────────────────────────────

func TestValidRole(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{model.RoleViewer, true},
		{model.RoleEditor, true},
		{model.RoleOwner, true},
		{"admin", false},
		{"superuser", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := validRole(tc.role); got != tc.want {
			t.Errorf("validRole(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}
}

// ── handleListMembers ─────────────────────────────────────────────────────────

func TestHandleListMembers_OK(t *testing.T) {
	uid := "member-user"
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember, Email: id + "@example.com"}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleViewer}, nil
		},
		listProjectMembers: func(_ context.Context, _ string) ([]*model.ProjectMember, error) {
			return []*model.ProjectMember{{UserID: uid, Role: model.RoleViewer}}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListMembers, http.MethodGet, "/", "", ownerTok(), "project", testProjSlug)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []memberResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 || resp[0].UserID != uid {
		t.Errorf("unexpected response: %+v", resp)
	}
}

// ── handleAddMember ───────────────────────────────────────────────────────────

func TestHandleAddMember_OK(t *testing.T) {
	added := false
	st := ownerStore()
	st.addProjectMember = func(_ context.Context, _, _, _ string, _ *string) error {
		added = true
		return nil
	}
	srv := newTestServer(t, st)
	body := `{"user_id":"target-user","role":"editor"}`
	w := call(t, srv.handleAddMember, http.MethodPost, "/", body, ownerTok(), "project", testProjSlug)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body)
	}
	if !added {
		t.Error("AddProjectMember was not called")
	}
}

func TestHandleAddMember_InvalidRole(t *testing.T) {
	srv := newTestServer(t, ownerStore())
	body := `{"user_id":"target","role":"superuser"}`
	w := call(t, srv.handleAddMember, http.MethodPost, "/", body, ownerTok(), "project", testProjSlug)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleAddMember_UserNotFound(t *testing.T) {
	st := ownerStore()
	// Override getUserByID to return not-found for any non-ownerTok user.
	st.getUserByID = func(_ context.Context, id string) (*model.User, error) {
		if id == testUserID {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		}
		return nil, store.ErrNotFound
	}

	srv := newTestServer(t, st)
	body := `{"user_id":"ghost-user","role":"viewer"}`
	w := call(t, srv.handleAddMember, http.MethodPost, "/", body, ownerTok(), "project", testProjSlug)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleAddMember_MissingUserID(t *testing.T) {
	srv := newTestServer(t, ownerStore())
	w := call(t, srv.handleAddMember, http.MethodPost, "/", `{"role":"viewer"}`, ownerTok(), "project", testProjSlug)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ── handleUpdateMember ────────────────────────────────────────────────────────

func TestHandleUpdateMember_OK(t *testing.T) {
	updated := false
	st := ownerStore()
	st.updateProjectMember = func(_ context.Context, _, _, _ string, _ *string) error {
		updated = true
		return nil
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleUpdateMember, http.MethodPut, "/", `{"role":"editor"}`, ownerTok(),
		"project", testProjSlug, "user_id", "target-user")

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body)
	}
	if !updated {
		t.Error("UpdateProjectMember was not called")
	}
}

func TestHandleUpdateMember_NotFound(t *testing.T) {
	st := ownerStore()
	st.updateProjectMember = func(_ context.Context, _, _, _ string, _ *string) error {
		return store.ErrNotFound
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleUpdateMember, http.MethodPut, "/", `{"role":"viewer"}`, ownerTok(),
		"project", testProjSlug, "user_id", "ghost")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleUpdateMember_InvalidRole(t *testing.T) {
	srv := newTestServer(t, ownerStore())
	w := call(t, srv.handleUpdateMember, http.MethodPut, "/", `{"role":"god"}`, ownerTok(),
		"project", testProjSlug, "user_id", "u1")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ── handleRemoveMember ────────────────────────────────────────────────────────

func TestHandleRemoveMember_OK(t *testing.T) {
	removed := false
	st := ownerStore()
	st.removeProjectMember = func(_ context.Context, _, _ string, _ *string) error {
		removed = true
		return nil
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleRemoveMember, http.MethodDelete, "/", "", ownerTok(),
		"project", testProjSlug, "user_id", "target-user")

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if !removed {
		t.Error("RemoveProjectMember was not called")
	}
}

func TestHandleRemoveMember_NotFound(t *testing.T) {
	st := ownerStore()
	st.removeProjectMember = func(_ context.Context, _, _ string, _ *string) error {
		return store.ErrNotFound
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleRemoveMember, http.MethodDelete, "/", "", ownerTok(),
		"project", testProjSlug, "user_id", "ghost")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
