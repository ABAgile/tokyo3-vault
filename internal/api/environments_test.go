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

func testEnv() *model.Environment {
	return &model.Environment{
		ID: testEnvID, ProjectID: testProjID, Name: "Production",
		Slug: testEnvSlug, CreatedAt: time.Now(),
	}
}

// ── handleListEnvs ────────────────────────────────────────────────────────────

func TestHandleListEnvs_OK(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleViewer}, nil
		},
		listEnvironments: func(_ context.Context, _ string) ([]*model.Environment, error) {
			return []*model.Environment{testEnv()}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListEnvs, http.MethodGet, "/", "", ownerTok(), "project", testProjSlug)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []envResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 || resp[0].Slug != testEnvSlug {
		t.Errorf("unexpected resp: %+v", resp)
	}
}

func TestHandleListEnvs_ProjectNotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleListEnvs, http.MethodGet, "/", "", ownerTok(), "project", "missing")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── handleCreateEnv ───────────────────────────────────────────────────────────

func TestHandleCreateEnv_OK(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleOwner}, nil
		},
		createEnvironment: func(_ context.Context, _, name, slug string) (*model.Environment, error) {
			return &model.Environment{
				ID: "new-env", ProjectID: testProjID, Name: name, Slug: slug,
			}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleCreateEnv, http.MethodPost, "/",
		`{"name":"Staging","slug":"staging"}`, ownerTok(), "project", testProjSlug)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body)
	}
	var resp envResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Slug != "staging" {
		t.Errorf("slug = %q, want staging", resp.Slug)
	}
}

func TestHandleCreateEnv_Conflict(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleOwner}, nil
		},
		createEnvironment: func(_ context.Context, _, _, _ string) (*model.Environment, error) {
			return nil, store.ErrConflict
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleCreateEnv, http.MethodPost, "/",
		`{"name":"Production","slug":"production"}`, ownerTok(), "project", testProjSlug)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestHandleCreateEnv_InvalidSlug(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleOwner}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleCreateEnv, http.MethodPost, "/",
		`{"name":"Bad","slug":"UPPER_SLUG"}`, ownerTok(), "project", testProjSlug)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ── handleDeleteEnv ───────────────────────────────────────────────────────────

func TestHandleDeleteEnv_OK(t *testing.T) {
	deleted := false
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleOwner}, nil
		},
		deleteEnvironment: func(_ context.Context, _, _ string) error {
			deleted = true
			return nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteEnv, http.MethodDelete, "/", "", ownerTok(),
		"project", testProjSlug, "env", testEnvSlug)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if !deleted {
		t.Error("DeleteEnvironment was not called")
	}
}

func TestHandleDeleteEnv_NotFound(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleOwner}, nil
		},
		deleteEnvironment: func(_ context.Context, _, _ string) error {
			return store.ErrNotFound
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteEnv, http.MethodDelete, "/", "", ownerTok(),
		"project", testProjSlug, "env", "missing")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
