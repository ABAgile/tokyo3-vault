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

func testProject() *model.Project {
	return &model.Project{ID: testProjID, Name: "My App", Slug: testProjSlug, CreatedAt: time.Now()}
}

// ── handleListProjects ────────────────────────────────────────────────────────

func TestHandleListProjects_ReturnsProjects(t *testing.T) {
	st := &mockStore{
		listProjectsByMember: func(_ context.Context, _ string) ([]*model.Project, error) {
			return []*model.Project{testProject()}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListProjects, http.MethodGet, "/", "", ownerTok())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []projectResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 || resp[0].Slug != testProjSlug {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestHandleListProjects_ScopedTokenRejected(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleListProjects, http.MethodGet, "/", "", machineToken(testProjID, "", false))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── handleCreateProject ───────────────────────────────────────────────────────

func TestHandleCreateProject_OK(t *testing.T) {
	st := &mockStore{
		createProject: func(_ context.Context, name, slug string) (*model.Project, error) {
			return &model.Project{ID: "new-p", Name: name, Slug: slug}, nil
		},
		addProjectMember: func(_ context.Context, _, _, _ string, _ *string) error { return nil },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleCreateProject, http.MethodPost, "/", `{"name":"My App","slug":"my-app"}`, ownerTok())

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body)
	}
	var resp projectResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Slug != "my-app" {
		t.Errorf("slug = %q, want %q", resp.Slug, "my-app")
	}
}

func TestHandleCreateProject_SlugDerived(t *testing.T) {
	var capturedSlug string
	st := &mockStore{
		createProject: func(_ context.Context, _, slug string) (*model.Project, error) {
			capturedSlug = slug
			return &model.Project{ID: "p1", Name: "Hello World", Slug: slug}, nil
		},
		addProjectMember: func(_ context.Context, _, _, _ string, _ *string) error { return nil },
	}
	srv := newTestServer(t, st)
	// No slug provided — should be derived from name.
	w := call(t, srv.handleCreateProject, http.MethodPost, "/", `{"name":"Hello World"}`, ownerTok())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if capturedSlug == "" {
		t.Error("slug was not derived from name")
	}
}

func TestHandleCreateProject_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		code int
	}{
		{"empty name", `{"name":"","slug":"my-app"}`, http.StatusBadRequest},
		{"invalid slug", `{"name":"ok","slug":"has_underscore"}`, http.StatusBadRequest},
		{"slug too short", `{"name":"ok","slug":"a"}`, http.StatusBadRequest},
		{"conflict", `{"name":"ok","slug":"my-app"}`, http.StatusConflict},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mockStore{
				createProject: func(_ context.Context, _, _ string) (*model.Project, error) {
					if tc.code == http.StatusConflict {
						return nil, store.ErrConflict
					}
					return nil, nil
				},
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleCreateProject, http.MethodPost, "/", tc.body, ownerTok())
			if w.Code != tc.code {
				t.Errorf("status = %d, want %d", w.Code, tc.code)
			}
		})
	}
}

// ── handleGetProject ──────────────────────────────────────────────────────────

func TestHandleGetProject_OK(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, slug string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleViewer}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleGetProject, http.MethodGet, "/", "", ownerTok(), "project", testProjSlug)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp projectResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Slug != testProjSlug {
		t.Errorf("slug = %q", resp.Slug)
	}
}

func TestHandleGetProject_NotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleGetProject, http.MethodGet, "/", "", ownerTok(), "project", "missing")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── handleDeleteProject ───────────────────────────────────────────────────────

func TestHandleDeleteProject_OK(t *testing.T) {
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
		deleteProject: func(_ context.Context, _ string) error { deleted = true; return nil },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteProject, http.MethodDelete, "/", "", ownerTok(), "project", testProjSlug)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204; body: %s", w.Code, w.Body)
	}
	if !deleted {
		t.Error("DeleteProject was not called")
	}
}

func TestHandleDeleteProject_NonOwnerRejected(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, _, _ string) (*model.ProjectMember, error) {
			return &model.ProjectMember{Role: model.RoleEditor}, nil // editor, not owner
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteProject, http.MethodDelete, "/", "", ownerTok(), "project", testProjSlug)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── toSlug ────────────────────────────────────────────────────────────────────

func TestToSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"My App", "my-app"},
		{"hello world", "hello-world"},
		{"  spaces  ", "spaces"},
		{"UPPER CASE", "upper-case"},
		{"multiple---hyphens", "multiple-hyphens"},
		{"a", "ax"}, // padded to min length 2
		{"special!@#chars", "special-chars"},
	}

	for _, tc := range tests {
		got := toSlug(tc.input)
		if got != tc.want {
			t.Errorf("toSlug(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
