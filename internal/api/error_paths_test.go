package api

// error_paths_test.go covers the internal-server-error and "not found" branches
// that the happy-path tests leave uncovered. Each test forces the relevant mock
// field to return an unexpected error so that the handler writes a 500 (or 404
// for the "project not found" variants), confirming those branches execute.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// errDB is an arbitrary store error that is neither ErrNotFound nor ErrConflict.
var errDB = errors.New("db error")

// ── environments ──────────────────────────────────────────────────────────────

func TestHandleCreateEnv_ProjectNotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleCreateEnv, http.MethodPost, "/", `{"name":"Dev","slug":"dev"}`, ownerTok(), "project", "missing")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleDeleteEnv_ProjectNotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleDeleteEnv, http.MethodDelete, "/", "", ownerTok(), "project", "missing", "env", "dev")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── members ───────────────────────────────────────────────────────────────────

func TestHandleListMembers_ProjectNotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleListMembers, http.MethodGet, "/", "", ownerTok(), "project", "missing")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleAddMember_ProjectNotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleAddMember, http.MethodPost, "/", `{"user_id":"u1","role":"viewer"}`, ownerTok(), "project", "missing")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleUpdateMember_ProjectNotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleUpdateMember, http.MethodPut, "/", `{"role":"viewer"}`, ownerTok(), "project", "missing", "user_id", "u1")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleRemoveMember_ProjectNotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleRemoveMember, http.MethodDelete, "/", "", ownerTok(), "project", "missing", "user_id", "u1")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── projects ──────────────────────────────────────────────────────────────────

func TestHandleGetProject_InternalError(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) { return nil, errDB },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleGetProject, http.MethodGet, "/", "", ownerTok(), "project", testProjSlug)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleDeleteProject_NotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleDeleteProject, http.MethodDelete, "/", "", ownerTok(), "project", "missing")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleDeleteProject_DeleteError(t *testing.T) {
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
		deleteProject: func(_ context.Context, _ string) error { return errDB },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteProject, http.MethodDelete, "/", "", ownerTok(), "project", testProjSlug)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleListProjects_StoreError(t *testing.T) {
	st := &mockStore{
		listProjectsByMember: func(_ context.Context, _ string) ([]*model.Project, error) { return nil, errDB },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListProjects, http.MethodGet, "/", "", ownerTok())
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ── resolveProjectEnv / secrets ───────────────────────────────────────────────

func TestHandleListSecrets_EnvNotFound(t *testing.T) {
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
		// getEnvironment left nil → ErrNotFound
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListSecrets, http.MethodGet, "/", "", ownerTok(), secretPV()...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleDeleteSecret_StoreError(t *testing.T) {
	st := baseStore()
	st.deleteSecret = func(_ context.Context, _, _, _ string) error { return errDB }
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteSecret, http.MethodDelete, "/", "", ownerTok(), secretPV("key", "OLD_KEY")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleListSecretVersions_StoreError(t *testing.T) {
	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "sec-1", Key: key}, nil, nil
	}
	st.listSecretVersions = func(_ context.Context, _ string) ([]*model.SecretVersion, error) {
		return nil, errDB
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListSecretVersions, http.MethodGet, "/", "", ownerTok(), secretPV("key", "MY_KEY")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ── resolveTokenScope (tokens) ────────────────────────────────────────────────

func TestHandleCreateToken_ScopedProjectOnlyNoEnv(t *testing.T) {
	// Providing a project slug but no env slug → resolveTokenScope returns
	// projectID with empty envID (the early-return branch at "envSlug == ''").
	var capturedEnvID *string
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		createToken: func(_ context.Context, t *model.Token) error {
			capturedEnvID = t.EnvID
			return nil
		},
	}
	srv := newTestServer(t, st)
	body := `{"name":"ci","project":"` + testProjSlug + `"}`
	w := call(t, srv.handleCreateToken, http.MethodPost, "/", body, ownerTok())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body)
	}
	if capturedEnvID != nil {
		t.Errorf("envID should be nil for project-only scope, got %v", capturedEnvID)
	}
}

func TestHandleCreateToken_EnvNotFound(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		// getEnvironment left nil → ErrNotFound
	}
	srv := newTestServer(t, st)
	body := `{"name":"ci","project":"` + testProjSlug + `","env":"missing-env"}`
	w := call(t, srv.handleCreateToken, http.MethodPost, "/", body, ownerTok())
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── resolveSrcProjectEnv (import) ─────────────────────────────────────────────

func TestHandleImportSecrets_SourceEnvNotFound(t *testing.T) {
	st := baseStore()
	st.getProject = func(_ context.Context, slug string) (*model.Project, error) {
		return &model.Project{ID: testProjID, Slug: slug}, nil
	}
	st.getEnvironment = func(_ context.Context, _, slug string) (*model.Environment, error) {
		if slug == testEnvSlug {
			return &model.Environment{ID: testEnvID, Slug: slug}, nil
		}
		return nil, store.ErrNotFound
	}

	srv := newTestServer(t, st)
	body := `{"from_project":"myapp","from_env":"missing-env","overwrite":false,"keys":[]}`
	w := call(t, srv.handleImportSecrets, http.MethodPost, "/", body, ownerTok(), secretPV()...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── audit logs ────────────────────────────────────────────────────────────────

func TestHandleListAuditLogs_ProjectNotFound(t *testing.T) {
	st := &mockStore{
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleAdmin}, nil
		},
		// getProject left nil → ErrNotFound
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListAuditLogs, http.MethodGet, "/?project=missing", "", ownerTok())
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleListAuditLogs_StoreError(t *testing.T) {
	st := &mockStore{
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleAdmin}, nil
		},
	}
	as := &mockAuditStore{
		listAuditLogs: func(_ context.Context, _ audit.Filter) ([]*model.AuditLog, error) {
			return nil, errDB
		},
	}
	srv := newTestServerWithAudit(t, st, as)
	w := call(t, srv.handleListAuditLogs, http.MethodGet, "/", "", ownerTok())
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleListAuditLogs_ProjectScopedOwner(t *testing.T) {
	// Project-scoped audit list for a project owner (non-admin).
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
	srv := newTestServerWithAudit(t, st, &mockAuditStore{})
	w := call(t, srv.handleListAuditLogs, http.MethodGet, "/?project="+testProjSlug, "", ownerTok())
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
}
