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

// ── handleListTokens ──────────────────────────────────────────────────────────

func TestHandleListTokens_OK(t *testing.T) {
	uid := testUserID
	tok1 := &model.Token{ID: "t1", Name: "ci", UserID: &uid, CreatedAt: time.Now()}
	st := &mockStore{
		listTokens: func(_ context.Context, userID string) ([]*model.Token, error) {
			return []*model.Token{tok1}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListTokens, http.MethodGet, "/", "", ownerTok())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []tokenListItem
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 || resp[0].ID != "t1" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestHandleListTokens_MachineTokenRejected(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleListTokens, http.MethodGet, "/", "", machineToken(testProjID, "", false))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── handleCreateToken ─────────────────────────────────────────────────────────

func TestHandleCreateToken_Unscoped(t *testing.T) {
	st := &mockStore{
		createToken: func(_ context.Context, _ *model.Token) error { return nil },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleCreateToken, http.MethodPost, "/", `{"name":"ci-deploy"}`, ownerTok())

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body)
	}
	var resp createTokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("raw token is empty")
	}
}

func TestHandleCreateToken_ScopedToProject(t *testing.T) {
	var capturedProjectID string
	st := &mockStore{
		getProject: func(_ context.Context, slug string) (*model.Project, error) {
			if slug == testProjSlug {
				return testProject(), nil
			}
			return nil, store.ErrNotFound
		},
		createToken: func(_ context.Context, t *model.Token) error {
			if t.ProjectID != nil {
				capturedProjectID = *t.ProjectID
			}
			return nil
		},
	}
	srv := newTestServer(t, st)
	body := `{"name":"deploy","project":"` + testProjSlug + `"}`
	w := call(t, srv.handleCreateToken, http.MethodPost, "/", body, ownerTok())

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body)
	}
	if capturedProjectID != testProjID {
		t.Errorf("projectID = %q, want %q", capturedProjectID, testProjID)
	}
}

func TestHandleCreateToken_ScopedToProjectAndEnv(t *testing.T) {
	var capturedEnvID string
	st := &mockStore{
		getProject: func(_ context.Context, _ string) (*model.Project, error) {
			return testProject(), nil
		},
		getEnvironment: func(_ context.Context, _, _ string) (*model.Environment, error) {
			return &model.Environment{ID: testEnvID, Slug: testEnvSlug}, nil
		},
		createToken: func(_ context.Context, t *model.Token) error {
			if t.EnvID != nil {
				capturedEnvID = *t.EnvID
			}
			return nil
		},
	}
	srv := newTestServer(t, st)
	body := `{"name":"ci","project":"` + testProjSlug + `","env":"` + testEnvSlug + `"}`
	w := call(t, srv.handleCreateToken, http.MethodPost, "/", body, ownerTok())

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body)
	}
	if capturedEnvID != testEnvID {
		t.Errorf("envID = %q, want %q", capturedEnvID, testEnvID)
	}
}

func TestHandleCreateToken_ProjectNotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{
		// getProject left nil → ErrNotFound
	})
	body := `{"name":"ci","project":"nonexistent"}`
	w := call(t, srv.handleCreateToken, http.MethodPost, "/", body, ownerTok())
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleCreateToken_InvalidExpiry(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleCreateToken, http.MethodPost, "/", `{"name":"x","expires_in":"not-a-duration"}`, ownerTok())
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleCreateToken_MissingName(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleCreateToken, http.MethodPost, "/", `{"name":""}`, ownerTok())
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleCreateToken_ReadOnly(t *testing.T) {
	var capturedReadOnly bool
	st := &mockStore{
		createToken: func(_ context.Context, t *model.Token) error {
			capturedReadOnly = t.ReadOnly
			return nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleCreateToken, http.MethodPost, "/", `{"name":"ro","read_only":true}`, ownerTok())
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if !capturedReadOnly {
		t.Error("token was not created as read-only")
	}
}

// ── handleDeleteToken ─────────────────────────────────────────────────────────

func TestHandleDeleteToken_OK(t *testing.T) {
	deleted := false
	st := &mockStore{
		deleteToken: func(_ context.Context, _, _ string) error { deleted = true; return nil },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteToken, http.MethodDelete, "/", "", ownerTok(), "id", "tok-to-delete")

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if !deleted {
		t.Error("DeleteToken was not called")
	}
}

func TestHandleDeleteToken_NotFound(t *testing.T) {
	st := &mockStore{
		deleteToken: func(_ context.Context, _, _ string) error { return store.ErrNotFound },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteToken, http.MethodDelete, "/", "", ownerTok(), "id", "ghost")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
