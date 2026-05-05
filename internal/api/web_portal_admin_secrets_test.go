package api

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	lcrypto "github.com/abagile/tokyo3-lcl/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// pAndE returns a project + environment that mockStore can hand back from
// getProject + getEnvironment so the lookup-then-act handlers can run.
func pAndE() (*model.Project, *model.Environment) {
	return &model.Project{ID: "p1", Slug: "demo"},
		&model.Environment{ID: "e1", ProjectID: "p1", Slug: "prod"}
}

func setProjectEnv(st *mockStore) {
	p, e := pAndE()
	st.getProject = func(_ context.Context, slug string) (*model.Project, error) {
		if slug != p.Slug {
			return nil, store.ErrNotFound
		}
		return p, nil
	}
	st.getEnvironment = func(_ context.Context, projectID, slug string) (*model.Environment, error) {
		if projectID != p.ID || slug != e.Slug {
			return nil, store.ErrNotFound
		}
		return e, nil
	}
}

// ── Secrets list ──────────────────────────────────────────────────────────────

func TestPortalAdminSecrets_GET_OK(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	st.listSecrets = func(_ context.Context, _, _ string) ([]*model.Secret, []*model.SecretVersion, error) {
		return []*model.Secret{{ID: "s1", Key: "DB_PASSWORD", UpdatedAt: time.Now()}},
			[]*model.SecretVersion{{ID: "v1", SecretID: "s1", Version: 3}},
			nil
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodGet, "/portal/admin/projects/demo/envs/prod/secrets", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecrets(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "DB_PASSWORD") {
		t.Fatalf("expected DB_PASSWORD in body, got: %s", body)
	}
	// Hard contract: never render values.
	if strings.Contains(body, "value") && strings.Contains(strings.ToLower(body), "secret value") {
		t.Errorf("body should not advertise viewing values: %s", body)
	}
}

// ── Secret delete ─────────────────────────────────────────────────────────────

func TestPortalAdminSecretDelete_OK(t *testing.T) {
	called := false
	st := &mockStore{}
	setProjectEnv(st)
	st.deleteSecret = func(_ context.Context, projectID, envID, key string) error {
		if projectID != "p1" || envID != "e1" || key != "API_TOKEN" {
			t.Errorf("unexpected args: %q %q %q", projectID, envID, key)
		}
		called = true
		return nil
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/api_token/delete", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "api_token") // handler upper-cases
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretDelete(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d", w.Code)
	}
	if !called {
		t.Fatal("DeleteSecret was not called")
	}
	if !strings.Contains(w.Header().Get("Location"), "success=") {
		t.Fatalf("expected success flash, got %q", w.Header().Get("Location"))
	}
}

func TestPortalAdminSecretDelete_NotFound(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	st.deleteSecret = func(_ context.Context, _, _, _ string) error { return store.ErrNotFound }
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/MISSING/delete", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "MISSING")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretDelete(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=Secret+not+found") {
		t.Fatalf("expected not-found flash, got %q", loc)
	}
}

// ── Secret versions ───────────────────────────────────────────────────────────

func TestPortalAdminSecretVersions_GET_OK(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	uid := "user-uuid-123"
	current := &model.SecretVersion{ID: "v3", SecretID: "s1", Version: 3, CreatedAt: time.Now(), CreatedBy: &uid}
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "API_TOKEN"}, current, nil
	}
	st.listSecretVersions = func(_ context.Context, secretID string) ([]*model.SecretVersion, error) {
		if secretID != "s1" {
			t.Errorf("unexpected secretID: %q", secretID)
		}
		return []*model.SecretVersion{
			current,
			{ID: "v2", SecretID: "s1", Version: 2, CreatedAt: time.Now().Add(-time.Hour), CreatedBy: &uid},
			{ID: "v1", SecretID: "s1", Version: 1, CreatedAt: time.Now().Add(-2 * time.Hour), CreatedBy: &uid},
		}, nil
	}
	// All three versions point at the same user UUID — confirm the template
	// renders the email and the in-memory cache only hits the store once.
	lookups := 0
	st.getUserByID = func(_ context.Context, id string) (*model.User, error) {
		lookups++
		if id != uid {
			t.Errorf("unexpected user lookup: %q", id)
		}
		return &model.User{ID: id, Email: "alice@example.com"}, nil
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodGet, "/portal/admin/projects/demo/envs/prod/secrets/api_token/versions", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "api_token")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretVersions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "v3") || !strings.Contains(body, "current") {
		t.Fatalf("expected current marker in body, got: %s", body)
	}
	if !strings.Contains(body, "alice@example.com") {
		t.Fatalf("expected resolved email in body, got: %s", body)
	}
	if strings.Contains(body, ">"+uid+"<") {
		t.Fatalf("raw UUID should be in title attribute only, not visible text: %s", body)
	}
	if lookups != 1 {
		t.Fatalf("expected 1 GetUserByID call (deduped via cache), got %d", lookups)
	}
}

// TestPortalAdminSecretVersions_GET_UnknownCreatedBy covers the fallback path
// where CreatedBy points at a token ID (machine token) or a deleted user —
// the page must show the raw UUID rather than blow up.
func TestPortalAdminSecretVersions_GET_UnknownCreatedBy(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	machineID := "tok-abc"
	current := &model.SecretVersion{ID: "v1", SecretID: "s1", Version: 1, CreatedAt: time.Now(), CreatedBy: &machineID}
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "X"}, current, nil
	}
	st.listSecretVersions = func(_ context.Context, _ string) ([]*model.SecretVersion, error) {
		return []*model.SecretVersion{current}, nil
	}
	st.getUserByID = func(_ context.Context, _ string) (*model.User, error) {
		return nil, store.ErrNotFound
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodGet, "/portal/admin/projects/demo/envs/prod/secrets/x/versions", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "x")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretVersions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), machineID) {
		t.Fatalf("expected fallback to raw UUID for unknown CreatedBy, got: %s", w.Body.String())
	}
}

// ── Secret rollback ───────────────────────────────────────────────────────────

func TestPortalAdminSecretRollback_OK(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1"}, &model.SecretVersion{ID: "v3"}, nil
	}
	st.getSecretVersion = func(_ context.Context, secretID, versionID string) (*model.SecretVersion, error) {
		if secretID != "s1" || versionID != "v1" {
			return nil, store.ErrNotFound
		}
		return &model.SecretVersion{ID: "v1", Version: 1}, nil
	}
	rolledBack := false
	st.rollbackSecret = func(_ context.Context, secretID, versionID string, _ *string) (*model.SecretVersion, error) {
		if secretID != "s1" || versionID != "v1" {
			t.Errorf("unexpected rollback args: %q %q", secretID, versionID)
		}
		rolledBack = true
		// Return the new (forward-only) version that the rollback created.
		return &model.SecretVersion{ID: "v4", SecretID: secretID, Version: 4}, nil
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/api_token/versions/v1/rollback", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "api_token")
	r.SetPathValue("version", "v1")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretRollback(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d", w.Code)
	}
	if !rolledBack {
		t.Fatal("RollbackSecret was not called")
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "v1") || !strings.Contains(loc, "v4") {
		t.Fatalf("expected flash to mention source v1 and new v4, got %q", loc)
	}
}

// ── Secret create ─────────────────────────────────────────────────────────────

func TestPortalAdminSecretNew_POST_OK(t *testing.T) {
	st := &mockStore{}
	srv := newPortalAdminTestServer(t, st)
	p, _ := makeEncryptedSecret(t, srv, "irrelevant") // give the project a real EncryptedPEK

	st.getProject = func(_ context.Context, _ string) (*model.Project, error) { return p, nil }
	st.getEnvironment = func(_ context.Context, _, _ string) (*model.Environment, error) {
		return &model.Environment{ID: "e1", Slug: "prod"}, nil
	}
	// no existing secret with that key
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return nil, nil, store.ErrNotFound
	}
	createCalled := false
	st.setSecret = func(_ context.Context, _, _, key string, comment *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		if key != "API_TOKEN" {
			t.Errorf("key: got %q", key)
		}
		if comment == nil || *comment != "ci-only" {
			t.Errorf("comment: got %v", comment)
		}
		createCalled = true
		return &model.SecretVersion{ID: "v1", Version: 1}, nil
	}

	form := url.Values{
		"key":     {"api_token"}, // handler upper-cases
		"value":   {"super-secret"},
		"comment": {"ci-only"},
	}
	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/new", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretNew(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	if !createCalled {
		t.Fatal("SetSecret was not called")
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "success=") || !strings.Contains(loc, "API_TOKEN") {
		t.Fatalf("redirect should include success flash with key, got %q", loc)
	}
}

func TestPortalAdminSecretNew_POST_InvalidKey(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	srv := newPortalAdminTestServer(t, st)

	form := url.Values{"key": {"bad-key!"}, "value": {"v"}}
	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/new", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretNew(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected re-render, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "uppercase") {
		t.Fatalf("expected key validation message, got %s", w.Body.String())
	}
}

func TestPortalAdminSecretNew_POST_DuplicateKey(t *testing.T) {
	st := &mockStore{}
	srv := newPortalAdminTestServer(t, st)
	p, _ := makeEncryptedSecret(t, srv, "x")
	st.getProject = func(_ context.Context, _ string) (*model.Project, error) { return p, nil }
	st.getEnvironment = func(_ context.Context, _, _ string) (*model.Environment, error) {
		return &model.Environment{ID: "e1", Slug: "prod"}, nil
	}
	// existing secret returned → must reject create
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "EXISTS"}, &model.SecretVersion{ID: "v1"}, nil
	}
	st.setSecret = func(_ context.Context, _, _, _ string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		t.Fatal("SetSecret must not be called when create collides with an existing key")
		return nil, nil
	}

	form := url.Values{"key": {"EXISTS"}, "value": {"v"}}
	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/new", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretNew(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected re-render, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already exists") {
		t.Fatalf("expected duplicate-key message, got %s", w.Body.String())
	}
}

// ── Secret edit ───────────────────────────────────────────────────────────────

func TestPortalAdminSecretEdit_GET_OK(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "API_TOKEN", Comment: "rotate quarterly"}, &model.SecretVersion{ID: "v1"}, nil
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodGet, "/portal/admin/projects/demo/envs/prod/secrets/api_token/edit", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "api_token")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretEdit(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "API_TOKEN") {
		t.Fatalf("expected current key in form, got: %s", body)
	}
	if !strings.Contains(body, "rotate quarterly") {
		t.Fatalf("expected comment pre-fill, got: %s", body)
	}
}

func TestPortalAdminSecretEdit_POST_OK(t *testing.T) {
	st := &mockStore{}
	srv := newPortalAdminTestServer(t, st)
	p, _ := makeEncryptedSecret(t, srv, "irrelevant")
	st.getProject = func(_ context.Context, _ string) (*model.Project, error) { return p, nil }
	st.getEnvironment = func(_ context.Context, _, _ string) (*model.Environment, error) {
		return &model.Environment{ID: "e1", Slug: "prod"}, nil
	}
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "API_TOKEN", Comment: "old"}, &model.SecretVersion{ID: "v1"}, nil
	}
	var savedComment *string
	st.setSecret = func(_ context.Context, _, _, _ string, comment *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		savedComment = comment
		return &model.SecretVersion{ID: "v2", Version: 2}, nil
	}

	form := url.Values{"value": {"new-value"}, "comment": {"updated"}}
	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/api_token/edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "api_token")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretEdit(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	if savedComment == nil || *savedComment != "updated" {
		t.Fatalf("expected comment updated, got: %v", savedComment)
	}
}

func TestPortalAdminSecretEdit_POST_EmptyValue(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "API_TOKEN"}, &model.SecretVersion{ID: "v1"}, nil
	}
	srv := newPortalAdminTestServer(t, st)

	form := url.Values{"value": {""}, "comment": {"keep"}}
	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/api_token/edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "api_token")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretEdit(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected re-render, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Value is required") {
		t.Fatalf("expected validation message, got: %s", w.Body.String())
	}
}

// ── Secret reveal ─────────────────────────────────────────────────────────────

// makeEncryptedSecret writes plaintext through the test server's project-key
// cache so the same server's decryptSecretVersion can recover it. Returns the
// Project (with EncryptedPEK populated) and the matching SecretVersion.
func makeEncryptedSecret(t *testing.T, srv *Server, plaintext string) (*model.Project, *model.SecretVersion) {
	t.Helper()
	pek := make([]byte, 32)
	for i := range pek {
		pek[i] = byte(i + 1)
	}
	ctx := context.Background()
	encPEK, err := srv.kp.Wrap(ctx, pek)
	if err != nil {
		t.Fatalf("wrap PEK: %v", err)
	}
	p := &model.Project{ID: "p1", Slug: "demo", EncryptedPEK: encPEK}
	pkp, err := srv.projectKP.ForProject(ctx, p.ID, p.EncryptedPEK)
	if err != nil {
		t.Fatalf("project KP: %v", err)
	}
	encVal, encDEK, err := lcrypto.EncryptEnvelope(ctx, pkp, []byte(plaintext))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return p, &model.SecretVersion{
		ID:             "v1",
		SecretID:       "s1",
		Version:        1,
		EncryptedValue: encVal,
		EncryptedDEK:   encDEK,
		CreatedAt:      time.Now(),
	}
}

func TestPortalAdminSecretReveal_OK(t *testing.T) {
	st := &mockStore{}
	srv := newPortalAdminTestServer(t, st)
	p, sv := makeEncryptedSecret(t, srv, "p4ssw0rd!")

	st.getProject = func(_ context.Context, slug string) (*model.Project, error) {
		if slug != p.Slug {
			return nil, store.ErrNotFound
		}
		return p, nil
	}
	st.getEnvironment = func(_ context.Context, _, _ string) (*model.Environment, error) {
		return &model.Environment{ID: "e1", Slug: "prod"}, nil
	}
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		if key != "DB_PASSWORD" {
			return nil, nil, store.ErrNotFound
		}
		return &model.Secret{ID: "s1", Key: key}, sv, nil
	}

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/db_password/reveal", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "db_password")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretReveal(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "p4ssw0rd!") {
		t.Fatalf("body should contain plaintext value, got: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "secret.get") {
		t.Fatalf("body should warn that this view was logged as secret.get, got: %s", w.Body.String())
	}
}

func TestPortalAdminSecretReveal_NotFound(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return nil, nil, store.ErrNotFound
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/missing/reveal", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "missing")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretReveal(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "error=Secret+not+found") {
		t.Fatalf("expected secret-not-found flash, got %q", w.Header().Get("Location"))
	}
}

// TestPortalAdminSecretVersionReveal_FragmentRollback verifies the inline
// reveal of a historical version (IsCurrent=false) includes the rollback
// button, while the current-version reveal (other test below) does not.
func TestPortalAdminSecretVersionReveal_FragmentRollback(t *testing.T) {
	st := &mockStore{}
	srv := newPortalAdminTestServer(t, st)
	p, sv := makeEncryptedSecret(t, srv, "old")

	st.getProject = func(_ context.Context, _ string) (*model.Project, error) { return p, nil }
	st.getEnvironment = func(_ context.Context, _, _ string) (*model.Environment, error) {
		return &model.Environment{ID: "e1", Slug: "prod"}, nil
	}
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "API_TOKEN"},
			&model.SecretVersion{ID: "v3"}, // current is v3, not the requested v1
			nil
	}
	st.getSecretVersion = func(_ context.Context, _, _ string) (*model.SecretVersion, error) {
		return sv, nil
	}

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/api_token/versions/v1/reveal", nil)
	r.Header.Set("X-Reveal-Fragment", "1")
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "api_token")
	r.SetPathValue("version", "v1")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretVersionReveal(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "/versions/v1/rollback") {
		t.Fatalf("historical-version reveal must include rollback form, got: %s", body)
	}
	if !strings.Contains(body, "Roll back to v") {
		t.Fatalf("rollback button label missing, got: %s", body)
	}
}

func TestPortalAdminSecretReveal_FragmentHeader(t *testing.T) {
	st := &mockStore{}
	srv := newPortalAdminTestServer(t, st)
	p, sv := makeEncryptedSecret(t, srv, "fragment-value")

	st.getProject = func(_ context.Context, _ string) (*model.Project, error) { return p, nil }
	st.getEnvironment = func(_ context.Context, _, _ string) (*model.Environment, error) {
		return &model.Environment{ID: "e1", Slug: "prod"}, nil
	}
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "API_TOKEN"}, sv, nil
	}

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/api_token/reveal", nil)
	r.Header.Set("X-Reveal-Fragment", "1")
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "api_token")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretReveal(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "fragment-value") {
		t.Fatalf("body should contain plaintext, got: %s", body)
	}
	// Fragment must NOT carry the full-page chrome (no <html>, <body>, sidebar, etc.).
	if strings.Contains(body, "<html") || strings.Contains(body, "<body") {
		t.Fatalf("fragment should not include base layout, got: %s", body)
	}
	// And must include the hooks the JS expects.
	if !strings.Contains(body, "data-reveal-text") || !strings.Contains(body, "data-reveal-copy") || !strings.Contains(body, "data-reveal-hide") {
		t.Fatalf("fragment missing JS hooks, got: %s", body)
	}
	// Current-version reveal must NOT show a rollback button — there's nothing
	// to roll back to from "current".
	if strings.Contains(body, "/rollback") {
		t.Fatalf("current-version fragment must not include rollback form, got: %s", body)
	}
}

func TestPortalAdminSecretVersionReveal_OK(t *testing.T) {
	st := &mockStore{}
	srv := newPortalAdminTestServer(t, st)
	p, sv := makeEncryptedSecret(t, srv, "old-secret-value")

	st.getProject = func(_ context.Context, _ string) (*model.Project, error) { return p, nil }
	st.getEnvironment = func(_ context.Context, _, _ string) (*model.Environment, error) {
		return &model.Environment{ID: "e1", Slug: "prod"}, nil
	}
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "DB_PASSWORD"}, &model.SecretVersion{ID: "v3"}, nil
	}
	st.getSecretVersion = func(_ context.Context, secretID, versionID string) (*model.SecretVersion, error) {
		if secretID == "s1" && versionID == "v1" {
			return sv, nil
		}
		return nil, store.ErrNotFound
	}

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/db_password/versions/v1/reveal", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r.SetPathValue("key", "db_password")
	r.SetPathValue("version", "v1")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretVersionReveal(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "old-secret-value") {
		t.Fatalf("body should contain historical plaintext, got: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Back to versions") {
		t.Fatalf("expected Back-to-versions link (BackToVersions=true), got: %s", w.Body.String())
	}
}

// ── Envfile import ────────────────────────────────────────────────────────────

func TestPortalAdminSecretsImport_OK(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return nil, nil, store.ErrNotFound // every key is new
	}
	upserts := 0
	st.setSecret = func(_ context.Context, _, _, key string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		if !strings.HasPrefix(key, "FOO") && !strings.HasPrefix(key, "BAR") {
			t.Errorf("unexpected key: %q", key)
		}
		upserts++
		return &model.SecretVersion{ID: "v" + key, SecretID: "s" + key}, nil
	}
	srv := newPortalAdminTestServer(t, st)

	body := bytes.NewBuffer(nil)
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile("envfile", "secrets.env")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write([]byte("FOO=1\nBAR=2\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/import", body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretsImport(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	if upserts != 2 {
		t.Fatalf("expected 2 upserts, got %d", upserts)
	}
	if !strings.Contains(w.Header().Get("Location"), "success=") {
		t.Fatalf("expected success flash, got %q", w.Header().Get("Location"))
	}
}

func TestPortalAdminSecretsImport_InvalidKey(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	srv := newPortalAdminTestServer(t, st)

	body := bytes.NewBuffer(nil)
	mw := multipart.NewWriter(body)
	fw, _ := mw.CreateFormFile("envfile", "bad.env")
	_, _ = fw.Write([]byte("lowercase=1\n"))
	mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/envs/prod/secrets/import", body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretsImport(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Fatalf("expected error flash, got %q", loc)
	}
}

// ── Envfile export ────────────────────────────────────────────────────────────

// noopStore lets renderEnvfile run without exercising encryption — both
// ListSecrets returning empty results and the resulting empty .env body are
// fine for asserting the Content-Disposition header.
func TestPortalAdminSecretsExport_OK(t *testing.T) {
	st := &mockStore{}
	setProjectEnv(st)
	st.listSecrets = func(_ context.Context, _, _ string) ([]*model.Secret, []*model.SecretVersion, error) {
		return nil, nil, nil
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodGet, "/portal/admin/projects/demo/envs/prod/secrets/export", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretsExport(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, `filename="demo-prod.env"`) {
		t.Fatalf("Content-Disposition: got %q", cd)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type: got %q", ct)
	}
}

func TestPortalAdminSecretsExport_ProjectNotFound(t *testing.T) {
	st := &mockStore{}
	st.getProject = func(_ context.Context, _ string) (*model.Project, error) {
		return nil, errors.New("nope")
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodGet, "/portal/admin/projects/demo/envs/prod/secrets/export", nil)
	r.SetPathValue("project", "demo")
	r.SetPathValue("env", "prod")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminSecretsExport(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", w.Code)
	}
}
