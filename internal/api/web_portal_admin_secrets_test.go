package api

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/crypto"
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
	current := &model.SecretVersion{ID: "v3", SecretID: "s1", Version: 3, CreatedAt: time.Now()}
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "s1", Key: "API_TOKEN"}, current, nil
	}
	st.listSecretVersions = func(_ context.Context, secretID string) ([]*model.SecretVersion, error) {
		if secretID != "s1" {
			t.Errorf("unexpected secretID: %q", secretID)
		}
		return []*model.SecretVersion{
			current,
			{ID: "v2", SecretID: "s1", Version: 2, CreatedAt: time.Now().Add(-time.Hour)},
			{ID: "v1", SecretID: "s1", Version: 1, CreatedAt: time.Now().Add(-2 * time.Hour)},
		}, nil
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
	st.rollbackSecret = func(_ context.Context, secretID, versionID string) error {
		if secretID != "s1" || versionID != "v1" {
			t.Errorf("unexpected rollback args: %q %q", secretID, versionID)
		}
		rolledBack = true
		return nil
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
	encPEK, err := srv.kp.WrapDEK(ctx, pek)
	if err != nil {
		t.Fatalf("wrap PEK: %v", err)
	}
	p := &model.Project{ID: "p1", Slug: "demo", EncryptedPEK: encPEK}
	pkp, err := srv.projectKP.ForProject(ctx, p.ID, p.EncryptedPEK)
	if err != nil {
		t.Fatalf("project KP: %v", err)
	}
	encVal, encDEK, err := crypto.EncryptSecret(ctx, pkp, []byte(plaintext))
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
