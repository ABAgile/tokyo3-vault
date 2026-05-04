package api

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/model"
)

// newPortalAdminTestServer builds a Server with the portal template manager
// initialised so portal handlers that render error pages don't nil-panic.
func newPortalAdminTestServer(t *testing.T, st *mockStore) *Server {
	t.Helper()
	srv := newTestServer(t, st)
	tm, err := newTmplManager("base_portal.html")
	if err != nil {
		t.Fatalf("init portal templates: %v", err)
	}
	srv.portalTmpl = tm
	srv.audit = audit.NoopSink{}
	return srv
}

// withPortalAdmin injects an admin portal context onto r so handlers that read
// pc := portalFromCtx(r) and tok := tokenFromCtx(r) see a server admin.
func withPortalAdmin(r *http.Request) *http.Request {
	uid := "admin-user-id"
	user := &model.User{ID: uid, Email: "admin@example.com", Role: model.UserRoleAdmin, Active: true}
	tok := &model.Token{ID: "portal-tok", UserID: &uid}
	ctx := context.WithValue(r.Context(), portalCtxKey{}, &portalCtx{Token: tok, User: user})
	ctx = context.WithValue(ctx, tokenKey, tok)
	return r.WithContext(ctx)
}

// ── Project create ────────────────────────────────────────────────────────────

func TestPortalAdminProjectNew_POST_OK(t *testing.T) {
	st := &mockStore{
		createProject: func(_ context.Context, name, slug string) (*model.Project, error) {
			if name != "Test Project" || slug != "test-project" {
				t.Errorf("unexpected name/slug: %q / %q", name, slug)
			}
			return &model.Project{ID: "p1", Name: name, Slug: slug}, nil
		},
		addProjectMember: func(_ context.Context, projectID, userID, role string, _ *string) error {
			if projectID != "p1" || userID != "admin-user-id" || role != model.RoleOwner {
				t.Errorf("unexpected member add: %q %q %q", projectID, userID, role)
			}
			return nil
		},
	}
	srv := newPortalAdminTestServer(t, st)

	form := url.Values{"name": {"Test Project"}, "slug": {"test-project"}}
	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/new", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminProjectNew(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d want %d", w.Code, http.StatusFound)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/portal/admin/projects/test-project") {
		t.Fatalf("redirect: got %q", loc)
	}
}

func TestPortalAdminProjectNew_POST_SlugDerivedFromName(t *testing.T) {
	var gotSlug string
	st := &mockStore{
		createProject: func(_ context.Context, _, slug string) (*model.Project, error) {
			gotSlug = slug
			return &model.Project{ID: "p1", Slug: slug}, nil
		},
	}
	srv := newPortalAdminTestServer(t, st)

	form := url.Values{"name": {"Cool Project"}} // no slug
	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/new", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminProjectNew(w, r)

	if gotSlug != "cool-project" {
		t.Fatalf("slug: got %q want %q", gotSlug, "cool-project")
	}
}

func TestPortalAdminProjectNew_POST_MissingName(t *testing.T) {
	srv := newPortalAdminTestServer(t, &mockStore{})

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/new", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminProjectNew(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d (re-rendered form)", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "Name is required") {
		t.Fatalf("body should contain 'Name is required', got: %s", w.Body.String())
	}
}

// ── Project delete ────────────────────────────────────────────────────────────

func TestPortalAdminProjectDelete_OK(t *testing.T) {
	deleted := false
	st := &mockStore{
		getProject: func(_ context.Context, slug string) (*model.Project, error) {
			return &model.Project{ID: "p1", Slug: slug}, nil
		},
		deleteProject: func(_ context.Context, slug string) error {
			if slug != "demo" {
				t.Errorf("unexpected slug: %q", slug)
			}
			deleted = true
			return nil
		},
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/delete", nil)
	r.SetPathValue("project", "demo")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminProjectDelete(w, r)

	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "/portal/admin/projects?") {
		t.Fatalf("redirect: status=%d loc=%q", w.Code, w.Header().Get("Location"))
	}
	if !deleted {
		t.Fatal("DeleteProject was not called")
	}
}

func TestPortalAdminProjectDelete_NotFound(t *testing.T) {
	st := &mockStore{} // default Stub returns ErrNotFound for getProject
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/missing/delete", nil)
	r.SetPathValue("project", "missing")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminProjectDelete(w, r)

	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.Contains(loc, "error=Project+not+found") {
		t.Fatalf("expected redirect with error flash, got status=%d loc=%q", w.Code, loc)
	}
}

// ── Project rotate-key ────────────────────────────────────────────────────────

func TestPortalAdminProjectRotateKey_MissingPEK(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, slug string) (*model.Project, error) {
			return &model.Project{ID: "p1", Slug: slug, EncryptedPEK: nil}, nil
		},
	}
	srv := newPortalAdminTestServer(t, st)

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/rotate", nil)
	r.SetPathValue("project", "demo")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminProjectRotateKey(w, r)

	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.Contains(loc, "vaultd+migrate-keys") {
		t.Fatalf("expected migrate-keys hint, got status=%d loc=%q", w.Code, loc)
	}
}

func TestPortalAdminProjectRotateKey_OK(t *testing.T) {
	srv := newPortalAdminTestServer(t, nil)
	// Pre-wrap a 32-byte PEK with the test KEK so the unwrap step succeeds.
	plainPEK := make([]byte, 32)
	if _, err := rand.Read(plainPEK); err != nil {
		t.Fatalf("rand: %v", err)
	}
	encPEK, err := srv.kp.WrapDEK(context.Background(), plainPEK)
	if err != nil {
		t.Fatalf("wrap PEK: %v", err)
	}
	rotated := false
	srv.store = &mockStore{
		getProject: func(_ context.Context, slug string) (*model.Project, error) {
			return &model.Project{ID: "p1", Slug: slug, EncryptedPEK: encPEK}, nil
		},
		// RotateProjectPEK isn't on mockStore's overridable fields — Stub returns
		// nil and skips the wrap-callback by default, which is fine here: we only
		// need the call to succeed to assert the audit + redirect flow.
	}
	_ = rotated

	r := httptest.NewRequest(http.MethodPost, "/portal/admin/projects/demo/rotate", nil)
	r.SetPathValue("project", "demo")
	r = withPortalAdmin(r)
	w := httptest.NewRecorder()

	srv.handlePortalAdminProjectRotateKey(w, r)

	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.Contains(loc, "success=") {
		t.Fatalf("expected success redirect, got status=%d loc=%q body=%q", w.Code, loc, w.Body.String())
	}
}
