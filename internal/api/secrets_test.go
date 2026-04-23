package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// ── pure-function tests ───────────────────────────────────────────────────────

func TestMaskValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "..."},
		{"a", "..."},
		{"ab", "..."},
		{"abc", "..."},
		{"abcd", "abc..."},
		{"postgres://user:pass@host/db", "pos..."},
		{"supersecretvalue", "sup..."},
	}
	for _, tc := range tests {
		got := maskValue(tc.input)
		if got != tc.want {
			t.Errorf("maskValue(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSecretAuditMeta(t *testing.T) {
	got := secretAuditMeta("abc...")
	var m map[string]string
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("secretAuditMeta produced invalid JSON: %v", err)
	}
	if m["value"] != "abc..." {
		t.Errorf("value = %q, want %q", m["value"], "abc...")
	}
}

// ── handler test helpers ──────────────────────────────────────────────────────

const (
	testProjSlug = "myapp"
	testProjID   = "proj-uuid-1"
	testEnvSlug  = "prod"
	testEnvID    = "env-uuid-1"
	testUserID   = "user-uuid-1"
)

// baseStore returns a mockStore pre-wired with project+env resolution, an owner
// membership record, and a no-op audit log — enough for most handler tests.
func baseStore() *mockStore {
	return &mockStore{
		getProject: func(_ context.Context, slug string) (*model.Project, error) {
			if slug == testProjSlug {
				return &model.Project{ID: testProjID, Slug: testProjSlug}, nil
			}
			return nil, store.ErrNotFound
		},
		getEnvironment: func(_ context.Context, pID, slug string) (*model.Environment, error) {
			if pID == testProjID && slug == testEnvSlug {
				return &model.Environment{ID: testEnvID, Slug: testEnvSlug}, nil
			}
			return nil, store.ErrNotFound
		},
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
		getProjectMember: func(_ context.Context, pID, _ string) (*model.ProjectMember, error) {
			if pID == testProjID {
				return &model.ProjectMember{Role: model.RoleOwner}, nil
			}
			return nil, store.ErrNotFound
		},
	}
}

// ownerTok returns a user session token for testUserID.
func ownerTok() *model.Token {
	uid := testUserID
	return &model.Token{ID: "tok-owner", UserID: &uid}
}

// encryptForTest encrypts value with the test server's fixed KEK.
func encryptForTest(t *testing.T, value string) (encVal, encDEK []byte) {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	kp := crypto.NewLocalKeyProvider(kek)
	ev, ed, err := crypto.EncryptSecret(context.Background(), kp, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return ev, ed
}

// call invokes handler directly (bypassing the router's auth middleware) with
// tok already in context and the provided path values set on the request.
// pathKV is an alternating sequence of key, value pairs (e.g. "project", "myapp").
func call(t *testing.T, handler http.HandlerFunc, method, url string, body string, tok *model.Token, pathKV ...string) *httptest.ResponseRecorder {
	t.Helper()
	var b strings.Reader
	if body != "" {
		b = *strings.NewReader(body)
	}
	r := httptest.NewRequest(method, url, &b)
	r = withToken(r, tok)
	for i := 0; i+1 < len(pathKV); i += 2 {
		r.SetPathValue(pathKV[i], pathKV[i+1])
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

// secretPV returns the standard project+env path values.
func secretPV(extra ...string) []string {
	base := []string{"project", testProjSlug, "env", testEnvSlug}
	return append(base, extra...)
}

// ── handleListSecrets ─────────────────────────────────────────────────────────

func TestHandleListSecrets(t *testing.T) {
	now := time.Now().UTC()
	sv := &model.SecretVersion{Version: 2}

	st := baseStore()
	st.listSecrets = func(_ context.Context, _, _ string) ([]*model.Secret, []*model.SecretVersion, error) {
		return []*model.Secret{
			{Key: "DB_URL", UpdatedAt: now},
			{Key: "API_KEY", UpdatedAt: now},
		}, []*model.SecretVersion{sv, nil}, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleListSecrets, http.MethodGet, "/", "", ownerTok(), secretPV()...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []secretMeta
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 2 {
		t.Fatalf("len = %d, want 2", len(resp))
	}
	if resp[0].Key != "DB_URL" || resp[0].Version != 2 {
		t.Errorf("resp[0] = %+v", resp[0])
	}
	if resp[1].Key != "API_KEY" || resp[1].Version != 0 {
		t.Errorf("resp[1] = %+v", resp[1])
	}
}

func TestHandleListSecrets_Empty(t *testing.T) {
	st := baseStore()
	st.listSecrets = func(_ context.Context, _, _ string) ([]*model.Secret, []*model.SecretVersion, error) {
		return nil, nil, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleListSecrets, http.MethodGet, "/", "", ownerTok(), secretPV()...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp []secretMeta
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 0 {
		t.Errorf("expected empty list, got %d entries", len(resp))
	}
}

// ── handleGetSecret ───────────────────────────────────────────────────────────

func TestHandleGetSecret_OK(t *testing.T) {
	encVal, encDEK := encryptForTest(t, "s3cr3t")
	now := time.Now().UTC()

	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		if key == "DB_URL" {
			return &model.Secret{Key: "DB_URL", UpdatedAt: now},
				&model.SecretVersion{Version: 1, EncryptedValue: encVal, EncryptedDEK: encDEK},
				nil
		}
		return nil, nil, store.ErrNotFound
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleGetSecret, http.MethodGet, "/", "", ownerTok(), secretPV("key", "DB_URL")...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp secretResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Value != "s3cr3t" {
		t.Errorf("Value = %q, want %q", resp.Value, "s3cr3t")
	}
	if resp.Key != "DB_URL" {
		t.Errorf("Key = %q, want %q", resp.Key, "DB_URL")
	}
	if resp.Version != 1 {
		t.Errorf("Version = %d, want 1", resp.Version)
	}
}

func TestHandleGetSecret_NotFound(t *testing.T) {
	srv := newTestServer(t, baseStore())
	w := call(t, srv.handleGetSecret, http.MethodGet, "/", "", ownerTok(), secretPV("key", "MISSING")...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleGetSecret_NoVersion(t *testing.T) {
	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{Key: key}, nil, nil // secret exists but has no version
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleGetSecret, http.MethodGet, "/", "", ownerTok(), secretPV("key", "ORPHAN")...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleGetSecret_KeyUppercased(t *testing.T) {
	encVal, encDEK := encryptForTest(t, "value123")
	now := time.Now().UTC()

	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		if key == "MY_KEY" {
			return &model.Secret{Key: "MY_KEY", UpdatedAt: now},
				&model.SecretVersion{EncryptedValue: encVal, EncryptedDEK: encDEK},
				nil
		}
		return nil, nil, store.ErrNotFound
	}

	srv := newTestServer(t, st)
	// Pass lowercase; handler must uppercase it.
	w := call(t, srv.handleGetSecret, http.MethodGet, "/", "", ownerTok(), secretPV("key", "my_key")...)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ── handleSetSecret (PUT) ─────────────────────────────────────────────────────

func TestHandleSetSecret_OK(t *testing.T) {
	sv := &model.SecretVersion{ID: "ver-1", Version: 1, CreatedAt: time.Now().UTC()}

	st := baseStore()
	st.setSecret = func(_ context.Context, _, _, _ string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		return sv, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleSetSecret, http.MethodPut, "/", `{"value":"mysecretvalue"}`, ownerTok(), secretPV("key", "NEW_KEY")...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp versionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Version != 1 {
		t.Errorf("Version = %d, want 1", resp.Version)
	}
}

func TestHandleSetSecret_InvalidKey(t *testing.T) {
	// Note: the handler uppercases the key before validating, so "mykey" → "MYKEY"
	// (valid). Only keys that are still invalid after uppercasing are rejected.
	tests := []struct {
		name string
		key  string
	}{
		{"starts with digit", "1KEY"},
		{"has hyphen", "MY-KEY"},
		{"has space", "MY KEY"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, baseStore())
			w := call(t, srv.handleSetSecret, http.MethodPut, "/", `{"value":"val"}`, ownerTok(),
				secretPV("key", tc.key)...)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
		})
	}
}

func TestHandleSetSecret_ReadOnlyToken(t *testing.T) {
	projID := testProjID
	tok := &model.Token{
		ID:        "ro-tok",
		ProjectID: &projID,
		ReadOnly:  true,
	}

	srv := newTestServer(t, baseStore())
	w := call(t, srv.handleSetSecret, http.MethodPut, "/", `{"value":"val"}`, tok, secretPV("key", "MY_KEY")...)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── handleDeleteSecret ────────────────────────────────────────────────────────

func TestHandleDeleteSecret_OK(t *testing.T) {
	deleted := false
	st := baseStore()
	st.deleteSecret = func(_ context.Context, _, _, _ string) error {
		deleted = true
		return nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteSecret, http.MethodDelete, "/", "", ownerTok(), secretPV("key", "OLD_KEY")...)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if !deleted {
		t.Error("store.DeleteSecret was not called")
	}
}

func TestHandleDeleteSecret_NotFound(t *testing.T) {
	// baseStore.deleteSecret default returns store.ErrNotFound
	srv := newTestServer(t, baseStore())
	w := call(t, srv.handleDeleteSecret, http.MethodDelete, "/", "", ownerTok(), secretPV("key", "MISSING")...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── handleUploadDotenv ────────────────────────────────────────────────────────

func TestHandleUploadDotenv_OK(t *testing.T) {
	var storedKeys []string
	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return nil, nil, store.ErrNotFound
	}
	st.setSecret = func(_ context.Context, _, _, key string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		storedKeys = append(storedKeys, key)
		return &model.SecretVersion{ID: "v1", Version: 1, CreatedAt: time.Now()}, nil
	}

	srv := newTestServer(t, st)
	dotenv := "# db config\nDB_URL=postgres://localhost/db\nAPP_KEY=secret123\n"
	w := call(t, srv.handleUploadDotenv, http.MethodPost, "/", dotenv, ownerTok(), secretPV()...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["uploaded"] != float64(2) {
		t.Errorf("uploaded = %v, want 2", resp["uploaded"])
	}
	if resp["skipped"] != float64(0) {
		t.Errorf("skipped = %v, want 0", resp["skipped"])
	}
	if len(storedKeys) != 2 {
		t.Errorf("SetSecret calls = %v, want [DB_URL APP_KEY]", storedKeys)
	}
}

func TestHandleUploadDotenv_SkipsExisting(t *testing.T) {
	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		if key == "DB_URL" {
			return &model.Secret{Key: "DB_URL"}, &model.SecretVersion{}, nil
		}
		return nil, nil, store.ErrNotFound
	}
	stored := 0
	st.setSecret = func(_ context.Context, _, _, _ string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		stored++
		return &model.SecretVersion{ID: "v1", Version: 1, CreatedAt: time.Now()}, nil
	}

	srv := newTestServer(t, st)
	dotenv := "DB_URL=postgres://localhost\nNEW_KEY=val\n"
	w := call(t, srv.handleUploadDotenv, http.MethodPost, "/", dotenv, ownerTok(), secretPV()...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["uploaded"] != float64(1) || resp["skipped"] != float64(1) {
		t.Errorf("uploaded=%v skipped=%v, want uploaded=1 skipped=1", resp["uploaded"], resp["skipped"])
	}
	if stored != 1 {
		t.Errorf("SetSecret called %d times, want 1", stored)
	}
}

func TestHandleUploadDotenv_Overwrite(t *testing.T) {
	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{Key: "K"}, &model.SecretVersion{}, nil // exists
	}
	stored := 0
	st.setSecret = func(_ context.Context, _, _, _ string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		stored++
		return &model.SecretVersion{ID: "v2", Version: 2, CreatedAt: time.Now()}, nil
	}

	srv := newTestServer(t, st)
	// Use ?overwrite=true query param.
	w := call(t, srv.handleUploadDotenv, http.MethodPost, "/?overwrite=true", "MY_KEY=newval\n", ownerTok(), secretPV()...)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if stored != 1 {
		t.Errorf("SetSecret called %d times, want 1 (should overwrite)", stored)
	}
}

func TestHandleUploadDotenv_InvalidDotenv(t *testing.T) {
	srv := newTestServer(t, baseStore())
	w := call(t, srv.handleUploadDotenv, http.MethodPost, "/", "NOEQUALS\n", ownerTok(), secretPV()...)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleUploadDotenv_InvalidKeyFormat(t *testing.T) {
	// Key "1INVALID" starts with digit — fails keyRe.
	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return nil, nil, store.ErrNotFound
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleUploadDotenv, http.MethodPost, "/", "1INVALID=val\n", ownerTok(), secretPV()...)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ── handleDownloadDotenv ──────────────────────────────────────────────────────

func TestHandleDownloadDotenv_OK(t *testing.T) {
	encVal1, encDEK1 := encryptForTest(t, "postgres://localhost/db")
	encVal2, encDEK2 := encryptForTest(t, "s3cr3t")

	st := baseStore()
	st.listSecrets = func(_ context.Context, _, _ string) ([]*model.Secret, []*model.SecretVersion, error) {
		return []*model.Secret{
				{Key: "DB_URL", Comment: "# database\n"},
				{Key: "APP_KEY"},
			}, []*model.SecretVersion{
				{EncryptedValue: encVal1, EncryptedDEK: encDEK1},
				{EncryptedValue: encVal2, EncryptedDEK: encDEK2},
			}, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleDownloadDotenv, http.MethodGet, "/", "", ownerTok(), secretPV()...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "# database\n") {
		t.Errorf("comment not in output: %q", body)
	}
	if !strings.Contains(body, "DB_URL=postgres://localhost/db") {
		t.Errorf("DB_URL not in output: %q", body)
	}
	if !strings.Contains(body, "APP_KEY=s3cr3t") {
		t.Errorf("APP_KEY not in output: %q", body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

func TestHandleDownloadDotenv_SkipsVersionless(t *testing.T) {
	encVal, encDEK := encryptForTest(t, "val")

	st := baseStore()
	st.listSecrets = func(_ context.Context, _, _ string) ([]*model.Secret, []*model.SecretVersion, error) {
		return []*model.Secret{
				{Key: "HAS_VERSION"},
				{Key: "NO_VERSION"},
			}, []*model.SecretVersion{
				{EncryptedValue: encVal, EncryptedDEK: encDEK},
				nil,
			}, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleDownloadDotenv, http.MethodGet, "/", "", ownerTok(), secretPV()...)
	body := w.Body.String()
	if strings.Contains(body, "NO_VERSION") {
		t.Errorf("version-less secret in output: %q", body)
	}
	if !strings.Contains(body, "HAS_VERSION") {
		t.Errorf("versioned secret missing from output: %q", body)
	}
}

// ── project/env resolution errors ────────────────────────────────────────────

func TestResolveProjectEnv_ProjectNotFound(t *testing.T) {
	st := &mockStore{
		// getProject left nil → ErrNotFound
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListSecrets, http.MethodGet, "/", "", ownerTok(), secretPV()...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestResolveProjectEnv_EnvNotFound(t *testing.T) {
	st := &mockStore{
		getProject: func(_ context.Context, slug string) (*model.Project, error) {
			return &model.Project{ID: testProjID, Slug: slug}, nil
		},
		// getEnvironment left nil → ErrNotFound
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListSecrets, http.MethodGet, "/", "", ownerTok(), secretPV()...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
