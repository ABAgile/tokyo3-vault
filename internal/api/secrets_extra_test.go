package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// ── handleListSecretVersions ──────────────────────────────────────────────────

func TestHandleListSecretVersions_OK(t *testing.T) {
	now := time.Now().UTC()
	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "sec-1", Key: key}, nil, nil
	}
	st.listSecretVersions = func(_ context.Context, secretID string) ([]*model.SecretVersion, error) {
		return []*model.SecretVersion{
			{ID: "v2", Version: 2, CreatedAt: now},
			{ID: "v1", Version: 1, CreatedAt: now},
		}, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleListSecretVersions, http.MethodGet, "/", "", ownerTok(),
		secretPV("key", "MY_KEY")...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []versionResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 2 {
		t.Fatalf("len = %d, want 2", len(resp))
	}
	if resp[0].Version != 2 || resp[1].Version != 1 {
		t.Errorf("unexpected versions: %+v", resp)
	}
}

func TestHandleListSecretVersions_SecretNotFound(t *testing.T) {
	srv := newTestServer(t, baseStore())
	w := call(t, srv.handleListSecretVersions, http.MethodGet, "/", "", ownerTok(),
		secretPV("key", "MISSING")...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── handleRollbackSecret ──────────────────────────────────────────────────────

func TestHandleRollbackSecret_OK(t *testing.T) {
	now := time.Now().UTC()
	targetVersionID := "v1-uuid"

	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "sec-1", Key: key}, nil, nil
	}
	st.getSecretVersion = func(_ context.Context, _, versionID string) (*model.SecretVersion, error) {
		if versionID == targetVersionID {
			return &model.SecretVersion{ID: targetVersionID, Version: 1, CreatedAt: now}, nil
		}
		return nil, store.ErrNotFound
	}
	rolled := false
	st.rollbackSecret = func(_ context.Context, secID, verID string) error {
		rolled = true
		return nil
	}

	srv := newTestServer(t, st)
	body := `{"version_id":"` + targetVersionID + `"}`
	w := call(t, srv.handleRollbackSecret, http.MethodPost, "/", body, ownerTok(),
		secretPV("key", "DB_URL")...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	if !rolled {
		t.Error("RollbackSecret was not called")
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["version"] != float64(1) {
		t.Errorf("version = %v, want 1", resp["version"])
	}
}

func TestHandleRollbackSecret_VersionNotFound(t *testing.T) {
	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "sec-1", Key: key}, nil, nil
	}
	// getSecretVersion defaults to ErrNotFound in mockStore, so no override needed.

	srv := newTestServer(t, st)
	body := `{"version_id":"non-existent-uuid"}`
	w := call(t, srv.handleRollbackSecret, http.MethodPost, "/", body, ownerTok(),
		secretPV("key", "DB_URL")...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleRollbackSecret_MissingVersionID(t *testing.T) {
	st := baseStore()
	st.getSecret = func(_ context.Context, _, _, key string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{ID: "sec-1", Key: key}, nil, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleRollbackSecret, http.MethodPost, "/", `{}`, ownerTok(),
		secretPV("key", "DB_URL")...)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ── handleImportSecrets ───────────────────────────────────────────────────────

func TestHandleImportSecrets_OK(t *testing.T) {
	encVal, encDEK := encryptForTest(t, "imported-value")
	now := time.Now().UTC()

	srcSec := &model.Secret{ID: "src-sec", Key: "DB_URL", Comment: "# db"}
	srcVer := &model.SecretVersion{
		ID: "v1", Version: 1, CreatedAt: now,
		EncryptedValue: encVal, EncryptedDEK: encDEK,
	}

	imported := 0
	st := baseStore()
	// Destination project+env already set up in baseStore.
	// Add source project+env lookups (same project, different env).
	srcEnvSlug := "staging"
	srcEnvID := "env-staging"
	st.getProject = func(_ context.Context, slug string) (*model.Project, error) {
		return &model.Project{ID: testProjID, Slug: slug}, nil
	}
	st.getEnvironment = func(_ context.Context, pID, slug string) (*model.Environment, error) {
		envID := testEnvID
		if slug == srcEnvSlug {
			envID = srcEnvID
		}
		return &model.Environment{ID: envID, Slug: slug}, nil
	}
	st.listSecrets = func(_ context.Context, _, envID string) ([]*model.Secret, []*model.SecretVersion, error) {
		if envID == srcEnvID {
			return []*model.Secret{srcSec}, []*model.SecretVersion{srcVer}, nil
		}
		return nil, nil, nil
	}
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return nil, nil, store.ErrNotFound // nothing in dst
	}
	st.setSecret = func(_ context.Context, _, _, _ string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		imported++
		return &model.SecretVersion{ID: "new-v", Version: 1, CreatedAt: now}, nil
	}

	srv := newTestServer(t, st)
	body := `{"from_project":"myapp","from_env":"` + srcEnvSlug + `","overwrite":false,"keys":[]}`
	w := call(t, srv.handleImportSecrets, http.MethodPost, "/", body, ownerTok(), secretPV()...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["imported"] != float64(1) {
		t.Errorf("imported = %v, want 1", resp["imported"])
	}
	if imported != 1 {
		t.Errorf("SetSecret called %d times, want 1", imported)
	}
}

func TestHandleImportSecrets_SkipsExisting(t *testing.T) {
	encVal, encDEK := encryptForTest(t, "val")
	now := time.Now().UTC()

	st := baseStore()
	st.getProject = func(_ context.Context, slug string) (*model.Project, error) {
		return &model.Project{ID: testProjID, Slug: slug}, nil
	}
	srcEnvID := "env-src"
	st.getEnvironment = func(_ context.Context, _, slug string) (*model.Environment, error) {
		id := testEnvID
		if slug == "src" {
			id = srcEnvID
		}
		return &model.Environment{ID: id, Slug: slug}, nil
	}
	st.listSecrets = func(_ context.Context, _, envID string) ([]*model.Secret, []*model.SecretVersion, error) {
		if envID == srcEnvID {
			return []*model.Secret{{Key: "EXISTING"}},
				[]*model.SecretVersion{{EncryptedValue: encVal, EncryptedDEK: encDEK, CreatedAt: now}},
				nil
		}
		return nil, nil, nil
	}
	// Secret already exists in destination
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return &model.Secret{Key: "EXISTING"}, &model.SecretVersion{}, nil
	}

	srv := newTestServer(t, st)
	body := `{"from_project":"myapp","from_env":"src","overwrite":false,"keys":[]}`
	w := call(t, srv.handleImportSecrets, http.MethodPost, "/", body, ownerTok(), secretPV()...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["skipped"] != float64(1) || resp["imported"] != float64(0) {
		t.Errorf("imported=%v skipped=%v, want 0/1", resp["imported"], resp["skipped"])
	}
}

func TestHandleImportSecrets_KeyFilter(t *testing.T) {
	encVal, encDEK := encryptForTest(t, "val")
	now := time.Now().UTC()
	setCount := 0

	st := baseStore()
	st.getProject = func(_ context.Context, slug string) (*model.Project, error) {
		return &model.Project{ID: testProjID, Slug: slug}, nil
	}
	srcEnvID := "env-src"
	st.getEnvironment = func(_ context.Context, _, slug string) (*model.Environment, error) {
		id := testEnvID
		if slug == "src" {
			id = srcEnvID
		}
		return &model.Environment{ID: id, Slug: slug}, nil
	}
	st.listSecrets = func(_ context.Context, _, envID string) ([]*model.Secret, []*model.SecretVersion, error) {
		if envID == srcEnvID {
			sv := &model.SecretVersion{EncryptedValue: encVal, EncryptedDEK: encDEK, CreatedAt: now}
			return []*model.Secret{{Key: "WANTED"}, {Key: "UNWANTED"}},
				[]*model.SecretVersion{sv, sv}, nil
		}
		return nil, nil, nil
	}
	st.getSecret = func(_ context.Context, _, _, _ string) (*model.Secret, *model.SecretVersion, error) {
		return nil, nil, store.ErrNotFound
	}
	st.setSecret = func(_ context.Context, _, _, _ string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		setCount++
		return &model.SecretVersion{ID: "nv", Version: 1, CreatedAt: now}, nil
	}

	srv := newTestServer(t, st)
	// Only import WANTED, not UNWANTED.
	body := `{"from_project":"myapp","from_env":"src","overwrite":false,"keys":["WANTED"]}`
	w := call(t, srv.handleImportSecrets, http.MethodPost, "/", body, ownerTok(), secretPV()...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	if setCount != 1 {
		t.Errorf("SetSecret called %d times, want 1 (only WANTED)", setCount)
	}
}

func TestHandleImportSecrets_MissingFromEnv(t *testing.T) {
	srv := newTestServer(t, baseStore())
	body := `{"from_project":"myapp","from_env":"","overwrite":false,"keys":[]}`
	w := call(t, srv.handleImportSecrets, http.MethodPost, "/", body, ownerTok(), secretPV()...)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleImportSecrets_SourceProjectNotFound(t *testing.T) {
	st := baseStore()
	// Destination resolution works (baseStore), but source project not found.
	st.getProject = func(_ context.Context, slug string) (*model.Project, error) {
		if slug == testProjSlug {
			return &model.Project{ID: testProjID, Slug: slug}, nil
		}
		return nil, store.ErrNotFound
	}
	st.getEnvironment = func(_ context.Context, pID, slug string) (*model.Environment, error) {
		if slug == testEnvSlug {
			return &model.Environment{ID: testEnvID, Slug: slug}, nil
		}
		return nil, store.ErrNotFound
	}

	srv := newTestServer(t, st)
	body := `{"from_project":"nonexistent","from_env":"dev","overwrite":false,"keys":[]}`
	w := call(t, srv.handleImportSecrets, http.MethodPost, "/", body, ownerTok(), secretPV()...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── handleSetSecret via POST (key in body) ────────────────────────────────────

func TestHandleSetSecret_POSTWithKeyInBody(t *testing.T) {
	sv := &model.SecretVersion{ID: "v1", Version: 1, CreatedAt: time.Now().UTC()}
	st := baseStore()
	st.setSecret = func(_ context.Context, _, _, _ string, _ *string, _, _ []byte, _ *string) (*model.SecretVersion, error) {
		return sv, nil
	}

	srv := newTestServer(t, st)
	// POST without key in path — key must come from body.
	body := `{"key":"NEW_KEY","value":"myvalue"}`
	// Empty "key" path value simulates POST /secrets (no {key} in path).
	w := call(t, srv.handleSetSecret, http.MethodPost, "/", body, ownerTok(), secretPV()...)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
}

func TestHandleSetSecret_POSTMissingKey(t *testing.T) {
	srv := newTestServer(t, baseStore())
	w := call(t, srv.handleSetSecret, http.MethodPost, "/", `{"value":"v"}`, ownerTok(), secretPV()...)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleSetSecret_POSTInvalidKey(t *testing.T) {
	srv := newTestServer(t, baseStore())
	w := call(t, srv.handleSetSecret, http.MethodPost, "/",
		`{"key":"1INVALID","value":"v"}`, ownerTok(), secretPV()...)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ── versionToResponse ─────────────────────────────────────────────────────────

func TestVersionToResponse(t *testing.T) {
	uid := "creator"
	now := time.Now().UTC()
	sv := &model.SecretVersion{
		ID:        "v-abc",
		Version:   3,
		CreatedAt: now,
		CreatedBy: &uid,
	}
	r := versionToResponse(sv)
	if r.ID != sv.ID || r.Version != 3 || *r.CreatedBy != uid {
		t.Errorf("unexpected response: %+v", r)
	}
	if !strings.HasPrefix(r.CreatedAt, now.Format("2006")) {
		t.Errorf("CreatedAt format unexpected: %q", r.CreatedAt)
	}
}
