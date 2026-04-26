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

// fakeBackend returns a test DynamicBackend.
func fakeBackend() *model.DynamicBackend {
	return &model.DynamicBackend{
		ID:        "backend-1",
		ProjectID: testProjID,
		EnvID:     testEnvID,
		Slug:      "pg-primary",
		Type:      "postgresql",
		// EncryptedConfig needs to be decryptable by the test KEK.
		// We'll keep it nil here since handleSetDynamicBackend tests use the store mock.
		EncryptedConfig:    []byte("enc"),
		EncryptedConfigDEK: []byte("dek"),
		DefaultTTL:         3600,
		MaxTTL:             86400,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
}

// ── handleSetDynamicBackend ───────────────────────────────────────────────────

func TestHandleSetDynamicBackend(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name: "valid postgresql",
			body: `{"type":"postgresql","config":{"host":"localhost","port":5432,"db":"mydb","user":"u","password":"p"}}`,
			setup: func(m *mockStore) {
				m.setDynamicBackend = func(_ context.Context, _, _, _, _ string, _, _ []byte, _, _ int) (*model.DynamicBackend, error) {
					return fakeBackend(), nil
				}
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing type",
			body:       `{"config":{"host":"localhost"}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing config",
			body:       `{"type":"postgresql"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown backend type",
			body:       `{"type":"unknown-db","config":{"host":"h"}}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "store error",
			body: `{"type":"postgresql","config":{"host":"localhost"}}`,
			setup: func(m *mockStore) {
				m.setDynamicBackend = func(_ context.Context, _, _, _, _ string, _, _ []byte, _, _ int) (*model.DynamicBackend, error) {
					return nil, store.ErrNotFound
				}
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := baseStore()
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleSetDynamicBackend, http.MethodPut, "/", tc.body,
				ownerTok(), secretPV("name", "pg-primary")...)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleGetDynamicBackend ───────────────────────────────────────────────────

func TestHandleGetDynamicBackend(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name: "found",
			setup: func(m *mockStore) {
				m.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
					return fakeBackend(), nil
				}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "not found",
			setup: func(m *mockStore) {
				m.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
					return nil, store.ErrNotFound
				}
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := baseStore()
			tc.setup(st)
			srv := newTestServer(t, st)
			w := call(t, srv.handleGetDynamicBackend, http.MethodGet, "/", "",
				ownerTok(), secretPV("name", "pg-primary")...)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleDeleteDynamicBackend ────────────────────────────────────────────────

func TestHandleDeleteDynamicBackend(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name:       "ok",
			wantStatus: http.StatusNoContent,
		},
		{
			name: "not found",
			setup: func(m *mockStore) {
				m.deleteDynamicBackend = func(_ context.Context, _, _, _ string) error {
					return store.ErrNotFound
				}
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := baseStore()
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleDeleteDynamicBackend, http.MethodDelete, "/", "",
				ownerTok(), secretPV("name", "pg-primary")...)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleSetDynamicRole ──────────────────────────────────────────────────────

func TestHandleSetDynamicRole(t *testing.T) {
	validBody := `{"creation_tmpl":"CREATE USER ...","revocation_tmpl":"DROP USER ..."}`

	tests := []struct {
		name       string
		body       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name: "ok",
			body: validBody,
			setup: func(m *mockStore) {
				m.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
					return fakeBackend(), nil
				}
				m.setDynamicRole = func(_ context.Context, _, _, _, _ string, _ *int) (*model.DynamicRole, error) {
					return &model.DynamicRole{
						ID: "role-1", Name: "readonly",
						CreationTmpl: "CREATE USER ...", RevocationTmpl: "DROP USER ...",
						CreatedAt: time.Now().UTC(),
					}, nil
				}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "backend not found",
			body: validBody,
			setup: func(m *mockStore) {
				m.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
					return nil, store.ErrNotFound
				}
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "missing templates",
			body: `{"creation_tmpl":"CREATE USER ..."}`,
			setup: func(m *mockStore) {
				m.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
					return fakeBackend(), nil
				}
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := baseStore()
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleSetDynamicRole, http.MethodPut, "/", tc.body,
				ownerTok(), secretPV("name", "pg-primary", "role", "readonly")...)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleListDynamicRoles ────────────────────────────────────────────────────

func TestHandleListDynamicRoles(t *testing.T) {
	st := baseStore()
	st.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
		return fakeBackend(), nil
	}
	st.listDynamicRoles = func(_ context.Context, _ string) ([]*model.DynamicRole, error) {
		return []*model.DynamicRole{
			{ID: "r1", Name: "ro", CreationTmpl: "C", RevocationTmpl: "D", CreatedAt: time.Now().UTC()},
		}, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleListDynamicRoles, http.MethodGet, "/", "",
		ownerTok(), secretPV("name", "pg-primary")...)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []dynamicRoleResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 || resp[0].Name != "ro" {
		t.Errorf("unexpected resp: %+v", resp)
	}
}

// ── handleDeleteDynamicRole ───────────────────────────────────────────────────

func TestHandleDeleteDynamicRole(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name: "ok",
			setup: func(m *mockStore) {
				m.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
					return fakeBackend(), nil
				}
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name: "role not found",
			setup: func(m *mockStore) {
				m.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
					return fakeBackend(), nil
				}
				m.deleteDynamicRole = func(_ context.Context, _, _ string) error {
					return store.ErrNotFound
				}
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "backend not found",
			setup: func(m *mockStore) {
				m.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
					return nil, store.ErrNotFound
				}
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := baseStore()
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleDeleteDynamicRole, http.MethodDelete, "/", "",
				ownerTok(), secretPV("name", "pg-primary", "role", "ro")...)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleListDynamicLeases ───────────────────────────────────────────────────

func TestHandleListDynamicLeases(t *testing.T) {
	now := time.Now().UTC()
	st := baseStore()
	st.listDynamicLeases = func(_ context.Context, _, _ string) ([]*model.DynamicLease, error) {
		return []*model.DynamicLease{
			{ID: "l-1", RoleName: "ro", Username: "user-abc", ExpiresAt: now.Add(time.Hour), CreatedAt: now},
		}, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleListDynamicLeases, http.MethodGet, "/", "",
		ownerTok(), secretPV()...)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []leaseResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 {
		t.Errorf("expected 1 lease, got %d", len(resp))
	}
}

// ── handleRevokeDynamicLease ──────────────────────────────────────────────────

func TestHandleRevokeDynamicLease(t *testing.T) {
	now := time.Now().UTC()
	fakeLease := &model.DynamicLease{
		ID:             "l-1",
		ProjectID:      testProjID,
		EnvID:          testEnvID,
		BackendID:      "backend-1",
		RoleName:       "ro",
		Username:       "u",
		RevocationTmpl: "DROP USER ...",
		ExpiresAt:      now.Add(time.Hour),
		CreatedAt:      now,
	}

	tests := []struct {
		name       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name: "ok - backend not found (best-effort revoke skipped)",
			setup: func(m *mockStore) {
				m.getDynamicLease = func(_ context.Context, _ string) (*model.DynamicLease, error) {
					return fakeLease, nil
				}
				// Backend not found → skip credential revocation.
				m.getDynamicBackendByID = func(_ context.Context, _ string) (*model.DynamicBackend, error) {
					return nil, store.ErrNotFound
				}
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name: "lease not found",
			setup: func(m *mockStore) {
				m.getDynamicLease = func(_ context.Context, _ string) (*model.DynamicLease, error) {
					return nil, store.ErrNotFound
				}
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "already revoked",
			setup: func(m *mockStore) {
				revokedAt := now.Add(-time.Minute)
				lease := *fakeLease
				lease.RevokedAt = &revokedAt
				m.getDynamicLease = func(_ context.Context, _ string) (*model.DynamicLease, error) {
					return &lease, nil
				}
			},
			wantStatus: http.StatusConflict,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := baseStore()
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleRevokeDynamicLease, http.MethodDelete, "/", "",
				ownerTok(), secretPV("lease_id", "l-1")...)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleIssueCreds — error paths ───────────────────────────────────────────

func TestHandleIssueCreds_BackendNotFound(t *testing.T) {
	st := baseStore()
	// getDynamicBackend returns ErrNotFound → 404.
	srv := newTestServer(t, st)
	w := call(t, srv.handleIssueCreds, http.MethodPost, "/", "",
		ownerTok(), secretPV("name", "no-such-backend", "role", "ro")...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body: %s", w.Code, w.Body)
	}
}

func TestHandleIssueCreds_RoleNotFound(t *testing.T) {
	st := baseStore()
	st.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
		return fakeBackend(), nil
	}
	// getDynamicRole returns ErrNotFound → 404.
	srv := newTestServer(t, st)
	w := call(t, srv.handleIssueCreds, http.MethodPost, "/", "",
		ownerTok(), secretPV("name", "pg-primary", "role", "no-such-role")...)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body: %s", w.Code, w.Body)
	}
}

func TestHandleIssueCreds_UnknownBackendType(t *testing.T) {
	st := baseStore()
	backend := fakeBackend()
	backend.Type = "unknown-type"
	st.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
		return backend, nil
	}
	st.getDynamicRole = func(_ context.Context, _, _ string) (*model.DynamicRole, error) {
		return &model.DynamicRole{ID: "r1", Name: "ro", RevocationTmpl: "DROP USER ...", CreatedAt: time.Now().UTC()}, nil
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleIssueCreds, http.MethodPost, "/", "",
		ownerTok(), secretPV("name", "pg-primary", "role", "ro")...)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body)
	}
}

func TestHandleIssueCreds_GetBackendDBError(t *testing.T) {
	st := baseStore()
	st.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
		return nil, errDB
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleIssueCreds, http.MethodPost, "/", "",
		ownerTok(), secretPV("name", "pg-primary", "role", "ro")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}

func TestHandleIssueCreds_GetRoleDBError(t *testing.T) {
	st := baseStore()
	st.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
		return fakeBackend(), nil
	}
	st.getDynamicRole = func(_ context.Context, _, _ string) (*model.DynamicRole, error) {
		return nil, errDB
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleIssueCreds, http.MethodPost, "/", "",
		ownerTok(), secretPV("name", "pg-primary", "role", "ro")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}

// ── handleRevokeDynamicLease — additional error paths ────────────────────────

func TestHandleRevokeDynamicLease_GetLeaseDBError(t *testing.T) {
	st := baseStore()
	st.getDynamicLease = func(_ context.Context, _ string) (*model.DynamicLease, error) {
		return nil, errDB
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleRevokeDynamicLease, http.MethodDelete, "/", "",
		ownerTok(), secretPV("lease_id", "l-1")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}

func TestHandleRevokeDynamicLease_GetBackendDBError(t *testing.T) {
	now := time.Now().UTC()
	st := baseStore()
	st.getDynamicLease = func(_ context.Context, _ string) (*model.DynamicLease, error) {
		return &model.DynamicLease{
			ID: "l-1", ProjectID: testProjID, EnvID: testEnvID, BackendID: "b-1",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}, nil
	}
	st.getDynamicBackendByID = func(_ context.Context, _ string) (*model.DynamicBackend, error) {
		return nil, errDB
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleRevokeDynamicLease, http.MethodDelete, "/", "",
		ownerTok(), secretPV("lease_id", "l-1")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}

// ── handleSetDynamicBackend — additional error paths ─────────────────────────

func TestHandleSetDynamicBackend_InvalidJSON(t *testing.T) {
	srv := newTestServer(t, baseStore())
	w := call(t, srv.handleSetDynamicBackend, http.MethodPut, "/", `{bad json`,
		ownerTok(), secretPV("name", "pg-primary")...)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ── handleGetDynamicBackend — additional error path ───────────────────────────

func TestHandleGetDynamicBackend_DBError(t *testing.T) {
	st := baseStore()
	st.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
		return nil, errDB
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleGetDynamicBackend, http.MethodGet, "/",
		"", ownerTok(), secretPV("name", "pg-primary")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}

// ── handleDeleteDynamicBackend — additional error path ────────────────────────

func TestHandleDeleteDynamicBackend_DBError(t *testing.T) {
	st := baseStore()
	st.deleteDynamicBackend = func(_ context.Context, _, _, _ string) error { return errDB }
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteDynamicBackend, http.MethodDelete, "/",
		"", ownerTok(), secretPV("name", "pg-primary")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}

// ── handleSetDynamicRole — additional error path ──────────────────────────────

func TestHandleSetDynamicRole_InvalidJSON(t *testing.T) {
	st := baseStore()
	st.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
		return fakeBackend(), nil
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleSetDynamicRole, http.MethodPut, "/", `{bad json`,
		ownerTok(), secretPV("name", "pg-primary", "role", "ro")...)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body)
	}
}

// ── handleDeleteDynamicRole — additional error path ───────────────────────────

func TestHandleDeleteDynamicRole_DBError(t *testing.T) {
	st := baseStore()
	st.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
		return fakeBackend(), nil
	}
	st.deleteDynamicRole = func(_ context.Context, _, _ string) error { return errDB }
	srv := newTestServer(t, st)
	w := call(t, srv.handleDeleteDynamicRole, http.MethodDelete, "/", "",
		ownerTok(), secretPV("name", "pg-primary", "role", "ro")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}

// ── handleListDynamicLeases — error path ──────────────────────────────────────

func TestHandleListDynamicLeases_DBError(t *testing.T) {
	st := baseStore()
	st.listDynamicLeases = func(_ context.Context, _, _ string) ([]*model.DynamicLease, error) {
		return nil, errDB
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListDynamicLeases, http.MethodGet, "/", "",
		ownerTok(), secretPV()...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}

// ── handleListDynamicRoles — error path ───────────────────────────────────────

func TestHandleListDynamicRoles_DBError(t *testing.T) {
	st := baseStore()
	st.getDynamicBackend = func(_ context.Context, _, _, _ string) (*model.DynamicBackend, error) {
		return fakeBackend(), nil
	}
	st.listDynamicRoles = func(_ context.Context, _ string) ([]*model.DynamicRole, error) {
		return nil, errDB
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListDynamicRoles, http.MethodGet, "/", "",
		ownerTok(), secretPV("name", "pg-primary")...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
	}
}
