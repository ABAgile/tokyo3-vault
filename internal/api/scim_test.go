package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// scimCall sends a request directly to a handler (bypassing auth middleware),
// optionally injecting a bearer token header.
func scimCall(t *testing.T, _ *Server, handler http.HandlerFunc, method, path, body, bearerToken string, pathKV ...string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if bearerToken != "" {
		r.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	// Set path values (key, value pairs).
	for i := 0; i+1 < len(pathKV); i += 2 {
		r.SetPathValue(pathKV[i], pathKV[i+1])
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

// ── scimAuth ──────────────────────────────────────────────────────────────────

func TestScimAuth_MissingToken(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	inner := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	w := scimCall(t, srv, srv.scimAuth(inner), http.MethodGet, "/scim/v2/Users", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestScimAuth_InvalidToken(t *testing.T) {
	// Stub GetSCIMTokenByHash returns ErrNotFound → 401.
	srv := newTestServer(t, &mockStore{})
	inner := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	w := scimCall(t, srv, srv.scimAuth(inner), http.MethodGet, "/scim/v2/Users", "", "bad-token")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; body: %s", w.Code, w.Body)
	}
}

// ── writeSCIMJSON / writeSCIMError ────────────────────────────────────────────

func TestWriteSCIMJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeSCIMJSON(w, http.StatusOK, map[string]string{"key": "val"})
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/scim+json" {
		t.Errorf("Content-Type = %q, want application/scim+json", ct)
	}
}

func TestWriteSCIMError(t *testing.T) {
	w := httptest.NewRecorder()
	writeSCIMError(w, http.StatusNotFound, "not found")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["detail"] != "not found" {
		t.Errorf("detail = %v", body["detail"])
	}
}

// ── requestBaseURL ────────────────────────────────────────────────────────────

func TestRequestBaseURL_HTTP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/scim/v2/Users", nil)
	r.Host = "example.com"
	got := requestBaseURL(r)
	if got != "http://example.com" {
		t.Errorf("got %q, want http://example.com", got)
	}
}

// ── scimUserResource ──────────────────────────────────────────────────────────

func TestScimUserResource(t *testing.T) {
	u := &model.User{
		ID:        "u1",
		Email:     "alice@example.com",
		Active:    true,
		CreatedAt: time.Now().UTC(),
	}
	r := scimUserResource(u, "https://vault.example.com")
	if r["id"] != "u1" {
		t.Errorf("id = %v", r["id"])
	}
	if _, ok := r["externalId"]; ok {
		t.Error("externalId should not be set when nil")
	}

	extID := "ext-123"
	u.SCIMExternalID = &extID
	r2 := scimUserResource(u, "https://vault.example.com")
	if r2["externalId"] != "ext-123" {
		t.Errorf("externalId = %v", r2["externalId"])
	}
}

// ── extractActiveBool ─────────────────────────────────────────────────────────

func TestExtractActiveBool(t *testing.T) {
	trueVal := true
	falseVal := false
	tests := []struct {
		name  string
		input any
		want  *bool
	}{
		{"bare true", true, &trueVal},
		{"bare false", false, &falseVal},
		{"object with active=true", map[string]any{"active": true}, &trueVal},
		{"object with active=false", map[string]any{"active": false}, &falseVal},
		{"object without active key", map[string]any{"other": "val"}, nil},
		{"nil", nil, nil},
		{"string", "true", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractActiveBool(tc.input)
			if tc.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", *got)
				}
			} else {
				if got == nil || *got != *tc.want {
					t.Errorf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// ── applyActiveChange ─────────────────────────────────────────────────────────

func TestApplyActiveChange_NoChange(t *testing.T) {
	// active == active → no-op.
	srv := newTestServer(t, adminStore())
	u := &model.User{ID: "u1", Active: true}
	r := httptest.NewRequest(http.MethodPatch, "/", nil)
	if err := srv.applyActiveChange(r, u, true); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestApplyActiveChange_Deactivate(t *testing.T) {
	srv := newTestServer(t, adminStore())
	u := &model.User{ID: "u1", Email: "u@example.com", Active: true}
	r := withToken(httptest.NewRequest(http.MethodPatch, "/", nil), adminTok())
	if err := srv.applyActiveChange(r, u, false); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestApplyActiveChange_Activate(t *testing.T) {
	srv := newTestServer(t, adminStore())
	u := &model.User{ID: "u1", Email: "u@example.com", Active: false}
	r := withToken(httptest.NewRequest(http.MethodPatch, "/", nil), adminTok())
	if err := srv.applyActiveChange(r, u, true); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// ── handleSCIMServiceProviderConfig ──────────────────────────────────────────

func TestHandleSCIMServiceProviderConfig(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := scimCall(t, srv, srv.handleSCIMServiceProviderConfig, http.MethodGet, "/scim/v2/ServiceProviderConfig", "", "")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["patch"]; !ok {
		t.Error("expected 'patch' key in response")
	}
}

// ── handleSCIMResourceTypes ───────────────────────────────────────────────────

func TestHandleSCIMResourceTypes(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := scimCall(t, srv, srv.handleSCIMResourceTypes, http.MethodGet, "/scim/v2/ResourceTypes", "", "")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["totalResults"].(float64) != 2 {
		t.Errorf("totalResults = %v, want 2", body["totalResults"])
	}
}

// ── handleSCIMSchemas ─────────────────────────────────────────────────────────

func TestHandleSCIMSchemas(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := scimCall(t, srv, srv.handleSCIMSchemas, http.MethodGet, "/scim/v2/Schemas", "", "")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ── handleSCIMListUsers ───────────────────────────────────────────────────────

func TestHandleSCIMListUsers(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		st := &mockStore{
			listUsers: func(_ context.Context) ([]*model.User, error) {
				return []*model.User{
					{ID: "u1", Email: "alice@example.com", Active: true, CreatedAt: time.Now().UTC()},
				}, nil
			},
		}
		srv := newTestServer(t, st)
		w := scimCall(t, srv, srv.handleSCIMListUsers, http.MethodGet, "/scim/v2/Users", "", "")
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body)
		}
		var body map[string]any
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["totalResults"].(float64) != 1 {
			t.Errorf("totalResults = %v, want 1", body["totalResults"])
		}
	})

	t.Run("db error", func(t *testing.T) {
		st := &mockStore{
			listUsers: func(_ context.Context) ([]*model.User, error) { return nil, errDB },
		}
		srv := newTestServer(t, st)
		w := scimCall(t, srv, srv.handleSCIMListUsers, http.MethodGet, "/scim/v2/Users", "", "")
		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", w.Code)
		}
	})
}

// ── scimUserRequest.email() ───────────────────────────────────────────────────

func TestScimUserRequestEmail(t *testing.T) {
	tests := []struct {
		name string
		req  scimUserRequest
		want string
	}{
		{
			name: "primary email",
			req: scimUserRequest{
				Emails: []struct {
					Value   string `json:"value"`
					Primary bool   `json:"primary"`
				}{
					{Value: "primary@example.com", Primary: true},
					{Value: "secondary@example.com", Primary: false},
				},
			},
			want: "primary@example.com",
		},
		{
			name: "fallback to first email",
			req: scimUserRequest{
				Emails: []struct {
					Value   string `json:"value"`
					Primary bool   `json:"primary"`
				}{
					{Value: "first@example.com", Primary: false},
				},
			},
			want: "first@example.com",
		},
		{
			name: "fallback to userName",
			req:  scimUserRequest{UserName: "USERNAME@EXAMPLE.COM"},
			want: "username@example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.req.email()
			if got != tc.want {
				t.Errorf("email() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ── handleSCIMCreateUser ──────────────────────────────────────────────────────

func TestHandleSCIMCreateUser(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name: "creates new user",
			body: `{"userName":"bob@example.com","emails":[{"value":"bob@example.com","primary":true}]}`,
			setup: func(m *mockStore) {
				m.createUser = func(_ context.Context, email, _, _ string) (*model.User, error) {
					return &model.User{ID: "u2", Email: email, Active: true, CreatedAt: time.Now().UTC()}, nil
				}
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "with externalId",
			body: `{"userName":"ext@example.com","externalId":"ext-abc"}`,
			setup: func(m *mockStore) {
				m.createUser = func(_ context.Context, email, _, _ string) (*model.User, error) {
					return &model.User{ID: "u3", Email: email, Active: true, CreatedAt: time.Now().UTC()}, nil
				}
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "existing user returns 200",
			body: `{"userName":"existing@example.com"}`,
			setup: func(m *mockStore) {
				m.getUserByEmail = func(_ context.Context, _ string) (*model.User, error) {
					return &model.User{ID: "u1", Email: "existing@example.com", Active: true, CreatedAt: time.Now().UTC()}, nil
				}
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing userName",
			body:       `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid JSON",
			body:       `{bad`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "conflict",
			body: `{"userName":"dup@example.com"}`,
			setup: func(m *mockStore) {
				m.createUser = func(_ context.Context, _, _, _ string) (*model.User, error) {
					return nil, store.ErrConflict
				}
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "getUserByEmail DB error",
			body: `{"userName":"err@example.com"}`,
			setup: func(m *mockStore) {
				m.getUserByEmail = func(_ context.Context, _ string) (*model.User, error) {
					return nil, errDB
				}
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "createUser DB error",
			body: `{"userName":"err2@example.com"}`,
			setup: func(m *mockStore) {
				m.createUser = func(_ context.Context, _, _, _ string) (*model.User, error) {
					return nil, errDB
				}
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := adminStore()
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			r := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(tc.body))
			r = withToken(r, adminTok())
			w := httptest.NewRecorder()
			srv.handleSCIMCreateUser(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleSCIMGetUser ─────────────────────────────────────────────────────────

func TestHandleSCIMGetUser(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*mockStore)
		userID     string
		wantStatus int
	}{
		{
			name: "found",
			setup: func(m *mockStore) {
				m.getUserByID = func(_ context.Context, id string) (*model.User, error) {
					return &model.User{ID: id, Email: "u@example.com", CreatedAt: time.Now().UTC()}, nil
				}
			},
			userID:     "u1",
			wantStatus: http.StatusOK,
		},
		{
			name:       "not found",
			userID:     "no-such",
			wantStatus: http.StatusNotFound,
		},
		{
			name: "db error",
			setup: func(m *mockStore) {
				m.getUserByID = func(_ context.Context, _ string) (*model.User, error) {
					return nil, errDB
				}
			},
			userID:     "u1",
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mockStore{}
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+tc.userID, nil)
			r.SetPathValue("id", tc.userID)
			w := httptest.NewRecorder()
			srv.handleSCIMGetUser(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleSCIMReplaceUser ─────────────────────────────────────────────────────

func TestHandleSCIMReplaceUser(t *testing.T) {
	existingUser := func(m *mockStore) {
		m.getUserByID = func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "u@example.com", Active: true, CreatedAt: time.Now().UTC()}, nil
		}
	}

	tests := []struct {
		name       string
		body       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name:       "replace active=false",
			body:       `{"active":false}`,
			setup:      existingUser,
			wantStatus: http.StatusOK,
		},
		{
			name:       "replace with no active field defaults to true",
			body:       `{}`,
			setup:      existingUser,
			wantStatus: http.StatusOK,
		},
		{
			name:       "user not found",
			body:       `{"active":false}`,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "invalid JSON",
			body:       `{bad`,
			setup:      existingUser,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "getUserByID DB error",
			body: `{"active":false}`,
			setup: func(m *mockStore) {
				m.getUserByID = func(_ context.Context, _ string) (*model.User, error) {
					return nil, errDB
				}
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// "user not found" needs a bare store (no getUserByID override).
			var st *mockStore
			if tc.setup == nil {
				st = &mockStore{}
			} else {
				st = adminStore()
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			r := httptest.NewRequest(http.MethodPut, "/scim/v2/Users/u1", strings.NewReader(tc.body))
			r.SetPathValue("id", "u1")
			r = withToken(r, adminTok())
			w := httptest.NewRecorder()
			srv.handleSCIMReplaceUser(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleSCIMPatchUser ───────────────────────────────────────────────────────

func TestHandleSCIMPatchUser(t *testing.T) {
	existingUser := func(m *mockStore) {
		m.getUserByID = func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "u@example.com", Active: true, CreatedAt: time.Now().UTC()}, nil
		}
	}

	tests := []struct {
		name       string
		body       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name:       "patch active=false",
			body:       `{"Operations":[{"op":"replace","path":"active","value":false}]}`,
			setup:      existingUser,
			wantStatus: http.StatusOK,
		},
		{
			name:       "patch via object value",
			body:       `{"Operations":[{"op":"Replace","path":"","value":{"active":false}}]}`,
			setup:      existingUser,
			wantStatus: http.StatusOK,
		},
		{
			name:       "non-replace op ignored",
			body:       `{"Operations":[{"op":"add","path":"emails","value":[]}]}`,
			setup:      existingUser,
			wantStatus: http.StatusOK,
		},
		{
			name:       "user not found",
			body:       `{"Operations":[]}`,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "invalid JSON",
			body:       `{bad`,
			setup:      existingUser,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "getUserByID DB error",
			body: `{"Operations":[]}`,
			setup: func(m *mockStore) {
				m.getUserByID = func(_ context.Context, _ string) (*model.User, error) {
					return nil, errDB
				}
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var st *mockStore
			if tc.setup == nil {
				st = &mockStore{}
			} else {
				st = adminStore()
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			r := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/u1", strings.NewReader(tc.body))
			r.SetPathValue("id", "u1")
			r = withToken(r, adminTok())
			w := httptest.NewRecorder()
			srv.handleSCIMPatchUser(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleSCIMDeleteUser ──────────────────────────────────────────────────────

func TestHandleSCIMDeleteUser(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name: "success (deactivate active user)",
			setup: func(m *mockStore) {
				m.getUserByID = func(_ context.Context, id string) (*model.User, error) {
					return &model.User{ID: id, Email: "u@example.com", Active: true, CreatedAt: time.Now().UTC()}, nil
				}
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name: "already inactive — no-op deactivation, still 204",
			setup: func(m *mockStore) {
				m.getUserByID = func(_ context.Context, id string) (*model.User, error) {
					return &model.User{ID: id, Email: "u@example.com", Active: false, CreatedAt: time.Now().UTC()}, nil
				}
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "user not found",
			wantStatus: http.StatusNotFound,
		},
		{
			name: "getUserByID DB error",
			setup: func(m *mockStore) {
				m.getUserByID = func(_ context.Context, _ string) (*model.User, error) {
					return nil, errDB
				}
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var st *mockStore
			if tc.setup == nil {
				st = &mockStore{}
			} else {
				st = adminStore()
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			r := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/u1", nil)
			r.SetPathValue("id", "u1")
			r = withToken(r, adminTok())
			w := httptest.NewRecorder()
			srv.handleSCIMDeleteUser(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── scimGroupResource ─────────────────────────────────────────────────────────

func TestScimGroupResource(t *testing.T) {
	r := scimGroupResource("gr-1", "Engineering", "ext-123", "https://vault.example.com", []string{"u1", "u2"})
	if r["id"] != "gr-1" {
		t.Errorf("id = %v", r["id"])
	}
	if r["externalId"] != "ext-123" {
		t.Errorf("externalId = %v", r["externalId"])
	}
	members := r["members"].([]map[string]any)
	if len(members) != 2 {
		t.Errorf("members len = %d, want 2", len(members))
	}

	// No externalId when empty.
	r2 := scimGroupResource("gr-2", "Ops", "", "https://vault.example.com", nil)
	if _, ok := r2["externalId"]; ok {
		t.Error("externalId should not be set when empty")
	}
}

// ── handleSCIMListGroups ──────────────────────────────────────────────────────

func TestHandleSCIMListGroups(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		srv := newTestServer(t, &mockStore{})
		w := scimCall(t, srv, srv.handleSCIMListGroups, http.MethodGet, "/scim/v2/Groups", "", "")
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("with data", func(t *testing.T) {
		st := &mockStore{
			listSCIMGroupRoles: func(_ context.Context) ([]*model.SCIMGroupRole, error) {
				return []*model.SCIMGroupRole{
					{ID: "gr-1", GroupID: "g1", DisplayName: "Eng", Role: model.RoleEditor, CreatedAt: time.Now().UTC()},
				}, nil
			},
		}
		srv := newTestServer(t, st)
		w := scimCall(t, srv, srv.handleSCIMListGroups, http.MethodGet, "/scim/v2/Groups", "", "")
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
		var body map[string]any
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["totalResults"].(float64) != 1 {
			t.Errorf("totalResults = %v, want 1", body["totalResults"])
		}
	})

	t.Run("db error", func(t *testing.T) {
		st := &mockStore{
			listSCIMGroupRoles: func(_ context.Context) ([]*model.SCIMGroupRole, error) {
				return nil, errDB
			},
		}
		srv := newTestServer(t, st)
		w := scimCall(t, srv, srv.handleSCIMListGroups, http.MethodGet, "/scim/v2/Groups", "", "")
		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", w.Code)
		}
	})
}

// ── handleSCIMCreateGroup ─────────────────────────────────────────────────────

func TestHandleSCIMCreateGroup(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "valid with members",
			body:       `{"displayName":"Engineering","members":[{"value":"u1"}]}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "valid with externalId (used as groupID)",
			body:       `{"displayName":"Ops","externalId":"okta-grp-123"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "missing displayName",
			body:       `{"members":[]}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid JSON",
			body:       `{bad`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, adminStore())
			r := httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", strings.NewReader(tc.body))
			r = withToken(r, adminTok())
			w := httptest.NewRecorder()
			srv.handleSCIMCreateGroup(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleSCIMGetGroup ────────────────────────────────────────────────────────

func TestHandleSCIMGetGroup(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*mockStore)
		id         string
		wantStatus int
	}{
		{
			name: "found",
			setup: func(m *mockStore) {
				m.getSCIMGroupRole = func(_ context.Context, id string) (*model.SCIMGroupRole, error) {
					return &model.SCIMGroupRole{ID: id, DisplayName: "Eng", CreatedAt: time.Now().UTC()}, nil
				}
			},
			id:         "gr-1",
			wantStatus: http.StatusOK,
		},
		{
			name:       "not found",
			id:         "no-such",
			wantStatus: http.StatusNotFound,
		},
		{
			name: "db error",
			setup: func(m *mockStore) {
				m.getSCIMGroupRole = func(_ context.Context, _ string) (*model.SCIMGroupRole, error) {
					return nil, errDB
				}
			},
			id:         "gr-1",
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mockStore{}
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/"+tc.id, nil)
			r.SetPathValue("id", tc.id)
			w := httptest.NewRecorder()
			srv.handleSCIMGetGroup(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleSCIMReplaceGroup ────────────────────────────────────────────────────

func TestHandleSCIMReplaceGroup(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "valid",
			body:       `{"displayName":"Engineering","members":[{"value":"u1"}]}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid JSON",
			body:       `{bad`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, adminStore())
			r := httptest.NewRequest(http.MethodPut, "/scim/v2/Groups/gr-1", strings.NewReader(tc.body))
			r.SetPathValue("id", "gr-1")
			r = withToken(r, adminTok())
			w := httptest.NewRecorder()
			srv.handleSCIMReplaceGroup(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleSCIMPatchGroup ──────────────────────────────────────────────────────

func TestHandleSCIMPatchGroup(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name: "replace displayName (group exists in store)",
			body: `{"Operations":[{"op":"replace","path":"displayName","value":"New Name"}]}`,
			setup: func(m *mockStore) {
				m.getSCIMGroupRole = func(_ context.Context, id string) (*model.SCIMGroupRole, error) {
					return &model.SCIMGroupRole{ID: id, DisplayName: "Old Name"}, nil
				}
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "replace displayName (group not found is ok)",
			body:       `{"Operations":[{"op":"replace","path":"displayName","value":"New Name"}]}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "add member op",
			body:       `{"Operations":[{"op":"add","path":"members","value":[{"value":"u2"}]}]}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid JSON",
			body:       `{bad`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := adminStore()
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			r := httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/gr-1", strings.NewReader(tc.body))
			r.SetPathValue("id", "gr-1")
			r = withToken(r, adminTok())
			w := httptest.NewRecorder()
			srv.handleSCIMPatchGroup(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleSCIMDeleteGroup ─────────────────────────────────────────────────────

func TestHandleSCIMDeleteGroup(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name:       "success",
			wantStatus: http.StatusNoContent,
		},
		{
			name: "not found is still 204 (idempotent)",
			setup: func(m *mockStore) {
				m.deleteSCIMGroupRole = func(_ context.Context, _ string) error { return store.ErrNotFound }
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name: "db error → 500",
			setup: func(m *mockStore) {
				m.deleteSCIMGroupRole = func(_ context.Context, _ string) error { return errDB }
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := adminStore()
			if tc.setup != nil {
				tc.setup(st)
			}
			srv := newTestServer(t, st)
			r := httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/gr-1", nil)
			r.SetPathValue("id", "gr-1")
			w := httptest.NewRecorder()
			srv.handleSCIMDeleteGroup(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── syncGroupMembers ──────────────────────────────────────────────────────────

func TestSyncGroupMembers(t *testing.T) {
	srv := newTestServer(t, adminStore())
	r := withToken(httptest.NewRequest(http.MethodPost, "/", nil), adminTok())
	members := []struct {
		Value string `json:"value"`
	}{
		{Value: "u1"},
	}
	if err := srv.syncGroupMembers(r, "g1", "Eng", members); err != nil {
		t.Errorf("syncGroupMembers: %v", err)
	}
}

func TestSyncGroupMembers_WithRoles(t *testing.T) {
	p := testProjID
	st := adminStore()
	st.listSCIMGroupRolesByGroup = func(_ context.Context, _ string) ([]*model.SCIMGroupRole, error) {
		return []*model.SCIMGroupRole{
			{ID: "gr-1", GroupID: "g1", ProjectID: &p, Role: model.RoleEditor},
		}, nil
	}
	srv := newTestServer(t, st)
	r := withToken(httptest.NewRequest(http.MethodPost, "/", nil), adminTok())
	members := []struct {
		Value string `json:"value"`
	}{
		{Value: "u1"},
	}
	if err := srv.syncGroupMembers(r, "g1", "Eng", members); err != nil {
		t.Errorf("syncGroupMembers with roles: %v", err)
	}
}
