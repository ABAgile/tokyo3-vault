package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// ── handleSignup ──────────────────────────────────────────────────────────────

func TestHandleSignup_FirstUser(t *testing.T) {
	user := &model.User{ID: "u1", Email: "admin@example.com", Role: model.UserRoleAdmin}
	st := &mockStore{
		hasAdminUser: func(_ context.Context) (bool, error) { return false, nil },
		createUser: func(_ context.Context, email, _, role string) (*model.User, error) {
			if role != model.UserRoleAdmin {
				t.Errorf("first user role = %q, want admin", role)
			}
			return user, nil
		},
		createToken: func(_ context.Context, _ *model.Token) error { return nil },
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleSignup, http.MethodPost, "/", `{"email":"admin@example.com","password":"password123"}`, nil)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body)
	}
	var resp tokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" {
		t.Error("token is empty")
	}
}

func TestHandleSignup_ClosedAfterFirstUser(t *testing.T) {
	st := &mockStore{
		hasAdminUser: func(_ context.Context) (bool, error) { return true, nil },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleSignup, http.MethodPost, "/", `{"email":"x@x.com","password":"pass1234"}`, nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestHandleSignup_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		code int
	}{
		{"empty email", `{"email":"","password":"password123"}`, http.StatusBadRequest},
		{"short password", `{"email":"a@b.com","password":"short"}`, http.StatusBadRequest},
		{"missing fields", `{}`, http.StatusBadRequest},
		{"invalid json", `not-json`, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mockStore{
				hasAdminUser: func(_ context.Context) (bool, error) { return false, nil },
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleSignup, http.MethodPost, "/", tc.body, nil)
			if w.Code != tc.code {
				t.Errorf("status = %d, want %d", w.Code, tc.code)
			}
		})
	}
}

func TestHandleSignup_EmailConflict(t *testing.T) {
	st := &mockStore{
		hasAdminUser: func(_ context.Context) (bool, error) { return false, nil },
		createUser:   func(_ context.Context, _, _, _ string) (*model.User, error) { return nil, store.ErrConflict },
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleSignup, http.MethodPost, "/", `{"email":"a@b.com","password":"password123"}`, nil)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

// ── handleLogin ───────────────────────────────────────────────────────────────

func TestHandleLogin_ValidCredentials(t *testing.T) {
	hash, _ := auth.HashPassword("correctpass")
	user := &model.User{ID: "u1", Email: "a@b.com", PasswordHash: hash, Active: true}
	st := &mockStore{
		getUserByEmail: func(_ context.Context, _ string) (*model.User, error) { return user, nil },
		createToken:    func(_ context.Context, _ *model.Token) error { return nil },
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleLogin, http.MethodPost, "/", `{"email":"a@b.com","password":"correctpass"}`, nil)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp tokenResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("token is empty")
	}
}

func TestHandleLogin_InvalidCredentials(t *testing.T) {
	tests := []struct {
		name     string
		storeErr error
		password string
	}{
		{"user not found", store.ErrNotFound, "any"},
		{"wrong password", nil, "wrongpass"},
	}

	hash, _ := auth.HashPassword("correctpass")
	user := &model.User{ID: "u1", Email: "a@b.com", PasswordHash: hash}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mockStore{
				getUserByEmail: func(_ context.Context, _ string) (*model.User, error) {
					if tc.storeErr != nil {
						return nil, tc.storeErr
					}
					return user, nil
				},
			}
			srv := newTestServer(t, st)
			body := `{"email":"a@b.com","password":"` + tc.password + `"}`
			w := call(t, srv.handleLogin, http.MethodPost, "/", body, nil)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", w.Code)
			}
		})
	}
}

// ── handleLogout ──────────────────────────────────────────────────────────────

func TestHandleLogout_OK(t *testing.T) {
	deleted := false
	st := &mockStore{
		deleteToken: func(_ context.Context, _, _ string) error { deleted = true; return nil },
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleLogout, http.MethodDelete, "/", "", ownerTok())
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if !deleted {
		t.Error("DeleteToken was not called")
	}
}

func TestHandleLogout_MachineTokenRejected(t *testing.T) {
	projID := "p1"
	tok := &model.Token{ID: "mt", ProjectID: &projID}

	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleLogout, http.MethodDelete, "/", "", tok)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── handleChangePassword ──────────────────────────────────────────────────────

func TestHandleChangePassword_OK(t *testing.T) {
	hash, _ := auth.HashPassword("oldpass12")
	user := &model.User{ID: testUserID, PasswordHash: hash}
	updated := false
	st := &mockStore{
		getUserByID: func(_ context.Context, _ string) (*model.User, error) { return user, nil },
		updateUserPassword: func(_ context.Context, _, _ string) error {
			updated = true
			return nil
		},
	}

	srv := newTestServer(t, st)
	body := `{"current_password":"oldpass12","new_password":"newpass99"}`
	w := call(t, srv.handleChangePassword, http.MethodPut, "/", body, ownerTok())
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body)
	}
	if !updated {
		t.Error("UpdateUserPassword was not called")
	}
}

func TestHandleChangePassword_WrongCurrentPassword(t *testing.T) {
	hash, _ := auth.HashPassword("rightpass1")
	user := &model.User{ID: testUserID, PasswordHash: hash}
	st := &mockStore{
		getUserByID: func(_ context.Context, _ string) (*model.User, error) { return user, nil },
	}

	srv := newTestServer(t, st)
	body := `{"current_password":"wrongpass1","new_password":"newpass991"}`
	w := call(t, srv.handleChangePassword, http.MethodPut, "/", body, ownerTok())
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandleChangePassword_ShortNewPassword(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	body := `{"current_password":"oldpass12","new_password":"short"}`
	w := call(t, srv.handleChangePassword, http.MethodPut, "/", body, ownerTok())
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleChangePassword_MachineTokenRejected(t *testing.T) {
	projID := "p1"
	tok := &model.Token{ID: "mt", ProjectID: &projID}
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleChangePassword, http.MethodPut, "/", `{"current_password":"a","new_password":"b"}`, tok)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── clientIP ──────────────────────────────────────────────────────────────────

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"host:port", "1.2.3.4:5678", "", "1.2.3.4"},
		{"x-forwarded-for single", "10.0.0.1:80", "9.8.7.6", "9.8.7.6"},
		{"x-forwarded-for chain", "10.0.0.1:80", "9.8.7.6, 10.0.0.1", "9.8.7.6"},
		{"x-forwarded-for with spaces", "10.0.0.1:80", "  9.8.7.6  , 10.0.0.1", "9.8.7.6"},
	}

	srv := newTestServer(t, &mockStore{})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			got := srv.clientIP(r)
			if got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// ── requireOwner ──────────────────────────────────────────────────────────────

func TestRequireOwner(t *testing.T) {
	const projID = "proj-1"

	memberWithRole := func(role string) *mockStore {
		return &mockStore{
			getUserByID: func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Role: model.UserRoleMember}, nil
			},
			getProjectMember: func(_ context.Context, pID, _ string) (*model.ProjectMember, error) {
				return &model.ProjectMember{Role: role}, nil
			},
		}
	}

	tests := []struct {
		name   string
		st     *mockStore
		tok    *model.Token
		wantOK bool
	}{
		{"nil token rejected", &mockStore{}, nil, false},
		{"machine token rejected", &mockStore{}, machineToken(projID, "", false), false},
		{"owner allowed", memberWithRole(model.RoleOwner), userToken(testUserID), true},
		{"editor rejected", memberWithRole(model.RoleEditor), userToken(testUserID), false},
		{"viewer rejected", memberWithRole(model.RoleViewer), userToken(testUserID), false},
		{
			"server admin allowed",
			&mockStore{
				getUserByID: func(_ context.Context, id string) (*model.User, error) {
					return &model.User{ID: id, Role: model.UserRoleAdmin}, nil
				},
			},
			userToken(testUserID),
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, tc.st)
			r, _ := http.NewRequest(http.MethodDelete, "/", nil)
			r = withToken(r, tc.tok)
			w := newRecorder()
			got := srv.requireOwner(w, r, tc.tok, projID)
			if got != tc.wantOK {
				t.Errorf("requireOwner = %v, want %v (HTTP %d)", got, tc.wantOK, w.Code)
			}
		})
	}
}

// ── requireServerAdmin ────────────────────────────────────────────────────────

func TestRequireServerAdmin(t *testing.T) {
	tests := []struct {
		name   string
		st     *mockStore
		tok    *model.Token
		wantOK bool
	}{
		{
			"admin allowed",
			&mockStore{
				getUserByID: func(_ context.Context, id string) (*model.User, error) {
					return &model.User{ID: id, Role: model.UserRoleAdmin}, nil
				},
			},
			userToken(testUserID),
			true,
		},
		{
			"member rejected",
			&mockStore{
				getUserByID: func(_ context.Context, id string) (*model.User, error) {
					return &model.User{ID: id, Role: model.UserRoleMember}, nil
				},
			},
			userToken(testUserID),
			false,
		},
		{"nil token rejected", &mockStore{}, nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, tc.st)
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r = withToken(r, tc.tok)
			w := newRecorder()
			got := srv.requireServerAdmin(w, r)
			if got != tc.wantOK {
				t.Errorf("requireServerAdmin = %v, want %v", got, tc.wantOK)
			}
		})
	}
}

// newRecorder is an alias to keep test code concise.
func newRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}
