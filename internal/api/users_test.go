package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

func adminTok() *model.Token {
	uid := "admin-user-id"
	return &model.Token{ID: "admin-tok", UserID: &uid}
}

func adminStore() *mockStore {
	return &mockStore{
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleAdmin}, nil
		},
		// Match the helper's name: an "admin store" has an admin. Otherwise
		// SCIM-create tests built on adminStore would silently trip the
		// bootstrap path and create users as admin instead of member.
		hasAdminUser: func(_ context.Context) (bool, error) { return true, nil },
	}
}

// ── handleListUsers ───────────────────────────────────────────────────────────

func TestHandleListUsers_AdminOK(t *testing.T) {
	st := adminStore()
	st.listUsers = func(_ context.Context) ([]*model.User, error) {
		return []*model.User{
			{ID: "u1", Email: "a@b.com", Role: model.UserRoleAdmin},
			{ID: "u2", Email: "c@d.com", Role: model.UserRoleMember},
		}, nil
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListUsers, http.MethodGet, "/", "", adminTok())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []userResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 2 {
		t.Errorf("len = %d, want 2", len(resp))
	}
}

func TestHandleListUsers_NonAdminRejected(t *testing.T) {
	st := &mockStore{
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListUsers, http.MethodGet, "/", "", ownerTok())
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── handleCreateUser ──────────────────────────────────────────────────────────

func TestHandleCreateUser_OK(t *testing.T) {
	st := adminStore()
	st.createUser = func(_ context.Context, email, _, role string) (*model.User, error) {
		return &model.User{ID: "new-u", Email: email, Role: role}, nil
	}
	srv := newTestServer(t, st)
	body := `{"email":"new@user.com","password":"password123","role":"member"}`
	w := call(t, srv.handleCreateUser, http.MethodPost, "/", body, adminTok())

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body)
	}
	var resp userResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Email != "new@user.com" {
		t.Errorf("email = %q", resp.Email)
	}
}

func TestHandleCreateUser_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		code int
	}{
		{"empty email", `{"email":"","password":"pass1234","role":"member"}`, http.StatusBadRequest},
		{"short password", `{"email":"a@b.com","password":"short","role":"member"}`, http.StatusBadRequest},
		{"invalid role", `{"email":"a@b.com","password":"pass1234","role":"god"}`, http.StatusBadRequest},
		{"email conflict", `{"email":"exists@b.com","password":"pass1234","role":"member"}`, http.StatusConflict},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := adminStore()
			st.createUser = func(_ context.Context, _, _, _ string) (*model.User, error) {
				if tc.code == http.StatusConflict {
					return nil, store.ErrConflict
				}
				return nil, nil
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleCreateUser, http.MethodPost, "/", tc.body, adminTok())
			if w.Code != tc.code {
				t.Errorf("status = %d, want %d", w.Code, tc.code)
			}
		})
	}
}

// ── handleLookupUser ──────────────────────────────────────────────────────────

func TestHandleLookupUser_OK(t *testing.T) {
	st := &mockStore{
		getUserByEmail: func(_ context.Context, email string) (*model.User, error) {
			return &model.User{ID: "u1", Email: email, Role: model.UserRoleMember}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleLookupUser, http.MethodGet, "/?email=alice@example.com", "", ownerTok())

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp userResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ID != "u1" {
		t.Errorf("id = %q", resp.ID)
	}
}

func TestHandleLookupUser_NotFound(t *testing.T) {
	srv := newTestServer(t, &mockStore{
		// getUserByEmail left nil → ErrNotFound
	})
	w := call(t, srv.handleLookupUser, http.MethodGet, "/?email=ghost@example.com", "", ownerTok())
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleLookupUser_MissingEmail(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	w := call(t, srv.handleLookupUser, http.MethodGet, "/", "", ownerTok())
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ── handleResetUserPassword ───────────────────────────────────────────────────

func TestHandleResetUserPassword_OK(t *testing.T) {
	updated := false
	st := adminStore()
	st.updateUserPassword = func(_ context.Context, _, _ string) error {
		updated = true
		return nil
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleResetUserPassword, http.MethodPut, "/",
		`{"password":"newpass99"}`, adminTok(), "user_id", "target-user")

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body)
	}
	if !updated {
		t.Error("UpdateUserPassword was not called")
	}
}

func TestHandleResetUserPassword_ShortPassword(t *testing.T) {
	srv := newTestServer(t, adminStore())
	w := call(t, srv.handleResetUserPassword, http.MethodPut, "/",
		`{"password":"short"}`, adminTok(), "user_id", "u1")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleResetUserPassword_UserNotFound(t *testing.T) {
	st := &mockStore{
		// getUserByID for admin check: first call is admin, second call is target user not found
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			if id == "admin-user-id" {
				return &model.User{ID: id, Role: model.UserRoleAdmin}, nil
			}
			return nil, store.ErrNotFound
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleResetUserPassword, http.MethodPut, "/",
		`{"password":"newpass99"}`, adminTok(), "user_id", "ghost")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ── handleSetUserRole ─────────────────────────────────────────────────────────

func TestHandleSetUserRole(t *testing.T) {
	type tc struct {
		name        string
		body        string
		targetRole  string
		adminCount  int
		adminCountE error
		setRoleE    error
		wantStatus  int
		wantSet     bool
	}
	cases := []tc{
		{name: "promote member to admin", body: `{"role":"admin"}`, targetRole: "member", adminCount: 1, wantStatus: http.StatusOK, wantSet: true},
		{name: "demote admin when other admin exists", body: `{"role":"member"}`, targetRole: "admin", adminCount: 2, wantStatus: http.StatusOK, wantSet: true},
		{name: "demote last admin → 409", body: `{"role":"member"}`, targetRole: "admin", adminCount: 1, wantStatus: http.StatusConflict},
		{name: "no-op when role unchanged", body: `{"role":"admin"}`, targetRole: "admin", wantStatus: http.StatusOK},
		{name: "invalid role", body: `{"role":"superuser"}`, targetRole: "member", wantStatus: http.StatusBadRequest},
		{name: "invalid JSON", body: `{bad`, targetRole: "member", wantStatus: http.StatusBadRequest},
		{name: "count error → 500", body: `{"role":"member"}`, targetRole: "admin", adminCountE: errDB, wantStatus: http.StatusInternalServerError},
		{name: "set error → 500", body: `{"role":"admin"}`, targetRole: "member", adminCount: 1, setRoleE: errDB, wantStatus: http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var setCalled bool
			st := &mockStore{
				getUserByID: func(_ context.Context, id string) (*model.User, error) {
					if id == "admin-user-id" {
						return &model.User{ID: id, Role: model.UserRoleAdmin}, nil
					}
					return &model.User{ID: id, Email: "t@example.com", Role: c.targetRole}, nil
				},
				countAdminUsers: func(_ context.Context) (int, error) { return c.adminCount, c.adminCountE },
				setUserRole: func(_ context.Context, _, _ string) error {
					setCalled = true
					return c.setRoleE
				},
			}
			srv := newTestServer(t, st)
			w := call(t, srv.handleSetUserRole, http.MethodPut, "/", c.body, adminTok(), "user_id", "target-uid")
			if w.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, c.wantStatus, w.Body)
			}
			if c.wantSet && !setCalled {
				t.Error("SetUserRole was not called")
			}
		})
	}
}

func TestHandleSetUserRole_NonAdminRejected(t *testing.T) {
	st := &mockStore{
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleSetUserRole, http.MethodPut, "/", `{"role":"admin"}`, ownerTok(), "user_id", "u1")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestHandleResetUserPassword_NonAdminRejected(t *testing.T) {
	st := &mockStore{
		getUserByID: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Role: model.UserRoleMember}, nil
		},
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleResetUserPassword, http.MethodPut, "/",
		`{"password":"newpass99"}`, ownerTok(), "user_id", "u1")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}
