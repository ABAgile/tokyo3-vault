package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// newTestServer returns a Server backed by the given mock store and a fixed test KEK.
// It uses NoopSink and NoopQueryStore for audit. Use newTestServerWithAudit when
// a test needs to inspect or control audit store behaviour.
func newTestServer(t *testing.T, st *mockStore) *Server {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	kp := crypto.NewLocalKeyProvider(kek)
	projectKP := crypto.NewProjectKeyCache(kp, time.Minute)
	return &Server{
		store:      st,
		kp:         kp,
		projectKP:  projectKP,
		log:        slog.Default(),
		audit:      audit.NoopSink{},
		auditStore: audit.NoopQueryStore{},
	}
}

// newTestServerWithAudit is like newTestServer but injects a custom audit.QueryStore.
func newTestServerWithAudit(t *testing.T, st *mockStore, as audit.QueryStore) *Server {
	t.Helper()
	srv := newTestServer(t, st)
	srv.auditStore = as
	return srv
}

// withToken injects tok into r's context, simulating the auth middleware.
func withToken(r *http.Request, tok *model.Token) *http.Request {
	ctx := context.WithValue(r.Context(), tokenKey, tok)
	return r.WithContext(ctx)
}

// userToken builds a minimal user session token.
func userToken(userID string) *model.Token {
	return &model.Token{ID: "tok-" + userID, UserID: &userID}
}

// machineToken builds a scoped machine token.
func machineToken(projectID, envID string, readOnly bool) *model.Token {
	tok := &model.Token{
		ID:        "machine-tok",
		ProjectID: &projectID,
		ReadOnly:  readOnly,
	}
	if envID != "" {
		tok.EnvID = &envID
	}
	return tok
}

// ── roleAtLeast ───────────────────────────────────────────────────────────────

func TestRoleAtLeast(t *testing.T) {
	tests := []struct {
		have string
		need string
		want bool
	}{
		{model.RoleViewer, model.RoleViewer, true},
		{model.RoleEditor, model.RoleViewer, true},
		{model.RoleOwner, model.RoleViewer, true},
		{model.RoleEditor, model.RoleEditor, true},
		{model.RoleOwner, model.RoleEditor, true},
		{model.RoleOwner, model.RoleOwner, true},
		{model.RoleViewer, model.RoleEditor, false},
		{model.RoleViewer, model.RoleOwner, false},
		{model.RoleEditor, model.RoleOwner, false},
		{"", model.RoleViewer, false},
	}

	for _, tc := range tests {
		got := roleAtLeast(tc.have, tc.need)
		if got != tc.want {
			t.Errorf("roleAtLeast(%q, %q) = %v, want %v", tc.have, tc.need, got, tc.want)
		}
	}
}

// ── requireWritable ───────────────────────────────────────────────────────────

func TestRequireWritable(t *testing.T) {
	s := newTestServer(t, &mockStore{})

	tests := []struct {
		name     string
		tok      *model.Token
		wantOK   bool
		wantCode int
	}{
		{"nil token allowed", nil, true, 0},
		{"non-readonly allowed", &model.Token{ReadOnly: false}, true, 0},
		{"readonly rejected", &model.Token{ReadOnly: true}, false, http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			got := s.requireWritable(w, tc.tok)
			if got != tc.wantOK {
				t.Errorf("requireWritable = %v, want %v", got, tc.wantOK)
			}
			if !tc.wantOK && w.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tc.wantCode)
			}
		})
	}
}

// ── requireUnscoped ───────────────────────────────────────────────────────────

func TestRequireUnscoped(t *testing.T) {
	s := newTestServer(t, &mockStore{})
	projID := "proj-1"

	tests := []struct {
		name   string
		tok    *model.Token
		wantOK bool
	}{
		{"nil token allowed", nil, true},
		{"user token (no ProjectID) allowed", &model.Token{}, true},
		{"scoped machine token rejected", &model.Token{ProjectID: &projID}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			got := s.requireUnscoped(w, tc.tok)
			if got != tc.wantOK {
				t.Errorf("requireUnscoped = %v, want %v", got, tc.wantOK)
			}
			if !tc.wantOK && w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", w.Code)
			}
		})
	}
}

// ── auth middleware ───────────────────────────────────────────────────────────

func TestAuthMiddlewareMissingToken(t *testing.T) {
	s := newTestServer(t, &mockStore{})
	handler := s.auth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAuthMiddlewareInvalidToken(t *testing.T) {
	s := newTestServer(t, &mockStore{
		// getTokenByHash left nil → returns store.ErrNotFound
	})
	handler := s.auth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer notavalidtoken")
	w := httptest.NewRecorder()
	handler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAuthMiddlewareExpiredToken(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	tok := &model.Token{ID: "t1", ExpiresAt: &past}

	s := newTestServer(t, &mockStore{
		getTokenByHash: func(_ context.Context, _ string) (*model.Token, error) {
			return tok, nil
		},
	})
	handler := s.auth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer sometoken")
	w := httptest.NewRecorder()
	handler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	rawToken := "validrawtoken123"
	hash := auth.HashToken(rawToken)

	future := time.Now().Add(time.Hour)
	tok := &model.Token{ID: "t1", ExpiresAt: &future}

	s := newTestServer(t, &mockStore{
		getTokenByHash: func(_ context.Context, h string) (*model.Token, error) {
			if h == hash {
				return tok, nil
			}
			return nil, store.ErrNotFound
		},
	})
	handler := s.auth(func(w http.ResponseWriter, r *http.Request) {
		if tokenFromCtx(r) == nil {
			t.Error("token not in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+rawToken)
	w := httptest.NewRecorder()
	handler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ── authorize ─────────────────────────────────────────────────────────────────

func TestAuthorize(t *testing.T) {
	const (
		projID = "project-uuid"
		envID  = "env-uuid"
		userID = "user-uuid"
	)

	memberStore := func(role string) *mockStore {
		return &mockStore{
			getUserByID: func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Role: model.UserRoleMember}, nil
			},
			getProjectMember: func(_ context.Context, pID, uID string) (*model.ProjectMember, error) {
				if pID == projID && uID == userID {
					return &model.ProjectMember{ProjectID: pID, UserID: uID, Role: role}, nil
				}
				return nil, store.ErrNotFound
			},
		}
	}

	tests := []struct {
		name     string
		st       *mockStore
		tok      *model.Token
		wantOK   bool
		wantCode int
	}{
		{
			name:     "nil token → 401",
			st:       &mockStore{},
			tok:      nil,
			wantOK:   false,
			wantCode: http.StatusUnauthorized,
		},
		{
			name:   "scoped machine token correct project+env",
			st:     &mockStore{},
			tok:    machineToken(projID, envID, false),
			wantOK: true,
		},
		{
			name:     "scoped machine token wrong project",
			st:       &mockStore{},
			tok:      machineToken("other-proj", envID, false),
			wantOK:   false,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "scoped machine token wrong env",
			st:       &mockStore{},
			tok:      machineToken(projID, "other-env", false),
			wantOK:   false,
			wantCode: http.StatusForbidden,
		},
		{
			name:   "user is project member",
			st:     memberStore(model.RoleViewer),
			tok:    userToken(userID),
			wantOK: true,
		},
		{
			name:     "user not a project member",
			st:       memberStore(model.RoleViewer),
			tok:      userToken("stranger"),
			wantOK:   false,
			wantCode: http.StatusForbidden,
		},
		{
			name: "server admin bypasses membership check",
			st: &mockStore{
				getUserByID: func(_ context.Context, id string) (*model.User, error) {
					return &model.User{ID: id, Role: model.UserRoleAdmin}, nil
				},
			},
			tok:    userToken(userID),
			wantOK: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, tc.st)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = withToken(r, tc.tok)
			w := httptest.NewRecorder()
			got := s.authorize(w, r, tc.tok, projID, envID)
			if got != tc.wantOK {
				t.Errorf("authorize = %v, want %v (HTTP %d)", got, tc.wantOK, w.Code)
			}
			if !tc.wantOK && tc.wantCode != 0 && w.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tc.wantCode)
			}
		})
	}
}
