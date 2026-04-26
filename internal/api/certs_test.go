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

// ── parseCertPrincipalIdentifier ──────────────────────────────────────────────

func TestParseCertPrincipalIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		req        registerPrincipalRequest
		wantSpiffe bool
		wantEmail  bool
		wantErr    bool
	}{
		{
			name:       "valid spiffe",
			req:        registerPrincipalRequest{SPIFFEID: "spiffe://cluster.local/ns/app/sa/svc"},
			wantSpiffe: true,
		},
		{
			name:      "valid email",
			req:       registerPrincipalRequest{EmailSAN: "alice@example.com"},
			wantEmail: true,
		},
		{
			name:    "neither set",
			req:     registerPrincipalRequest{},
			wantErr: true,
		},
		{
			name:    "both set",
			req:     registerPrincipalRequest{SPIFFEID: "spiffe://x", EmailSAN: "a@b.com"},
			wantErr: true,
		},
		{
			name:    "invalid spiffe scheme",
			req:     registerPrincipalRequest{SPIFFEID: "http://cluster.local/ns/app"},
			wantErr: true,
		},
		{
			name:    "invalid email",
			req:     registerPrincipalRequest{EmailSAN: "not-an-email"},
			wantErr: true,
		},
		{
			name:    "spiffe missing host",
			req:     registerPrincipalRequest{SPIFFEID: "spiffe://"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spiffeID, emailSAN, err := parseCertPrincipalIdentifier(tc.req)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantSpiffe && spiffeID == nil {
				t.Error("expected spiffeID to be set")
			}
			if tc.wantEmail && emailSAN == nil {
				t.Error("expected emailSAN to be set")
			}
		})
	}
}

// ── handleRegisterCertPrincipal ───────────────────────────────────────────────

func TestHandleRegisterCertPrincipal(t *testing.T) {
	uid := testUserID

	tests := []struct {
		name       string
		body       string
		tok        *model.Token
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name:       "valid spiffe",
			body:       `{"description":"workload","spiffe_id":"spiffe://cluster.local/ns/app/sa/svc"}`,
			tok:        ownerTok(),
			wantStatus: http.StatusCreated,
		},
		{
			name:       "valid email",
			body:       `{"description":"alice","email_san":"alice@example.com"}`,
			tok:        ownerTok(),
			wantStatus: http.StatusCreated,
		},
		{
			name:       "missing description",
			body:       `{"spiffe_id":"spiffe://cluster.local/ns/app/sa/svc"}`,
			tok:        ownerTok(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "both identifiers",
			body:       `{"description":"d","spiffe_id":"spiffe://x","email_san":"a@b.com"}`,
			tok:        ownerTok(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "no identifier",
			body:       `{"description":"d"}`,
			tok:        ownerTok(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid spiffe",
			body:       `{"description":"d","spiffe_id":"http://bad"}`,
			tok:        ownerTok(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid email",
			body:       `{"description":"d","email_san":"not-an-email"}`,
			tok:        ownerTok(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "conflict",
			body: `{"description":"d","spiffe_id":"spiffe://cluster.local/ns/dup/sa/svc"}`,
			tok:  ownerTok(),
			setup: func(m *mockStore) {
				m.createCertPrincipal = func(_ context.Context, _ *model.CertPrincipal) error { return store.ErrConflict }
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "no userID in token",
			body: `{"description":"d","spiffe_id":"spiffe://cluster.local/ns/x/sa/y"}`,
			tok: func() *model.Token {
				p := testProjID
				return &model.Token{ID: "machine-only", ProjectID: &p}
			}(),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "with expires_in",
			body:       `{"description":"expiring","spiffe_id":"spiffe://cluster.local/ns/exp/sa/svc","expires_in":"24h"}`,
			tok:        ownerTok(),
			wantStatus: http.StatusCreated,
		},
		{
			name:       "invalid expires_in",
			body:       `{"description":"d","spiffe_id":"spiffe://cluster.local/ns/exp/sa/svc","expires_in":"not-a-duration"}`,
			tok:        ownerTok(),
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mockStore{}
			st.getProject = baseStore().getProject
			st.getEnvironment = baseStore().getEnvironment
			st.getProjectMember = baseStore().getProjectMember
			st.getUserByID = func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Active: true, Role: model.UserRoleMember}, nil
			}
			// Default: createCertPrincipal succeeds.
			st.createCertPrincipal = func(_ context.Context, p *model.CertPrincipal) error {
				p.ID = "cert-id"
				return nil
			}
			if tc.setup != nil {
				tc.setup(st)
			}

			// requireUnscoped needs an unscoped token (no ProjectID).
			tok := tc.tok
			if tok == nil {
				tok = &model.Token{ID: "tok", UserID: &uid}
			}

			srv := newTestServer(t, st)
			w := call(t, srv.handleRegisterCertPrincipal, http.MethodPost, "/", tc.body, tok)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── handleListCertPrincipals ──────────────────────────────────────────────────

func TestHandleListCertPrincipals(t *testing.T) {
	uid := testUserID
	spiffeID := "spiffe://cluster.local/ns/app/sa/svc"
	now := time.Now().UTC()

	st := &mockStore{}
	st.getUserByID = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Role: model.UserRoleMember}, nil
	}
	st.listCertPrincipals = func(_ context.Context, _ string) ([]*model.CertPrincipal, error) {
		return []*model.CertPrincipal{
			{ID: "cp-1", Description: "workload", SPIFFEID: &spiffeID, UserID: &uid, CreatedAt: now},
		}, nil
	}

	srv := newTestServer(t, st)
	tok := ownerTok()
	w := call(t, srv.handleListCertPrincipals, http.MethodGet, "/", "", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp []certPrincipalResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 || resp[0].ID != "cp-1" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestHandleListCertPrincipals_NoUserID(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	p := testProjID
	tok := &model.Token{ID: "machine-only", ProjectID: &p}
	w := call(t, srv.handleListCertPrincipals, http.MethodGet, "/", "", tok)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── handleDeleteCertPrincipal ─────────────────────────────────────────────────

func TestHandleDeleteCertPrincipal(t *testing.T) {
	tests := []struct {
		name       string
		certID     string
		setup      func(*mockStore)
		wantStatus int
	}{
		{
			name:       "found",
			certID:     "cert-1",
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "not found",
			certID: "cert-missing",
			setup: func(m *mockStore) {
				m.deleteCertPrincipal = func(_ context.Context, _, _ string) error { return store.ErrNotFound }
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mockStore{}
			st.getUserByID = func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Role: model.UserRoleMember}, nil
			}
			if tc.setup != nil {
				tc.setup(st)
			}

			srv := newTestServer(t, st)
			w := call(t, srv.handleDeleteCertPrincipal, http.MethodDelete, "/", "", ownerTok(), "id", tc.certID)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
		})
	}
}

// ── certPrincipalToToken ──────────────────────────────────────────────────────

func TestCertPrincipalToToken(t *testing.T) {
	uid := "user-1"
	projID := "proj-1"
	envID := "env-1"
	now := time.Now().UTC()
	exp := now.Add(time.Hour)

	p := &model.CertPrincipal{
		ID:          "cp-1",
		UserID:      &uid,
		Description: "workload cert",
		ProjectID:   &projID,
		EnvID:       &envID,
		ReadOnly:    true,
		ExpiresAt:   &exp,
		CreatedAt:   now,
	}

	tok := certPrincipalToToken(p)
	if tok.ID != "cp-1" {
		t.Errorf("ID = %q, want cp-1", tok.ID)
	}
	if tok.UserID != &uid {
		t.Errorf("UserID mismatch")
	}
	if tok.Name != "workload cert" {
		t.Errorf("Name = %q, want 'workload cert'", tok.Name)
	}
	if tok.ProjectID != &projID {
		t.Errorf("ProjectID mismatch")
	}
	if tok.EnvID != &envID {
		t.Errorf("EnvID mismatch")
	}
	if !tok.ReadOnly {
		t.Error("ReadOnly should be true")
	}
	if tok.ExpiresAt != &exp {
		t.Errorf("ExpiresAt mismatch")
	}
}

// ── principalToResp ───────────────────────────────────────────────────────────

func TestPrincipalToResp(t *testing.T) {
	uid := "user-1"
	projID := "proj-1"
	spiffeID := "spiffe://cluster.local/ns/app/sa/svc"
	now := time.Now().UTC()
	exp := now.Add(time.Hour)

	p := &model.CertPrincipal{
		ID:          "cp-2",
		UserID:      &uid,
		Description: "my cert",
		SPIFFEID:    &spiffeID,
		ProjectID:   &projID,
		ReadOnly:    false,
		ExpiresAt:   &exp,
		CreatedAt:   now,
	}

	resp := principalToResp(p)
	if resp.ID != "cp-2" {
		t.Errorf("ID = %q", resp.ID)
	}
	if resp.SPIFFEID == nil || *resp.SPIFFEID != spiffeID {
		t.Errorf("SPIFFEID mismatch")
	}
	if resp.ExpiresAt == nil {
		t.Error("ExpiresAt should be set")
	}
}
