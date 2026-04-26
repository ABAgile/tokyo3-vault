package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/abagile/tokyo3-vault/internal/model"
)

// TestScopeFromPtrs tests the scopeFromPtrs helper.
func TestScopeFromPtrs(t *testing.T) {
	projID := "proj-1"
	envID := "env-1"

	tests := []struct {
		name      string
		projectID *string
		envID     *string
		want      string
	}{
		{"nil projectID", nil, nil, "unscoped"},
		{"project only", &projID, nil, "project"},
		{"both set", &projID, &envID, "env"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scopeFromPtrs(tc.projectID, tc.envID)
			if got != tc.want {
				t.Errorf("scopeFromPtrs = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHandleListAccess_HappyPath tests the normal case.
func TestHandleListAccess_HappyPath(t *testing.T) {
	uid := testUserID
	st := baseStore()

	st.listProjectMembersWithAccess = func(_ context.Context, _, _ string) ([]*model.ProjectMember, error) {
		return []*model.ProjectMember{
			{ProjectID: testProjID, UserID: uid, Role: model.RoleOwner},
		}, nil
	}
	st.listTokensWithAccess = func(_ context.Context, _, _ string) ([]*model.Token, error) {
		projID := testProjID
		return []*model.Token{
			{ID: "tok-1", Name: "ci", ProjectID: &projID},
		}, nil
	}
	st.listCertPrincipalsWithAccess = func(_ context.Context, _, _ string) ([]*model.CertPrincipal, error) {
		spiffeID := "spiffe://cluster.local/ns/x/sa/y"
		return []*model.CertPrincipal{
			{ID: "cp-1", Description: "workload", SPIFFEID: &spiffeID, UserID: &uid},
		}, nil
	}
	st.getUserByID = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Email: id + "@test.com", Role: model.UserRoleMember}, nil
	}

	srv := newTestServer(t, st)
	w := call(t, srv.handleListAccess, http.MethodGet, "/", "", ownerTok(), secretPV()...)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}

	var resp accessResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Members) != 1 {
		t.Errorf("members len = %d, want 1", len(resp.Members))
	}
	if len(resp.Tokens) != 1 {
		t.Errorf("tokens len = %d, want 1", len(resp.Tokens))
	}
	if len(resp.Principals) != 1 {
		t.Errorf("principals len = %d, want 1", len(resp.Principals))
	}
	if resp.Members[0].Scope != "project" {
		t.Errorf("member scope = %q, want project", resp.Members[0].Scope)
	}
}

// TestHandleListAccess_MembersError tests members store error.
func TestHandleListAccess_MembersError(t *testing.T) {
	st := baseStore()
	st.listProjectMembersWithAccess = func(_ context.Context, _, _ string) ([]*model.ProjectMember, error) {
		return nil, errors.New("db failure")
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListAccess, http.MethodGet, "/", "", ownerTok(), secretPV()...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// TestHandleListAccess_TokensError tests tokens store error.
func TestHandleListAccess_TokensError(t *testing.T) {
	st := baseStore()
	st.listTokensWithAccess = func(_ context.Context, _, _ string) ([]*model.Token, error) {
		return nil, errors.New("db failure")
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListAccess, http.MethodGet, "/", "", ownerTok(), secretPV()...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// TestHandleListAccess_PrincipalsError tests principals store error.
func TestHandleListAccess_PrincipalsError(t *testing.T) {
	st := baseStore()
	st.listCertPrincipalsWithAccess = func(_ context.Context, _, _ string) ([]*model.CertPrincipal, error) {
		return nil, errors.New("db failure")
	}
	srv := newTestServer(t, st)
	w := call(t, srv.handleListAccess, http.MethodGet, "/", "", ownerTok(), secretPV()...)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
