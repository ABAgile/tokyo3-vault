package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)


// isServerAdmin reports whether userID belongs to a user with the server-admin role.
func (s *Server) isServerAdmin(ctx context.Context, userID string) bool {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return false
	}
	return user.Role == model.UserRoleAdmin
}

type contextKey string

const tokenKey contextKey = "token"

// auth wraps a handler with authentication. Client certificate (SPIFFE/mTLS) is
// checked first when the connection has peer certificates; bearer token is the fallback.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try SPIFFE/mTLS client cert first.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			tok, err := s.authFromSPIFFECert(r)
			if err == nil {
				ctx := context.WithValue(r.Context(), tokenKey, tok)
				next(w, r.WithContext(ctx))
				return
			}
			// errSPIFFEUnregistered: cert present but no matching principal → fall through to bearer.
			// Any other error (e.g. expired): explicit denial.
			if err != errSPIFFEUnregistered {
				writeError(w, http.StatusUnauthorized, err.Error())
				return
			}
		}

		// Bearer token fallback.
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "missing token")
			return
		}
		tok, err := auth.Validate(r.Context(), s.store, raw)
		if err == store.ErrNotFound {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if err != nil {
			s.log.Error("auth lookup", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if tok.ExpiresAt != nil && time.Now().UTC().After(*tok.ExpiresAt) {
			writeError(w, http.StatusUnauthorized, "token expired")
			return
		}
		ctx := context.WithValue(r.Context(), tokenKey, tok)
		next(w, r.WithContext(ctx))
	}
}

// tokenFromCtx retrieves the authenticated token from the request context.
func tokenFromCtx(r *http.Request) *model.Token {
	t, _ := r.Context().Value(tokenKey).(*model.Token)
	return t
}

// authorize checks that tok is permitted to access projectID and optionally envID.
//
//   - Machine tokens (ProjectID set): scope check only.
//   - User session tokens (ProjectID nil): project_members lookup.
//
// Returns false and writes the appropriate error on denial.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, tok *model.Token, projectID, envID string) bool {
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return false
	}

	if tok.ProjectID != nil {
		// Machine token: enforce explicit scope.
		if *tok.ProjectID != projectID {
			writeError(w, http.StatusForbidden, "token not authorized for this project")
			return false
		}
		if envID != "" && tok.EnvID != nil && *tok.EnvID != envID {
			writeError(w, http.StatusForbidden, "token not authorized for this environment")
			return false
		}
		return true
	}

	// User / unscoped token: check project membership.
	if tok.UserID == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	// Server admins have implicit access to every project.
	if s.isServerAdmin(r.Context(), *tok.UserID) {
		return true
	}
	// When an env is specified, accept either an env-specific or project-level membership.
	var err error
	if envID != "" {
		_, err = s.store.GetProjectMemberForEnv(r.Context(), projectID, envID, *tok.UserID)
	} else {
		_, err = s.store.GetProjectMember(r.Context(), projectID, *tok.UserID)
	}
	if err == store.ErrNotFound {
		writeError(w, http.StatusForbidden, "not a member of this project")
		return false
	}
	if err != nil {
		s.log.Error("get project member", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return false
	}
	return true
}

// requireWritable returns false and writes 403 if the token is read-only.
// Use this for global (non-project-level) write operations where there is no projectID to look up.
// For project-level writes, use requireWrite instead.
func (s *Server) requireWritable(w http.ResponseWriter, tok *model.Token) bool {
	if tok != nil && tok.ReadOnly {
		writeError(w, http.StatusForbidden, "token is read-only")
		return false
	}
	return true
}

// requireUnscoped returns false and writes 403 if the token is scoped to a specific project.
// Use this on routes that manage projects/tokens globally (e.g. create project, list projects).
func (s *Server) requireUnscoped(w http.ResponseWriter, tok *model.Token) bool {
	if tok != nil && tok.ProjectID != nil {
		writeError(w, http.StatusForbidden, "scoped machine tokens cannot perform this action")
		return false
	}
	return true
}

// requireWrite checks that the token can perform write operations on projectID.
//
//   - Any token with ReadOnly=true is rejected immediately.
//   - Scoped machine tokens (ProjectID set): ReadOnly check is sufficient (scope already verified).
//   - User / unscoped tokens: must have editor role or higher in the project.
func (s *Server) requireWrite(w http.ResponseWriter, r *http.Request, tok *model.Token, projectID string) bool {
	if tok != nil && tok.ReadOnly {
		writeError(w, http.StatusForbidden, "token is read-only")
		return false
	}
	if tok != nil && tok.ProjectID != nil {
		// Scoped machine token that is not read-only: write already authorized by scope.
		return true
	}
	return s.requireProjectRole(w, r, projectID, model.RoleEditor)
}

// requireOwner checks that the token's user is the owner of projectID.
// Scoped machine tokens are always rejected — ownership is a human concept.
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request, tok *model.Token, projectID string) bool {
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return false
	}
	if tok.ProjectID != nil {
		writeError(w, http.StatusForbidden, "only project owners can perform this action")
		return false
	}
	return s.requireProjectRole(w, r, projectID, model.RoleOwner)
}

// requireServerAdmin returns false and writes 403 if the token's user is not a server admin.
func (s *Server) requireServerAdmin(w http.ResponseWriter, r *http.Request) bool {
	tok := tokenFromCtx(r)
	if tok == nil || tok.UserID == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	user, err := s.store.GetUserByID(r.Context(), *tok.UserID)
	if err != nil {
		s.log.Error("get user for admin check", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return false
	}
	if user.Role != model.UserRoleAdmin {
		writeError(w, http.StatusForbidden, "server admin access required")
		return false
	}
	return true
}

// requireProjectRole verifies the token's user has at least minRole in the project.
// Server admins bypass the membership check and are treated as owners of every project.
func (s *Server) requireProjectRole(w http.ResponseWriter, r *http.Request, projectID, minRole string) bool {
	tok := tokenFromCtx(r)
	if tok == nil || tok.UserID == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	// Server admins implicitly hold owner-level access to every project.
	if s.isServerAdmin(r.Context(), *tok.UserID) {
		return true
	}
	m, err := s.store.GetProjectMember(r.Context(), projectID, *tok.UserID)
	if err == store.ErrNotFound {
		writeError(w, http.StatusForbidden, "not a member of this project")
		return false
	}
	if err != nil {
		s.log.Error("get project member", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return false
	}
	if !roleAtLeast(m.Role, minRole) {
		writeError(w, http.StatusForbidden, "requires "+minRole+" role or higher")
		return false
	}
	return true
}

// roleAtLeast returns true if have >= need in the privilege hierarchy.
func roleAtLeast(have, need string) bool {
	rank := map[string]int{
		model.RoleViewer: 1,
		model.RoleEditor: 2,
		model.RoleOwner:  3,
	}
	return rank[have] >= rank[need]
}
