package api

import (
	"net/http"
)

type accessMemberEntry struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Scope  string `json:"scope"` // "project" | "env"
}

type accessTokenEntry struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	OwnerID    *string `json:"owner_id"`
	OwnerEmail string  `json:"owner_email"`
	Scope      string  `json:"scope"` // "env" | "project" | "unscoped"
	ReadOnly   bool    `json:"read_only"`
	ExpiresAt  *string `json:"expires_at"`
	CreatedAt  string  `json:"created_at"`
}

type accessPrincipalEntry struct {
	ID          string  `json:"id"`
	SPIFFEID    *string `json:"spiffe_id,omitempty"`
	EmailSAN    *string `json:"email_san,omitempty"`
	Description string  `json:"description"`
	OwnerID     *string `json:"owner_id"`
	OwnerEmail  string  `json:"owner_email"`
	Scope       string  `json:"scope"` // "env" | "project" | "unscoped"
	ReadOnly    bool    `json:"read_only"`
	ExpiresAt   *string `json:"expires_at"`
	CreatedAt   string  `json:"created_at"`
}

type accessResponse struct {
	Members    []accessMemberEntry    `json:"members"`
	Tokens     []accessTokenEntry     `json:"tokens"`
	Principals []accessPrincipalEntry `json:"principals"`
}

// handleListAccess returns all identities that can access a project+env:
// project members (users), scoped/unscoped machine tokens, and scoped/unscoped
// SPIFFE principals. Requires at least viewer role on the project.
func (s *Server) handleListAccess(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	ctx := r.Context()

	// email lookup cache — avoids repeated store calls for the same user ID.
	emails := map[string]string{}
	lookupEmail := func(userID *string) string {
		if userID == nil {
			return ""
		}
		if e, ok := emails[*userID]; ok {
			return e
		}
		if u, err := s.store.GetUserByID(ctx, *userID); err == nil {
			emails[*userID] = u.Email
			return u.Email
		}
		return *userID
	}

	// ── members ──────────────────────────────────────────────────────────────

	projectMembers, err := s.store.ListProjectMembersWithAccess(ctx, project.ID, envID)
	if err != nil {
		s.log.Error("list access: members", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	members := make([]accessMemberEntry, 0, len(projectMembers))
	for _, m := range projectMembers {
		scope := "project"
		if m.EnvID != nil {
			scope = "env"
		}
		members = append(members, accessMemberEntry{
			UserID: m.UserID,
			Email:  lookupEmail(&m.UserID),
			Role:   m.Role,
			Scope:  scope,
		})
	}

	// ── tokens ───────────────────────────────────────────────────────────────

	rawTokens, err := s.store.ListTokensWithAccess(ctx, project.ID, envID)
	if err != nil {
		s.log.Error("list access: tokens", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	tokens := make([]accessTokenEntry, 0, len(rawTokens))
	for _, t := range rawTokens {
		entry := accessTokenEntry{
			ID:         t.ID,
			Name:       t.Name,
			OwnerID:    t.UserID,
			OwnerEmail: lookupEmail(t.UserID),
			Scope:      scopeFromPtrs(t.ProjectID, t.EnvID),
			ReadOnly:   t.ReadOnly,
			CreatedAt:  fmtAPITime(t.CreatedAt),
		}
		entry.ExpiresAt = fmtOptionalTime(t.ExpiresAt)
		tokens = append(tokens, entry)
	}

	// ── principals ───────────────────────────────────────────────────────────

	rawPrincipals, err := s.store.ListCertPrincipalsWithAccess(ctx, project.ID, envID)
	if err != nil {
		s.log.Error("list access: principals", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	principals := make([]accessPrincipalEntry, 0, len(rawPrincipals))
	for _, p := range rawPrincipals {
		entry := accessPrincipalEntry{
			ID:          p.ID,
			SPIFFEID:    p.SPIFFEID,
			EmailSAN:    p.EmailSAN,
			Description: p.Description,
			OwnerID:     p.UserID,
			OwnerEmail:  lookupEmail(p.UserID),
			Scope:       scopeFromPtrs(p.ProjectID, p.EnvID),
			ReadOnly:    p.ReadOnly,
			CreatedAt:   fmtAPITime(p.CreatedAt),
		}
		entry.ExpiresAt = fmtOptionalTime(p.ExpiresAt)
		principals = append(principals, entry)
	}

	writeJSON(w, http.StatusOK, accessResponse{
		Members:    members,
		Tokens:     tokens,
		Principals: principals,
	})
}

func scopeFromPtrs(projectID, envID *string) string {
	if projectID == nil {
		return "unscoped"
	}
	if envID == nil {
		return "project"
	}
	return "env"
}
