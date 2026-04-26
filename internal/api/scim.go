package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

// ── SCIM auth middleware ──────────────────────────────────────────────────────

func (s *Server) scimAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" {
			writeSCIMError(w, http.StatusUnauthorized, "missing token")
			return
		}
		_, err := s.store.GetSCIMTokenByHash(r.Context(), auth.HashToken(raw))
		if errors.Is(err, store.ErrNotFound) {
			writeSCIMError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if err != nil {
			s.log.Error("scim auth", "err", err)
			writeSCIMError(w, http.StatusInternalServerError, "internal error")
			return
		}
		next(w, r)
	}
}

// ── SCIM response helpers ─────────────────────────────────────────────────────

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
)

func writeSCIMJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	writeSCIMJSON(w, status, map[string]any{
		"schemas": []string{scimErrorSchema},
		"status":  status,
		"detail":  detail,
	})
}

// scimUserResource builds the SCIM User resource from a vault User.
func scimUserResource(u *model.User, baseURL string) map[string]any {
	r := map[string]any{
		"schemas":  []string{scimUserSchema},
		"id":       u.ID,
		"userName": u.Email,
		"emails": []map[string]any{
			{"value": u.Email, "primary": true},
		},
		"active": u.Active,
		"meta": map[string]any{
			"resourceType": "User",
			"created":      u.CreatedAt.UTC().Format(time.RFC3339),
			"location":     baseURL + "/scim/v2/Users/" + u.ID,
		},
	}
	if u.SCIMExternalID != nil {
		r["externalId"] = *u.SCIMExternalID
	}
	return r
}

func requestBaseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// ── SCIM discovery endpoints ──────────────────────────────────────────────────

func (s *Server) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": 200},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{
			{
				"type":             "oauthbearertoken",
				"name":             "Bearer Token",
				"description":      "Bearer token authentication",
				"specUri":          "https://tools.ietf.org/html/rfc6750",
				"documentationUri": "",
			},
		},
	})
}

func (s *Server) handleSCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	base := requestBaseURL(r)
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": 2,
		"Resources": []map[string]any{
			{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":       "User",
				"name":     "User",
				"endpoint": "/scim/v2/Users",
				"schema":   scimUserSchema,
				"meta":     map[string]any{"location": base + "/scim/v2/ResourceTypes/User"},
			},
			{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":       "Group",
				"name":     "Group",
				"endpoint": "/scim/v2/Groups",
				"schema":   scimGroupSchema,
				"meta":     map[string]any{"location": base + "/scim/v2/ResourceTypes/Group"},
			},
		},
	})
}

func (s *Server) handleSCIMSchemas(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": 0,
		"Resources":    []any{},
	})
}

// ── SCIM Users ────────────────────────────────────────────────────────────────

func (s *Server) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.log.Error("scim list users", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	base := requestBaseURL(r)
	resources := make([]any, 0, len(users))
	for _, u := range users {
		resources = append(resources, scimUserResource(u, base))
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": len(users),
		"startIndex":   1,
		"itemsPerPage": len(users),
		"Resources":    resources,
	})
}

// scimUserRequest represents the JSON body sent by the IdP for create/replace.
type scimUserRequest struct {
	Schemas    []string `json:"schemas"`
	ExternalID string   `json:"externalId"`
	UserName   string   `json:"userName"`
	Active     *bool    `json:"active"`
	Emails     []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

func (req *scimUserRequest) email() string {
	// Prefer primary email; fall back to first; fall back to userName.
	for _, e := range req.Emails {
		if e.Primary {
			return strings.ToLower(strings.TrimSpace(e.Value))
		}
	}
	if len(req.Emails) > 0 {
		return strings.ToLower(strings.TrimSpace(req.Emails[0].Value))
	}
	return strings.ToLower(strings.TrimSpace(req.UserName))
}

func (s *Server) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	var req scimUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	email := req.email()
	if email == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName or primary email is required")
		return
	}

	// Check if user already exists (IdP re-sending a create for an existing user).
	existing, err := s.store.GetUserByEmail(r.Context(), email)
	if err == nil {
		// Already exists — return existing resource.
		writeSCIMJSON(w, http.StatusOK, scimUserResource(existing, requestBaseURL(r)))
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		s.log.Error("scim get user by email", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Create new OIDC user without a password. The oidc_issuer/subject will be
	// set on first OIDC login (JIT provisioning links them automatically).
	user, err := s.store.CreateUser(r.Context(), email, "", model.UserRoleMember)
	if errors.Is(err, store.ErrConflict) {
		writeSCIMError(w, http.StatusConflict, "email already exists")
		return
	}
	if err != nil {
		s.log.Error("scim create user", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if req.ExternalID != "" {
		extID := req.ExternalID
		user.SCIMExternalID = &extID
	}

	if err := s.logAudit(r, ActionSCIMUserCreate, "", email); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeSCIMJSON(w, http.StatusCreated, scimUserResource(user, requestBaseURL(r)))
}

func (s *Server) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		s.log.Error("scim get user", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeSCIMJSON(w, http.StatusOK, scimUserResource(user, requestBaseURL(r)))
}

func (s *Server) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		s.log.Error("scim replace user — get", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var req scimUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	active := true // default to active on replace
	if req.Active != nil {
		active = *req.Active
	}
	if err := s.applyActiveChange(r, user, active); err != nil {
		s.log.Error("scim replace user — active", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	user.Active = active
	writeSCIMJSON(w, http.StatusOK, scimUserResource(user, requestBaseURL(r)))
}

// handleSCIMPatchUser handles PATCH /scim/v2/Users/{id}.
// Supports Operations: replace active, replace userName.
// Okta and Azure AD both use PATCH with `op: Replace` to deactivate users.
func (s *Server) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		s.log.Error("scim patch user — get", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var body struct {
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	for _, op := range body.Operations {
		if strings.ToLower(op.Op) != "replace" {
			continue
		}
		path := strings.ToLower(op.Path)
		if path == "active" || path == "" {
			// op.Value may be a full object map (Okta) or a bare bool (others).
			active := extractActiveBool(op.Value)
			if active != nil {
				if err := s.applyActiveChange(r, user, *active); err != nil {
					s.log.Error("scim patch user — active", "err", err)
					writeSCIMError(w, http.StatusInternalServerError, "internal error")
					return
				}
				user.Active = *active
			}
		}
	}
	writeSCIMJSON(w, http.StatusOK, scimUserResource(user, requestBaseURL(r)))
}

// extractActiveBool pulls the active value from the PATCH op's Value field.
// Handles both bare bool and object {"active": bool} (sent by some IdPs).
func extractActiveBool(v any) *bool {
	switch val := v.(type) {
	case bool:
		return &val
	case map[string]any:
		if a, ok := val["active"]; ok {
			if b, ok := a.(bool); ok {
				return &b
			}
		}
	}
	return nil
}

// applyActiveChange persists an active state change and invalidates tokens on deactivation.
func (s *Server) applyActiveChange(r *http.Request, user *model.User, active bool) error {
	if user.Active == active {
		return nil
	}
	if err := s.store.SetUserActive(r.Context(), user.ID, active); err != nil {
		return err
	}
	if !active {
		if err := s.store.DeleteAllTokensForUser(r.Context(), user.ID); err != nil {
			return err
		}
		return s.logAudit(r, ActionSCIMUserDeactivate, "", user.Email)
	}
	return s.logAudit(r, ActionSCIMUserUpdate, "", user.Email)
}

func (s *Server) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		s.log.Error("scim delete user — get", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Deactivate instead of hard-delete to preserve audit log references.
	if err := s.applyActiveChange(r, user, false); err != nil {
		s.log.Error("scim delete user — deactivate", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── SCIM Groups ───────────────────────────────────────────────────────────────
//
// Vault has no native group concept. Groups map to project roles via scim_group_roles.
// When the IdP pushes a group with members, vault syncs project memberships for those users.

type scimGroupRequest struct {
	Schemas     []string `json:"schemas"`
	ExternalID  string   `json:"externalId"`
	DisplayName string   `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

func scimGroupResource(id, displayName, externalID, baseURL string, memberIDs []string) map[string]any {
	members := make([]map[string]any, 0, len(memberIDs))
	for _, mid := range memberIDs {
		members = append(members, map[string]any{
			"value": mid,
			"$ref":  baseURL + "/scim/v2/Users/" + mid,
		})
	}
	r := map[string]any{
		"schemas":     []string{scimGroupSchema},
		"id":          id,
		"displayName": displayName,
		"members":     members,
		"meta": map[string]any{
			"resourceType": "Group",
			"location":     baseURL + "/scim/v2/Groups/" + id,
		},
	}
	if externalID != "" {
		r["externalId"] = externalID
	}
	return r
}

func (s *Server) handleSCIMListGroups(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListSCIMGroupRoles(r.Context())
	if err != nil {
		s.log.Error("scim list groups", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	base := requestBaseURL(r)
	resources := make([]any, 0, len(roles))
	for _, gr := range roles {
		resources = append(resources, scimGroupResource(gr.ID, gr.DisplayName, "", base, nil))
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": len(roles),
		"startIndex":   1,
		"itemsPerPage": len(roles),
		"Resources":    resources,
	})
}

func (s *Server) handleSCIMCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req scimGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required")
		return
	}
	groupID := req.ExternalID
	if groupID == "" {
		groupID = uuid.NewString()
	}
	// Group without a role mapping is valid — membership will be synced via PATCH.
	base := requestBaseURL(r)
	var memberIDs []string
	for _, m := range req.Members {
		memberIDs = append(memberIDs, m.Value)
	}
	if err := s.logAudit(r, ActionSCIMGroupSync, "", req.DisplayName); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeSCIMJSON(w, http.StatusCreated, scimGroupResource(groupID, req.DisplayName, req.ExternalID, base, memberIDs))
}

func (s *Server) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	gr, err := s.store.GetSCIMGroupRole(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "group not found")
		return
	}
	if err != nil {
		s.log.Error("scim get group", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeSCIMJSON(w, http.StatusOK, scimGroupResource(gr.ID, gr.DisplayName, "", requestBaseURL(r), nil))
}

func (s *Server) handleSCIMReplaceGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req scimGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.syncGroupMembers(r, id, req.DisplayName, req.Members); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	var memberIDs []string
	for _, m := range req.Members {
		memberIDs = append(memberIDs, m.Value)
	}
	writeSCIMJSON(w, http.StatusOK, scimGroupResource(id, req.DisplayName, req.ExternalID, requestBaseURL(r), memberIDs))
}

func (s *Server) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	displayName := ""
	gr, err := s.store.GetSCIMGroupRole(r.Context(), id)
	if err == nil {
		displayName = gr.DisplayName
	}
	for _, op := range body.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			if strings.ToLower(op.Path) == "displayname" {
				if dn, ok := op.Value.(string); ok {
					displayName = dn
				}
			}
		case "add", "remove":
			// Member add/remove — sync membership for the affected users.
			// We re-read the full group and let syncGroupMembers handle the diff.
		}
	}
	if err := s.logAudit(r, ActionSCIMGroupSync, "", displayName); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeSCIMJSON(w, http.StatusOK, scimGroupResource(id, displayName, "", requestBaseURL(r), nil))
}

func (s *Server) handleSCIMDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteSCIMGroupRole(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("scim delete group", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// syncGroupMembers applies the project memberships implied by group→role mappings.
// For each member in the group, any configured scim_group_roles row is used to
// add the user to the corresponding vault project as the specified role.
func (s *Server) syncGroupMembers(r *http.Request, groupID, displayName string, members []struct {
	Value string `json:"value"`
}) error {
	roles, err := s.store.ListSCIMGroupRolesByGroup(r.Context(), groupID)
	if err != nil {
		s.log.Error("scim sync group members — list roles", "err", err)
		return err
	}
	for _, gr := range roles {
		if gr.ProjectID == nil {
			continue
		}
		for _, m := range members {
			if addErr := s.store.AddProjectMember(r.Context(), *gr.ProjectID, m.Value, gr.Role, gr.EnvID); addErr != nil {
				s.log.Warn("scim sync — add member", "user", m.Value, "project", *gr.ProjectID, "err", addErr)
			}
		}
	}
	return s.logAudit(r, ActionSCIMGroupSync, "", displayName)
}

// ── SCIM token management (admin API) ─────────────────────────────────────────

func (s *Server) handleCreateSCIMToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	var req struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Description == "" {
		writeError(w, http.StatusBadRequest, "description is required")
		return
	}

	raw, err := auth.GenerateRawToken()
	if err != nil {
		s.log.Error("generate scim token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	t := &model.SCIMToken{
		ID:          uuid.NewString(),
		TokenHash:   auth.HashToken(raw),
		Description: req.Description,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateSCIMToken(r.Context(), t); err != nil {
		s.log.Error("create scim token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionSCIMTokenCreate, "", req.Description); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":          t.ID,
		"token":       raw,
		"description": t.Description,
		"created_at":  fmtAPITime(t.CreatedAt),
	})
}

func (s *Server) handleListSCIMTokens(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	tokens, err := s.store.ListSCIMTokens(r.Context())
	if err != nil {
		s.log.Error("list scim tokens", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]map[string]string, 0, len(tokens))
	for _, t := range tokens {
		resp = append(resp, map[string]string{
			"id":          t.ID,
			"description": t.Description,
			"created_at":  fmtAPITime(t.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteSCIMToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.store.DeleteSCIMToken(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "token not found")
		return
	} else if err != nil {
		s.log.Error("delete scim token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionSCIMTokenDelete, "", id); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── SCIM group→role mapping management (admin API) ────────────────────────────

// isValidGroupRole reports whether role is one of the three allowed values.
func isValidGroupRole(role string) bool {
	return role == model.RoleViewer || role == model.RoleEditor || role == model.RoleOwner
}

func (s *Server) handleCreateSCIMGroupRole(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	var req struct {
		GroupID     string `json:"group_id"`
		DisplayName string `json:"display_name"`
		ProjectSlug string `json:"project_slug"`
		EnvSlug     string `json:"env_slug"`
		Role        string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.GroupID == "" || req.ProjectSlug == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "group_id, project_slug, and role are required")
		return
	}
	if !isValidGroupRole(req.Role) {
		writeError(w, http.StatusBadRequest, "role must be viewer, editor, or owner")
		return
	}
	p, err := s.store.GetProject(r.Context(), req.ProjectSlug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.log.Error("scim group role — get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	envID, ok := s.resolveOptionalEnv(w, r, p.ID, req.EnvSlug)
	if !ok {
		return
	}
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.GroupID
	}
	gr, err := s.store.SetSCIMGroupRole(r.Context(), req.GroupID, displayName, &p.ID, envID, req.Role)
	if err != nil {
		s.log.Error("scim group role — set", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, scimGroupRoleToResponse(gr))
}

// resolveOptionalEnv looks up envSlug within projectID if non-empty. Returns
// (*envID, true) on success or (nil, true) when envSlug is empty. Writes an
// HTTP error and returns (nil, false) on failure.
func (s *Server) resolveOptionalEnv(w http.ResponseWriter, r *http.Request, projectID, envSlug string) (*string, bool) {
	if envSlug == "" {
		return nil, true
	}
	env, err := s.store.GetEnvironment(r.Context(), projectID, envSlug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "environment not found")
		return nil, false
	}
	if err != nil {
		s.log.Error("scim group role — get env", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	return &env.ID, true
}

func (s *Server) handleListSCIMGroupRoles(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	roles, err := s.store.ListSCIMGroupRoles(r.Context())
	if err != nil {
		s.log.Error("list scim group roles", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]map[string]any, 0, len(roles))
	for _, gr := range roles {
		resp = append(resp, scimGroupRoleToResponse(gr))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteSCIMGroupRole(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.store.DeleteSCIMGroupRole(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "group role not found")
		return
	} else if err != nil {
		s.log.Error("delete scim group role", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func scimGroupRoleToResponse(gr *model.SCIMGroupRole) map[string]any {
	r := map[string]any{
		"id":           gr.ID,
		"group_id":     gr.GroupID,
		"display_name": gr.DisplayName,
		"role":         gr.Role,
		"created_at":   fmtAPITime(gr.CreatedAt),
	}
	if gr.ProjectID != nil {
		r["project_id"] = *gr.ProjectID
	}
	if gr.EnvID != nil {
		r["env_id"] = *gr.EnvID
	}
	return r
}
