package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

// ── SCIM auth middleware ──────────────────────────────────────────────────────

// scimAuth authenticates inbound SCIM requests. Two paths, tried in order:
//
//  1. mTLS — when VAULT_SCIM_MTLS_CA + VAULT_SCIM_MTLS_SAN_DNS are configured,
//     a peer client cert whose chain validates against ClientCAs (set up in
//     vaultd's buildServerTLS) AND whose DNS SANs match the allow-list grants
//     access. No SCIM token mint needed — the cert is the credential.
//  2. Bearer token — falls back to the legacy /api/v1/scim/tokens flow.
//
// Either path is sufficient; both are safe to keep enabled simultaneously
// (e.g. SaaS callers that can't bring a cert continue to use bearer).
func (s *Server) scimAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.scimMTLSAuthorized(r) {
			next(w, r)
			return
		}
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

// scimMTLSAuthorized reports whether the request presents a peer client cert
// from a trusted IdP. Returns false (silently) if mTLS isn't configured, no
// cert was presented, or the cert's DNS SANs don't match the allow-list — the
// caller then falls through to the bearer-token path.
//
// Chain validation is already performed by the TLS layer via ClientCAs (set
// in cmd/vaultd/main.go buildServerTLS). This function only checks identity:
// at least one DNS SAN on the leaf must match a configured allow-list entry
// (case-insensitive). Bare CN is not consulted — modern x509 puts identity in
// SANs, and refusing CN avoids the well-known CN-poisoning class of bugs.
func (s *Server) scimMTLSAuthorized(r *http.Request) bool {
	if len(s.scimAllowedSANs) == 0 {
		return false
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	leaf := r.TLS.PeerCertificates[0]
	for _, san := range leaf.DNSNames {
		if slices.Contains(s.scimAllowedSANs, strings.ToLower(san)) {
			return true
		}
	}
	return false
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
	filter, err := parseSCIMFilter(r.URL.Query().Get("filter"), scimResourceUser)
	if err != nil {
		writeSCIMInvalidFilter(w, err.Error())
		return
	}
	if filter != nil {
		s.scimListUsersFiltered(w, r, filter)
		return
	}
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

// scimListUsersFiltered resolves a single-attribute eq filter against the user
// store and returns a SCIM ListResponse with 0 or 1 Resources.
func (s *Server) scimListUsersFiltered(w http.ResponseWriter, r *http.Request, filter *scimFilter) {
	var (
		user *model.User
		err  error
	)
	switch filter.Attribute {
	case "userName":
		user, err = s.store.GetUserByEmail(r.Context(), filter.Value)
	case "externalId":
		user, err = s.store.GetUserBySCIMExternalID(r.Context(), filter.Value)
	case "id":
		user, err = s.store.GetUserByID(r.Context(), filter.Value)
	default:
		writeSCIMInvalidFilter(w, "unsupported attribute: "+filter.Attribute)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMJSON(w, http.StatusOK, map[string]any{
			"schemas":      []string{scimListSchema},
			"totalResults": 0,
			"startIndex":   1,
			"itemsPerPage": 0,
			"Resources":    []any{},
		})
		return
	}
	if err != nil {
		s.log.Error("scim list users — filter lookup", "attr", filter.Attribute, "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": 1,
		"startIndex":   1,
		"itemsPerPage": 1,
		"Resources":    []any{scimUserResource(user, requestBaseURL(r))},
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

// handleSCIMCreateUser creates a new SCIM-provisioned user. Default role is
// `member`; the SCIM spec offers no clean way to express vault's platform-admin
// concept, and trusting an arbitrary IdP-supplied role attribute would let
// anyone with SCIM access mint vault admins.
//
// First-user bootstrap: when the users table has no admin yet (HasAdminUser
// returns false), the very first SCIM-provisioned user IS promoted to admin.
// This mirrors handleSignup's local first-user rule and is the only practical
// way to bootstrap an admin when VAULT_OIDC_ENFORCE=true (which closes
// /api/v1/auth/signup). The bootstrap is single-shot — every subsequent SCIM
// create lands as `member`.
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

	role := model.UserRoleMember
	hasAdmin, err := s.store.HasAdminUser(r.Context())
	if err != nil {
		s.log.Error("scim create user — check admin", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	bootstrap := !hasAdmin
	if bootstrap {
		role = model.UserRoleAdmin
		s.log.Warn("scim bootstrap: promoting first user to admin", "email", email)
	}

	// Create new OIDC user without a password. The oidc_issuer/subject will be
	// set on first OIDC login (JIT provisioning links them automatically).
	user, err := s.store.CreateUser(r.Context(), email, "", role)
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
		if err := s.store.SetUserSCIMExternalID(r.Context(), user.ID, req.ExternalID); err != nil {
			s.log.Error("scim create user — set externalId", "err", err)
			writeSCIMError(w, http.StatusInternalServerError, "internal error")
			return
		}
		extID := req.ExternalID
		user.SCIMExternalID = &extID
	}

	action := ActionSCIMUserCreate
	if bootstrap {
		action = ActionSCIMUserCreateBootstrap
	}
	if err := s.logAudit(r, action, "", email); err != nil {
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
	if req.ExternalID != "" {
		if err := s.store.SetUserSCIMExternalID(r.Context(), user.ID, req.ExternalID); err != nil {
			s.log.Error("scim replace user — set externalId", "err", err)
			writeSCIMError(w, http.StatusInternalServerError, "internal error")
			return
		}
		extID := req.ExternalID
		user.SCIMExternalID = &extID
	}
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
	filter, err := parseSCIMFilter(r.URL.Query().Get("filter"), scimResourceGroup)
	if err != nil {
		writeSCIMInvalidFilter(w, err.Error())
		return
	}
	roles, err := s.store.ListSCIMGroupRoles(r.Context())
	if err != nil {
		s.log.Error("scim list groups", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// One SCIM Group corresponds to a (possibly empty) set of scim_group_roles
	// rows that share the same scim_external_id (the IdP's group UUID). Dedupe
	// by scim_external_id so the SCIM resource id is the upstream-stable
	// identifier auth pushes on PUT/PATCH/DELETE.
	type groupView struct{ id, name string }
	seen := make(map[string]groupView, len(roles))
	order := make([]string, 0, len(roles))
	for _, gr := range roles {
		if _, ok := seen[gr.SCIMExternalID]; ok {
			continue
		}
		seen[gr.SCIMExternalID] = groupView{id: gr.SCIMExternalID, name: gr.DisplayName}
		order = append(order, gr.SCIMExternalID)
	}
	base := requestBaseURL(r)
	resources := make([]any, 0, len(order))
	for _, gid := range order {
		v := seen[gid]
		if filter != nil && !groupMatchesFilter(v.id, v.name, filter) {
			continue
		}
		resources = append(resources, scimGroupResource(v.id, v.name, v.id, base, nil))
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": len(resources),
		"startIndex":   1,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

func groupMatchesFilter(id, displayName string, f *scimFilter) bool {
	switch f.Attribute {
	case "id":
		return id == f.Value
	case "displayName":
		return displayName == f.Value
	}
	return false
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
	// externalId is the upstream group's stable UUID; it becomes the SCIM
	// resource id and the lookup key against scim_group_roles.scim_external_id.
	// A missing externalId means the upstream client can't address the group on
	// follow-up updates, so reject.
	groupID := strings.TrimSpace(req.ExternalID)
	if groupID == "" {
		writeSCIMError(w, http.StatusBadRequest, "externalId is required")
		return
	}
	// syncGroupMembers is a no-op until an admin wires up a scim_group_roles
	// row for this groupID via /portal/admin/scim-group-roles. Vault never
	// auto-creates role mappings — the group→project/role policy is admin-owned.
	if err := s.syncGroupMembers(r, groupID, req.DisplayName, req.Members, true); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	memberIDs := make([]string, 0, len(req.Members))
	for _, m := range req.Members {
		memberIDs = append(memberIDs, m.Value)
	}
	writeSCIMJSON(w, http.StatusCreated, scimGroupResource(groupID, req.DisplayName, groupID, requestBaseURL(r), memberIDs))
}

func (s *Server) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	roles, err := s.store.ListSCIMGroupRolesByExternalID(r.Context(), groupID)
	if err != nil {
		s.log.Error("scim get group", "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(roles) == 0 {
		writeSCIMError(w, http.StatusNotFound, "group not found")
		return
	}
	writeSCIMJSON(w, http.StatusOK, scimGroupResource(groupID, roles[0].DisplayName, groupID, requestBaseURL(r), nil))
}

func (s *Server) handleSCIMReplaceGroup(w http.ResponseWriter, r *http.Request) {
	// Path id is the upstream group's UUID (= scim_group_roles.scim_external_id),
	// not a row PK — auth's outbound provisioner addresses groups by their own ID.
	groupID := r.PathValue("id")
	var req scimGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.syncGroupMembers(r, groupID, req.DisplayName, req.Members, true); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	memberIDs := make([]string, 0, len(req.Members))
	for _, m := range req.Members {
		memberIDs = append(memberIDs, m.Value)
	}
	writeSCIMJSON(w, http.StatusOK, scimGroupResource(groupID, req.DisplayName, groupID, requestBaseURL(r), memberIDs))
}

func (s *Server) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
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
	if roles, err := s.store.ListSCIMGroupRolesByExternalID(r.Context(), groupID); err == nil && len(roles) > 0 {
		displayName = roles[0].DisplayName
	}
	var addedMembers []struct {
		Value string `json:"value"`
	}
	for _, op := range body.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			switch strings.ToLower(op.Path) {
			case "displayname":
				if dn, ok := op.Value.(string); ok {
					displayName = dn
				}
			case "members":
				addedMembers = append(addedMembers, parsePatchMembers(op.Value)...)
			}
		case "add":
			if strings.ToLower(op.Path) == "members" {
				addedMembers = append(addedMembers, parsePatchMembers(op.Value)...)
			}
		case "remove":
			// syncGroupMembers can only add memberships, not revoke them.
			// Removal-by-PATCH is therefore acknowledged but not applied;
			// admins must clean up project_members manually if needed.
		}
	}
	if err := s.syncGroupMembers(r, groupID, displayName, addedMembers, false); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeSCIMJSON(w, http.StatusOK, scimGroupResource(groupID, displayName, groupID, requestBaseURL(r), nil))
}

// parsePatchMembers extracts {value: "user-id"} entries from a SCIM PATCH op
// value, which IdPs serialise as either []any of map[string]any or a single
// map[string]any. Returns nil for any other shape so unrelated PATCH ops slip
// through harmlessly.
func parsePatchMembers(v any) []struct {
	Value string `json:"value"`
} {
	switch x := v.(type) {
	case []any:
		out := make([]struct {
			Value string `json:"value"`
		}, 0, len(x))
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				if id, ok := m["value"].(string); ok && id != "" {
					out = append(out, struct {
						Value string `json:"value"`
					}{Value: id})
				}
			}
		}
		return out
	case map[string]any:
		if id, ok := x["value"].(string); ok && id != "" {
			return []struct {
				Value string `json:"value"`
			}{{Value: id}}
		}
	}
	return nil
}

func (s *Server) handleSCIMDeleteGroup(w http.ResponseWriter, _ *http.Request) {
	// scim_group_roles entries are admin-owned policy and not auto-removable
	// from the SCIM surface — deleting a group upstream must not silently
	// drop role bindings here. Acknowledge the request (idempotent 204) and
	// leave existing project memberships in place; admins curate them via
	// /portal/admin/scim-group-roles.
	w.WriteHeader(http.StatusNoContent)
}

// syncGroupMembers reconciles project memberships against the desired member
// set for a SCIM group, scoped by source (scim_external_id). For each
// configured scim_group_roles row that maps this group to a (project, env, role):
//
//   - Each desired member is upserted as a SCIM-sourced project_members row.
//   - When replace is true (PUT semantics), prior SCIM-sourced rows from this
//     same source group whose user is no longer in the desired set are deleted,
//     so removal-by-omission propagates. When replace is false (PATCH "add"
//     semantics), only upserts happen — additive only.
//
// Members are scoped to this group's provenance, so admin-added rows and rows
// from other SCIM groups are never touched. The effective role visible to
// authorize/requireWrite is max-merged across all surviving rows.
func (s *Server) syncGroupMembers(r *http.Request, scimExternalID, displayName string, members []struct {
	Value string `json:"value"`
}, replace bool) error {
	roles, err := s.store.ListSCIMGroupRolesByExternalID(r.Context(), scimExternalID)
	if err != nil {
		s.log.Error("scim sync group members — list roles", "err", err)
		return err
	}
	keep := make([]string, 0, len(members))
	for _, m := range members {
		if m.Value != "" {
			keep = append(keep, m.Value)
		}
	}
	for _, gr := range roles {
		if gr.ProjectID == nil {
			continue
		}
		for _, uid := range keep {
			if err := s.store.UpsertSCIMProjectMember(r.Context(), scimExternalID, *gr.ProjectID, uid, gr.Role, gr.EnvID); err != nil {
				s.log.Warn("scim sync — upsert member", "user", uid, "project", *gr.ProjectID, "err", err)
			}
		}
		if replace {
			if err := s.store.RemoveSCIMProjectMembersExcept(r.Context(), scimExternalID, *gr.ProjectID, gr.EnvID, keep); err != nil {
				s.log.Warn("scim sync — remove leavers", "project", *gr.ProjectID, "err", err)
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
		SCIMExternalID string `json:"scim_external_id"`
		DisplayName    string `json:"display_name"`
		ProjectSlug    string `json:"project_slug"`
		EnvSlug        string `json:"env_slug"`
		Role           string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.SCIMExternalID == "" || req.ProjectSlug == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "scim_external_id, project_slug, and role are required")
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
		displayName = req.SCIMExternalID
	}
	gr, err := s.store.SetSCIMGroupRole(r.Context(), req.SCIMExternalID, displayName, &p.ID, envID, req.Role)
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
		"id":               gr.ID,
		"scim_external_id": gr.SCIMExternalID,
		"display_name":     gr.DisplayName,
		"role":             gr.Role,
		"created_at":       fmtAPITime(gr.CreatedAt),
	}
	if gr.ProjectID != nil {
		r["project_id"] = *gr.ProjectID
	}
	if gr.EnvID != nil {
		r["env_id"] = *gr.EnvID
	}
	return r
}
