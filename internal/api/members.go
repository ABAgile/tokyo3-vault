package api

import (
	"encoding/json"
	"net/http"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

type memberResponse struct {
	UserID    string  `json:"user_id"`
	Email     string  `json:"email"`
	Role      string  `json:"role"`
	Scope     string  `json:"scope"`           // "project" | "env"
	EnvID     *string `json:"env_id,omitempty"` // populated when scope = "env"
	CreatedAt string  `json:"created_at"`
}

type addMemberRequest struct {
	UserID string  `json:"user_id"`
	Role   string  `json:"role"`
	EnvID  *string `json:"env_id,omitempty"`
}

type updateMemberRequest struct {
	Role  string  `json:"role"`
	EnvID *string `json:"env_id,omitempty"` // identifies which row to update
}

func validRole(role string) bool {
	return role == model.RoleViewer || role == model.RoleEditor || role == model.RoleOwner
}

func memberScope(m *model.ProjectMember) string {
	if m.EnvID == nil {
		return "project"
	}
	return "env"
}

// handleListMembers lists all members of a project. Requires viewer+ role.
func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetProject(r.Context(), r.PathValue("project"))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !s.authorize(w, r, tokenFromCtx(r), p.ID, "") {
		return
	}

	members, err := s.store.ListProjectMembers(r.Context(), p.ID)
	if err != nil {
		s.log.Error("list members", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	resp := make([]memberResponse, 0, len(members))
	for _, m := range members {
		mr := memberResponse{
			UserID:    m.UserID,
			Role:      m.Role,
			Scope:     memberScope(m),
			EnvID:     m.EnvID,
			CreatedAt: m.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if u, err := s.store.GetUserByID(r.Context(), m.UserID); err == nil {
			mr.Email = u.Email
		}
		resp = append(resp, mr)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAddMember adds a user to the project. Requires owner role.
func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	p, err := s.store.GetProject(r.Context(), r.PathValue("project"))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !s.requireOwner(w, r, tok, p.ID) {
		return
	}

	var req addMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	if !validRole(req.Role) {
		writeError(w, http.StatusBadRequest, "role must be viewer, editor, or owner")
		return
	}
	if req.EnvID != nil && req.Role == model.RoleOwner {
		writeError(w, http.StatusBadRequest, "owner role cannot be scoped to a single environment")
		return
	}

	// Verify user exists.
	if _, err := s.store.GetUserByID(r.Context(), req.UserID); err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
		s.log.Error("get user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := s.store.AddProjectMember(r.Context(), p.ID, req.UserID, req.Role, req.EnvID); err != nil {
		s.log.Error("add member", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.logAudit(r, ActionMemberAdd, p.ID, req.UserID)
	w.WriteHeader(http.StatusNoContent)
}

// handleUpdateMember changes a member's role. Requires owner role.
func (s *Server) handleUpdateMember(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	p, err := s.store.GetProject(r.Context(), r.PathValue("project"))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !s.requireOwner(w, r, tok, p.ID) {
		return
	}

	var req updateMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !validRole(req.Role) {
		writeError(w, http.StatusBadRequest, "role must be viewer, editor, or owner")
		return
	}
	if req.EnvID != nil && req.Role == model.RoleOwner {
		writeError(w, http.StatusBadRequest, "owner role cannot be scoped to a single environment")
		return
	}

	targetUserID := r.PathValue("user_id")
	if err := s.store.UpdateProjectMember(r.Context(), p.ID, targetUserID, req.Role, req.EnvID); err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "member not found")
		return
	} else if err != nil {
		s.log.Error("update member", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.logAudit(r, ActionMemberUpdate, p.ID, targetUserID)
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveMember removes a user from the project. Requires owner role.
// Optional query param ?env_id=<env-db-id> targets an env-scoped row; absent = project-level row.
func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	p, err := s.store.GetProject(r.Context(), r.PathValue("project"))
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !s.requireOwner(w, r, tok, p.ID) {
		return
	}

	targetUserID := r.PathValue("user_id")
	var envID *string
	if raw := r.URL.Query().Get("env_id"); raw != "" {
		envID = &raw
	}

	if err := s.store.RemoveProjectMember(r.Context(), p.ID, targetUserID, envID); err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "member not found")
		return
	} else if err != nil {
		s.log.Error("remove member", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.logAudit(r, ActionMemberRemove, p.ID, targetUserID)
	w.WriteHeader(http.StatusNoContent)
}
