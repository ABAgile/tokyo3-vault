package api

import (
	"encoding/json"
	"net/http"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

type memberResponse struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

type addMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type updateMemberRequest struct {
	Role string `json:"role"`
}

func validRole(role string) bool {
	return role == model.RoleViewer || role == model.RoleEditor || role == model.RoleOwner
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

	// Verify user exists.
	if _, err := s.store.GetUserByID(r.Context(), req.UserID); err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
		s.log.Error("get user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := s.store.AddProjectMember(r.Context(), p.ID, req.UserID, req.Role); err != nil {
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

	targetUserID := r.PathValue("user_id")
	if err := s.store.UpdateProjectMember(r.Context(), p.ID, targetUserID, req.Role); err == store.ErrNotFound {
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
	if err := s.store.RemoveProjectMember(r.Context(), p.ID, targetUserID); err == store.ErrNotFound {
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
