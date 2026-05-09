package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

type userResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"` // "member" | "admin"
}

func userToResponse(u *model.User) userResponse {
	return userResponse{
		ID:        u.ID,
		Email:     u.Email,
		Role:      u.Role,
		CreatedAt: fmtAPITime(u.CreatedAt),
	}
}

// handleListUsers returns all users. Server admin only.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.log.Error("list users", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]userResponse, 0, len(users))
	for _, u := range users {
		resp = append(resp, userToResponse(u))
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleCreateUser lets a server admin create a new user with a given role.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if !validatePassword(w, req.Password) {
		return
	}
	if req.Role != model.UserRoleAdmin && req.Role != model.UserRoleMember {
		writeError(w, http.StatusBadRequest, "role must be member or admin")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.log.Error("hash password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	user, err := s.store.CreateUser(r.Context(), req.Email, hash, req.Role)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}
	if err != nil {
		s.log.Error("create user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionUserCreate, "", user.Email); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, userToResponse(user))
}

// handleResetUserPassword lets a server admin set a new password for any user
// without requiring the current password.
func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !validatePassword(w, req.Password) {
		return
	}
	targetUserID := r.PathValue("user_id")
	_, err := s.store.GetUserByID(r.Context(), targetUserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		s.log.Error("get user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.log.Error("hash password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), targetUserID, hash); err != nil {
		s.log.Error("update password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.store.DeleteAllTokensForUser(r.Context(), targetUserID); err != nil {
		s.log.Error("revoke tokens after password reset", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionAuthChangePassword, "", targetUserID); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSetUserRole lets a server admin promote/demote another (or themselves)
// between member and admin. Rejects the demotion that would leave the system
// with zero admins (last-admin guard) so vault stays administrable.
func (s *Server) handleSetUserRole(w http.ResponseWriter, r *http.Request) {
	if !s.requireServerAdmin(w, r) {
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Role != model.UserRoleAdmin && req.Role != model.UserRoleMember {
		writeError(w, http.StatusBadRequest, "role must be member or admin")
		return
	}
	targetUserID := r.PathValue("user_id")
	target, err := s.store.GetUserByID(r.Context(), targetUserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		s.log.Error("get user for role change", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if target.Role == req.Role {
		writeJSON(w, http.StatusOK, userToResponse(target))
		return
	}
	if target.Role == model.UserRoleAdmin && req.Role == model.UserRoleMember {
		count, err := s.store.CountAdminUsers(r.Context())
		if err != nil {
			s.log.Error("count admins", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if count <= 1 {
			writeError(w, http.StatusConflict, "cannot demote the last admin — promote another user first")
			return
		}
	}
	if err := s.store.SetUserRole(r.Context(), targetUserID, req.Role); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		s.log.Error("set user role", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	target.Role = req.Role
	if err := s.logAudit(r, ActionUserSetRole, "", target.Email); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusOK, userToResponse(target))
}

// handleLookupUser resolves an email address to a user ID.
// Any authenticated token may call this (used by "vault members add --email").
func (s *Server) handleLookupUser(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("email")))
	if email == "" {
		writeError(w, http.StatusBadRequest, "email query parameter is required")
		return
	}
	user, err := s.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		s.log.Error("lookup user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, userToResponse(user))
}
