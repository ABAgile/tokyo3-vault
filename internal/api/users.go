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
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
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
	s.logAudit(r, ActionUserCreate, "", user.Email)
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
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	targetUserID := r.PathValue("user_id")
	if _, err := s.store.GetUserByID(r.Context(), targetUserID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
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
	s.logAudit(r, ActionAuthChangePassword, "", targetUserID)
	w.WriteHeader(http.StatusNoContent)
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
