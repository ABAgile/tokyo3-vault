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

type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}

// handleSignup is the public registration endpoint.
// It is only open when no admin user exists yet (first-run bootstrap).
// The first user created this way is always assigned the admin role.
// After that, new users must be created by an existing admin via POST /api/v1/users.
func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if s.oidcEnforce {
		writeError(w, http.StatusForbidden, "local account creation is disabled — accounts are managed through the IdP")
		return
	}
	hasAdmin, err := s.store.HasAdminUser(r.Context())
	if err != nil {
		s.log.Error("check admin", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if hasAdmin {
		writeError(w, http.StatusForbidden, "registration is closed; ask your administrator to create an account for you")
		return
	}

	var req signupRequest
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
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.log.Error("hash password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// First user is always admin.
	user, err := s.store.CreateUser(r.Context(), req.Email, hash, model.UserRoleAdmin)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}
	if err != nil {
		s.log.Error("create user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	rawToken, _, err := auth.IssueUserToken(r.Context(), s.store, user.ID, "session")
	if err != nil {
		s.log.Error("issue token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionAuthSignup, "", user.Email); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, tokenResponse{Token: rawToken, Name: "session"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidcEnforce {
		writeError(w, http.StatusForbidden, "local authentication is disabled — use SSO")
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	user, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !auth.CheckPassword(user.PasswordHash, req.Password)) {
		if auditErr := s.logAudit(r, ActionAuthLoginFailed, "", req.Email); auditErr != nil {
			writeError(w, http.StatusInternalServerError, "audit unavailable")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		s.log.Error("get user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !user.Active {
		writeError(w, http.StatusForbidden, "account is deprovisioned")
		return
	}

	rawToken, _, err := auth.IssueUserToken(r.Context(), s.store, user.ID, "session")
	if err != nil {
		s.log.Error("issue token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionAuthLogin, "", user.Email); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{Token: rawToken, Name: "session"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if tok.UserID == nil {
		writeError(w, http.StatusForbidden, "machine tokens cannot self-delete via logout")
		return
	}
	if err := s.store.DeleteToken(r.Context(), tok.ID, *tok.UserID); err != nil {
		s.log.Error("delete token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionAuthLogout, "", ""); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleChangePassword lets a user change their own password.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if tok.UserID == nil {
		writeError(w, http.StatusForbidden, "machine tokens cannot change passwords")
		return
	}
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Current == "" || req.New == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}
	if !validatePassword(w, req.New) {
		return
	}
	user, err := s.store.GetUserByID(r.Context(), *tok.UserID)
	if err != nil {
		s.log.Error("get user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !auth.CheckPassword(user.PasswordHash, req.Current) {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	newHash, err := auth.HashPassword(req.New)
	if err != nil {
		s.log.Error("hash password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), *tok.UserID, newHash); err != nil {
		s.log.Error("update password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionAuthChangePassword, "", user.Email); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
