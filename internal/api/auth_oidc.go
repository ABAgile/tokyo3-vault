package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// handleOIDCConfig returns OIDC discovery info for clients.
// GET /api/v1/auth/oidc/config
func (s *Server) handleOIDCConfig(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"enforce": s.oidcEnforce,
	})
}

// handleOIDCLogin starts the Authorization Code + PKCE flow.
// GET /api/v1/auth/oidc/login?cli_callback=<url>
//
// cli_callback is the localhost URL the CLI's local HTTP server is listening on.
// If provided, the callback handler will redirect the browser there with the
// session token after a successful login.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "OIDC is not configured")
		return
	}
	cliCallback := r.URL.Query().Get("cli_callback")
	authURL, _, err := s.oidc.BeginAuth(cliCallback)
	if err != nil {
		s.log.Error("oidc begin auth", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"authorization_url": authURL})
}

// handleOIDCCallback handles the redirect from the IdP.
// GET /api/v1/auth/oidc/callback?code=...&state=...
//
// Flow:
//  1. Verify state (HMAC + expiry), extract code_verifier + cli_callback.
//  2. Exchange code for tokens (PKCE).
//  3. Verify ID token.
//  4. JIT-provision or look up the vault user.
//  5. Issue a session token and return it (JSON for web, redirect for CLI).
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "OIDC is not configured")
		return
	}

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		s.log.Warn("oidc callback error from IdP", "error", errParam, "description", desc)
		writeError(w, http.StatusBadRequest, "IdP returned error: "+errParam)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		writeError(w, http.StatusBadRequest, "code and state are required")
		return
	}

	claims, cliCallback, err := s.oidc.CompleteAuth(r.Context(), code, state)
	if err != nil {
		s.log.Warn("oidc complete auth", "err", err)
		writeError(w, http.StatusBadRequest, "OIDC authentication failed")
		return
	}

	user, err := s.jitProvision(r, claims.Issuer, claims.Subject, claims.Email)
	if err != nil {
		s.log.Error("oidc jit provision", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if !user.Active {
		writeError(w, http.StatusForbidden, "account is deprovisioned")
		return
	}

	rawToken, _, err := auth.IssueUserToken(r.Context(), s.store, user.ID, "session")
	if err != nil {
		s.log.Error("issue oidc token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := s.logAudit(r, ActionAuthOIDCLogin, "", user.Email); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}

	if cliCallback != "" {
		http.Redirect(w, r, cliCallback+"?token="+rawToken, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{Token: rawToken, Name: "session"})
}

// jitProvision looks up or creates a vault user from OIDC identity claims.
//
// Lookup order:
//  1. Match on oidc_issuer + oidc_subject → existing OIDC user.
//  2. Match on email → local user; link OIDC identity.
//  3. Neither → create new OIDC user (JIT provisioning).
func (s *Server) jitProvision(r *http.Request, issuer, subject, email string) (*model.User, error) {
	ctx := r.Context()
	email = strings.ToLower(strings.TrimSpace(email))

	// 1. Existing OIDC user — fast path.
	user, err := s.store.GetUserByOIDCSubject(ctx, issuer, subject)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// 2. Local user with matching email — link OIDC identity.
	user, err = s.store.GetUserByEmail(ctx, email)
	if err == nil {
		if linkErr := s.store.SetUserOIDCIdentity(ctx, user.ID, issuer, subject); linkErr != nil && !errors.Is(linkErr, store.ErrConflict) {
			return nil, linkErr
		}
		if err := s.logAudit(r, ActionAuthOIDCIdentityLinked, "", email); err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		return user, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// 3. New user — JIT provision with member role.
	user, err = s.store.CreateOIDCUser(ctx, email, issuer, subject, model.UserRoleMember)
	if err != nil {
		return nil, err
	}
	if err := s.logAudit(r, ActionAuthOIDCJITProvision, "", email); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return user, nil
}
