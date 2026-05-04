// Server-rendered admin portal handlers, mounted at /portal/*. Login flows
// (local password, OIDC SSO) issue a regular user session token via
// auth.IssueUserToken and store the raw token in an AES-256-GCM-sealed
// HttpOnly cookie. Request validation reuses auth.Validate so portal sessions
// share the sliding expiry, deactivation, and audit semantics of API tokens.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/auth"
	icrypto "github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// portalCookie is the encrypted bearer-token cookie. Contents are sealed with
// the master KEK (or an ephemeral 32-byte key in KMS-mode); decoding ↔
// re-validating against the tokens table is done on every request.
const portalCookie = "vault_portal"

// portalSSOCallback is the cli_callback sentinel passed to oidc.BeginAuth from
// the portal flow. The shared OIDC callback handler (handleOIDCCallback) sees
// this value and, instead of redirecting to a CLI loopback URL or returning
// JSON, sets the portal cookie and 302s to /portal.
const portalSSOCallback = "vault://portal"

// tokenNamePortal is the session label used for portal-issued user tokens.
const tokenNamePortal = "portal"

// minPortalPasswordLen is the floor enforced on local passwords created or
// changed through the portal.
const minPortalPasswordLen = 12

type portalCtxKey struct{}

type portalCtx struct {
	Token *model.Token
	User  *model.User
}

func portalFromCtx(r *http.Request) *portalCtx {
	p, _ := r.Context().Value(portalCtxKey{}).(*portalCtx)
	return p
}

// portalBase is embedded in every portal page data struct.
type portalBase struct {
	ActivePage string
	UserEmail  string
	IsAdmin    bool
	User       *model.User
}

func newPortalBase(pc *portalCtx, page string) portalBase {
	return portalBase{
		ActivePage: page,
		UserEmail:  pc.User.Email,
		IsAdmin:    pc.User.Role == model.UserRoleAdmin,
		User:       pc.User,
	}
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

func (s *Server) setPortalCookie(w http.ResponseWriter, rawToken string) error {
	enc, err := icrypto.SealBytes(s.cookieKey, []byte(rawToken))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     portalCookie,
		Value:    base64.RawURLEncoding.EncodeToString(enc),
		Path:     "/",
		MaxAge:   int(auth.DefaultSessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Server) readPortalCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(portalCookie)
	if err != nil {
		return "", err
	}
	enc, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", err
	}
	raw, err := icrypto.OpenBytes(s.cookieKey, enc)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func clearPortalCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: portalCookie, Value: "", Path: "/",
		MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// ── Middleware ────────────────────────────────────────────────────────────────

// portalAuth gates portal pages on a valid session cookie. On any failure the
// browser is redirected to /portal/login rather than receiving a 401, since the
// portal is human-facing.
func (s *Server) portalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := s.readPortalCookie(r)
		if err != nil || raw == "" {
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		tok, err := auth.Validate(r.Context(), s.store, raw)
		if errors.Is(err, store.ErrNotFound) {
			clearPortalCookie(w)
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		if err != nil {
			s.log.Error("portal auth", "err", err)
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		if tok.ExpiresAt != nil && time.Now().UTC().After(*tok.ExpiresAt) {
			clearPortalCookie(w)
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		if tok.UserID == nil {
			// Machine token slipped into a portal cookie; reject.
			clearPortalCookie(w)
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		// Slide session expiry on each request, mirroring s.auth.
		if tok.IsSession {
			newExpiry := time.Now().UTC().Add(auth.DefaultSessionTTL)
			if err := s.store.ExtendTokenExpiry(r.Context(), tok.TokenHash, newExpiry); err == nil {
				tok.ExpiresAt = &newExpiry
			}
		}
		user, err := s.store.GetUserByID(r.Context(), *tok.UserID)
		if err != nil {
			clearPortalCookie(w)
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		if !user.Active {
			clearPortalCookie(w)
			flashRedirect(w, r, "/portal/login", "error", "Account is deactivated.")
			return
		}
		ctx := context.WithValue(r.Context(), portalCtxKey{}, &portalCtx{Token: tok, User: user})
		// Also set the API tokenKey so downstream helpers (logAudit, etc.) work.
		ctx = context.WithValue(ctx, tokenKey, tok)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) portalAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.portalAuth(func(w http.ResponseWriter, r *http.Request) {
		pc := portalFromCtx(r)
		if pc.User.Role != model.UserRoleAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// ── Login / logout ────────────────────────────────────────────────────────────

func (s *Server) handlePortalLoginGET(w http.ResponseWriter, r *http.Request) {
	s.portalTmpl.render(w, "portal_login.html", struct {
		Error, Email  string
		OIDCEnabled   bool
		LocalDisabled bool
		AllowRegister bool
	}{
		Error:         r.URL.Query().Get("error"),
		OIDCEnabled:   s.oidc != nil,
		LocalDisabled: s.oidcEnforce,
		AllowRegister: s.allowReg,
	})
}

// ── Portal registration ───────────────────────────────────────────────────────
//
// Self-service signup, gated on api.Config.AllowRegistration (= VAULT_ALLOW_REGISTRATION).
// On success, issues a portal session cookie and redirects to /portal — same
// shape as the login flow. Mirrors the JSON /api/v1/auth/signup bootstrap rule:
// if no admin exists yet, the registrant becomes admin.

func (s *Server) handlePortalRegisterGET(w http.ResponseWriter, r *http.Request) {
	if !s.allowReg {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}
	s.portalTmpl.render(w, "portal_register.html", struct {
		Error, Email string
	}{})
}

func (s *Server) handlePortalRegisterPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allowReg {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}
	_ = r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	render := func(msg string) {
		s.portalTmpl.render(w, "portal_register.html", struct {
			Error, Email string
		}{Error: msg, Email: email})
	}

	if email == "" || password == "" {
		render("Email and password are required.")
		return
	}
	if password != confirm {
		render("Passwords do not match.")
		return
	}
	if !validatePortalPassword(password) {
		render("Password must be at least 12 characters.")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		s.log.Error("hash password", "err", err)
		render("Registration failed. Please try again.")
		return
	}

	// First user is admin; subsequent registrants are members.
	role := model.UserRoleMember
	hasAdmin, err := s.store.HasAdminUser(r.Context())
	if err != nil {
		s.log.Error("portal register has-admin", "err", err)
		render("Registration failed. Please try again.")
		return
	}
	if !hasAdmin {
		role = model.UserRoleAdmin
	}

	user, err := s.store.CreateUser(r.Context(), email, hash, role)
	if errors.Is(err, store.ErrConflict) {
		render("An account with that email already exists.")
		return
	}
	if err != nil {
		s.log.Error("portal register create user", "err", err)
		render("Registration failed. Please try again.")
		return
	}

	rawToken, tok, err := auth.IssueUserToken(r.Context(), s.store, user.ID, tokenNamePortal)
	if err != nil {
		s.log.Error("portal register issue token", "err", err)
		flashRedirect(w, r, "/portal/login", "error", "Registered. Please sign in.")
		return
	}
	if err := s.setPortalCookie(w, rawToken); err != nil {
		s.log.Error("portal register seal cookie", "err", err)
		flashRedirect(w, r, "/portal/login", "error", "Registered. Please sign in.")
		return
	}
	if err := s.logAudit(r, ActionAuthSignup, "", user.Email); err != nil {
		_ = s.store.DeleteToken(r.Context(), tok.ID, user.ID)
		clearPortalCookie(w)
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/portal", http.StatusFound)
}

func (s *Server) handlePortalLoginPOST(w http.ResponseWriter, r *http.Request) {
	if s.oidcEnforce {
		flashRedirect(w, r, "/portal/login", "error", "Local login is disabled.")
		return
	}
	_ = r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	user, ok, err := s.loginUser(r, email, password)
	if err != nil {
		flashRedirect(w, r, "/portal/login", "error", "Sign-in failed.")
		return
	}
	if !ok {
		flashRedirect(w, r, "/portal/login", "error", "Invalid email or password.")
		return
	}
	if !user.Active {
		flashRedirect(w, r, "/portal/login", "error", "Account is deactivated.")
		return
	}

	rawToken, tok, err := auth.IssueUserToken(r.Context(), s.store, user.ID, tokenNamePortal)
	if err != nil {
		s.log.Error("portal issue token", "err", err)
		flashRedirect(w, r, "/portal/login", "error", "Sign-in failed.")
		return
	}
	if err := s.setPortalCookie(w, rawToken); err != nil {
		s.log.Error("seal portal cookie", "err", err)
		flashRedirect(w, r, "/portal/login", "error", "Sign-in failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionAuthLogin, "", "", user.Email, portalMeta(nil)); err != nil {
		_ = s.store.DeleteToken(r.Context(), tok.ID, user.ID)
		clearPortalCookie(w)
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/portal", http.StatusFound)
}

// loginUser is the credential-checking core shared by handleLogin (JSON) and
// handlePortalLoginPOST (form). On bad credentials it audits a login-failed
// event and returns (nil, false, nil). On a store or audit failure it returns
// (nil, false, err) so the caller can fail closed.
func (s *Server) loginUser(r *http.Request, email, password string) (*model.User, bool, error) {
	user, err := s.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !auth.CheckPassword(user.PasswordHash, password)) {
		if auditErr := s.logAudit(r, ActionAuthLoginFailed, "", email); auditErr != nil {
			return nil, false, auditErr
		}
		return nil, false, nil
	}
	if err != nil {
		s.log.Error("login lookup", "err", err)
		return nil, false, err
	}
	return user, true, nil
}

func (s *Server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if pc != nil && pc.Token.UserID != nil {
		_ = s.store.DeleteToken(r.Context(), pc.Token.ID, *pc.Token.UserID)
		_ = s.logAuditEnv(r, ActionAuthLogout, "", "", pc.User.Email, `{"via":"portal"}`)
	}
	clearPortalCookie(w)
	http.Redirect(w, r, "/portal/login", http.StatusFound)
}

// ── OIDC portal flow ──────────────────────────────────────────────────────────

// handlePortalLoginOIDC kicks off the OIDC flow with a portal-mode sentinel
// that the shared callback (handleOIDCCallback) recognises.
func (s *Server) handlePortalLoginOIDC(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		flashRedirect(w, r, "/portal/login", "error", "SSO is not configured.")
		return
	}
	authURL, _, err := s.oidc.BeginAuth(portalSSOCallback)
	if err != nil {
		s.log.Error("portal oidc begin", "err", err)
		flashRedirect(w, r, "/portal/login", "error", "SSO failed.")
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// ── Self-service: home / account / tokens ─────────────────────────────────────

func (s *Server) handlePortalHome(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	s.portalTmpl.render(w, "portal_home.html", struct {
		portalBase
		OIDCLinked bool
	}{newPortalBase(pc, "home"), pc.User.OIDCSubject != nil})
}

func (s *Server) handlePortalAccount(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	s.portalTmpl.render(w, "portal_account.html", struct {
		portalBase
		Success, Error string
		OIDCOnly       bool
	}{
		portalBase: newPortalBase(pc, "account"),
		Success:    r.URL.Query().Get("success"),
		Error:      r.URL.Query().Get("error"),
		OIDCOnly:   pc.User.PasswordHash == "" && pc.User.OIDCSubject != nil,
	})
}

func (s *Server) handlePortalAccountPassword(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if pc.User.PasswordHash == "" {
		flashRedirect(w, r, "/portal/account", "error", "Account has no local password.")
		return
	}
	_ = r.ParseForm()
	current := r.FormValue("current_password")
	newPw := r.FormValue("new_password")
	if !auth.CheckPassword(pc.User.PasswordHash, current) {
		flashRedirect(w, r, "/portal/account", "error", "Current password is incorrect.")
		return
	}
	if !validatePortalPassword(newPw) {
		flashRedirect(w, r, "/portal/account", "error", "Password must be at least 12 characters.")
		return
	}
	hash, err := auth.HashPassword(newPw)
	if err != nil {
		s.log.Error("hash password", "err", err)
		flashRedirect(w, r, "/portal/account", "error", "Password update failed.")
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), pc.User.ID, hash); err != nil {
		s.log.Error("update password", "err", err)
		flashRedirect(w, r, "/portal/account", "error", "Password update failed.")
		return
	}
	if err := s.store.DeleteAllTokensForUser(r.Context(), pc.User.ID); err != nil {
		s.log.Error("revoke tokens after password change", "err", err)
	}
	if err := s.logAuditEnv(r, ActionAuthChangePassword, "", "", pc.User.Email, `{"via":"portal"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	clearPortalCookie(w)
	flashRedirect(w, r, "/portal/login", "error", "Password changed. Please sign in again.")
}

func (s *Server) handlePortalTokens(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	tokens, _ := s.store.ListTokens(r.Context(), pc.User.ID)
	s.portalTmpl.render(w, "portal_tokens.html", struct {
		portalBase
		Tokens                   []*model.Token
		Success, Error, NewToken string
	}{
		portalBase: newPortalBase(pc, "tokens"),
		Tokens:     tokens,
		Success:    r.URL.Query().Get("success"),
		Error:      r.URL.Query().Get("error"),
		NewToken:   r.URL.Query().Get("token"),
	})
}

func (s *Server) handlePortalTokenNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		flashRedirect(w, r, "/portal/tokens", "error", "Token label is required.")
		return
	}
	rawToken, _, err := auth.IssueUserToken(r.Context(), s.store, pc.User.ID, name)
	if err != nil {
		s.log.Error("issue portal token", "err", err)
		flashRedirect(w, r, "/portal/tokens", "error", "Token issue failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionTokenCreate, "", "", name, `{"via":"portal"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/tokens", "token", rawToken)
}

func (s *Server) handlePortalTokenDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id := r.PathValue("id")
	if err := s.store.DeleteToken(r.Context(), id, pc.User.ID); err != nil {
		flashRedirect(w, r, "/portal/tokens", "error", "Revoke failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionTokenDelete, "", "", id, `{"via":"portal"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/tokens", "success", "Token revoked.")
}

// ── helpers ───────────────────────────────────────────────────────────────────

// validatePortalPassword mirrors the basic minimum-length check from
// validatePassword; the latter writes its own HTTP error and isn't reusable
// from the redirect-flash flow.
func validatePortalPassword(pw string) bool {
	return len(pw) >= minPortalPasswordLen
}

// portalMeta returns a JSON metadata blob tagged with via=portal, merging in
// extra fields. Used as the metadata argument to logAuditEnv. Building the
// JSON via encoding/json (rather than string concat) keeps the field values
// safe even if a future caller passes user-supplied input.
func portalMeta(extra map[string]any) string {
	m := map[string]any{"via": "portal"}
	maps.Copy(m, extra)
	b, _ := json.Marshal(m)
	return string(b)
}

// flashRedirect issues a 302 to path with one query param attached. kind is
// "success" / "error" / "token"; msg is the unencoded value (url.Values.Encode
// handles escaping). Both must be non-empty for the param to be added.
func flashRedirect(w http.ResponseWriter, r *http.Request, path, kind, msg string) {
	if kind != "" && msg != "" {
		q := url.Values{}
		q.Set(kind, msg)
		path += "?" + q.Encode()
	}
	http.Redirect(w, r, path, http.StatusFound)
}
