package api

import (
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// portalPrincipalRow is the table row for an existing cert principal,
// flattening the SPIFFEID/EmailSAN choice into a single Identifier column
// and resolving the project/env IDs back to slugs for display.
type portalPrincipalRow struct {
	*model.CertPrincipal
	Identifier string
	Scope      string
}

// handlePortalPrincipals renders the cert-principals page: list of principals
// the current user has registered + a "Register principal" form. Per-user
// scope by design (matches the JSON `/api/v1/cert-principals` semantics);
// users see and manage only the principals they registered.
func (s *Server) handlePortalPrincipals(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	principals, _ := s.store.ListCertPrincipals(r.Context(), pc.User.ID)
	// Reuse the same scope picker the machine-tokens page builds — the
	// project + env list is filtered by the user's memberships there.
	// Principals always require a project (no Unscoped option), so we
	// drop CanIssueUnscoped — the template doesn't render it anyway.
	scopeProjects, projectByID, envSlugByID := s.loadPortalTokenScopes(r)
	rows := make([]portalPrincipalRow, 0, len(principals))
	for _, p := range principals {
		row := portalPrincipalRow{
			CertPrincipal: p,
			Identifier:    formatPrincipalIdentifier(p),
			Scope:         formatPrincipalScope(p, projectByID, envSlugByID),
		}
		rows = append(rows, row)
	}
	s.portalTmpl.render(w, "portal_principals.html", struct {
		portalBase
		Principals     []portalPrincipalRow
		ScopeProjects  []portalTokenScopeProject
		Success, Error string
	}{
		portalBase:    newPortalBase(pc, "principals"),
		Principals:    rows,
		ScopeProjects: scopeProjects,
		Success:       r.URL.Query().Get("success"),
		Error:         r.URL.Query().Get("error"),
	})
}

// formatPrincipalIdentifier returns the SPIFFE ID or email SAN string for
// display — exactly one of the two columns is non-nil by validation.
func formatPrincipalIdentifier(p *model.CertPrincipal) string {
	if p.SPIFFEID != nil {
		return *p.SPIFFEID
	}
	if p.EmailSAN != nil {
		return *p.EmailSAN
	}
	return ""
}

// formatPrincipalScope renders the principal's scope as "<project>" or
// "<project> / <env>". Always non-empty for valid principals.
func formatPrincipalScope(p *model.CertPrincipal, projectByID map[string]*model.Project, envSlugByID map[string]string) string {
	if p.ProjectID == nil {
		return "—"
	}
	projectLabel := *p.ProjectID
	if proj := projectByID[*p.ProjectID]; proj != nil {
		projectLabel = proj.Slug
	}
	if p.EnvID == nil {
		return projectLabel
	}
	envLabel := *p.EnvID
	if slug, ok := envSlugByID[*p.EnvID]; ok {
		envLabel = slug
	}
	return projectLabel + " / " + envLabel
}

// handlePortalPrincipalNew accepts the registration form. Validates exactly
// one of spiffe_id / email_san, resolves the scope picker value to project
// + env IDs (verifying the user has access — same envFirst path the
// machine-tokens form uses), and writes the principal row.
func (s *Server) handlePortalPrincipalNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	desc := strings.TrimSpace(r.FormValue("description"))
	if desc == "" {
		flashRedirect(w, r, "/portal/principals", "error", "Description is required.")
		return
	}

	// Single identifier input: auto-detect SPIFFE URI vs email. Anything
	// starting with the spiffe:// scheme is parsed as a URI; everything
	// else is parsed as an email address. Either-or validates exclusively
	// to one column on the row, matching the JSON API's "exactly one of
	// SPIFFEID / EmailSAN must be non-nil" invariant.
	identifier := strings.TrimSpace(r.FormValue("identifier"))
	if identifier == "" {
		flashRedirect(w, r, "/portal/principals", "error", "Identifier is required.")
		return
	}
	var spiffeID, emailSAN string
	if strings.HasPrefix(strings.ToLower(identifier), "spiffe://") {
		u, err := url.Parse(identifier)
		if err != nil || u.Scheme != "spiffe" || u.Host == "" {
			flashRedirect(w, r, "/portal/principals", "error", "SPIFFE identifier must be a valid URI like spiffe://trust-domain/workload/path.")
			return
		}
		spiffeID = identifier
	} else {
		if _, err := mail.ParseAddress(identifier); err != nil {
			flashRedirect(w, r, "/portal/principals", "error", "Identifier must be a SPIFFE URI (spiffe://…) or a valid email address.")
			return
		}
		emailSAN = identifier
	}

	scope := strings.TrimSpace(r.FormValue("scope"))
	if scope == "" {
		flashRedirect(w, r, "/portal/principals", "error", "Scope is required — principals must be tied to a project.")
		return
	}
	projectSlug, envSlug, _ := strings.Cut(scope, "/")

	p, err := s.store.GetProject(r.Context(), projectSlug)
	if errors.Is(err, store.ErrNotFound) {
		flashRedirect(w, r, "/portal/principals", "error", "Project not found: "+projectSlug)
		return
	}
	if err != nil {
		s.log.Error("portal principals: get project", "err", err)
		flashRedirect(w, r, "/portal/principals", "error", "Register failed.")
		return
	}
	var envID string
	if envSlug != "" {
		env, err := s.store.GetEnvironment(r.Context(), p.ID, envSlug)
		if errors.Is(err, store.ErrNotFound) {
			flashRedirect(w, r, "/portal/principals", "error", "Environment not found: "+envSlug)
			return
		}
		if err != nil {
			s.log.Error("portal principals: get env", "err", err)
			flashRedirect(w, r, "/portal/principals", "error", "Register failed.")
			return
		}
		envID = env.ID
	}
	// Non-admins can only register principals against scopes they have access
	// to. Server admins skip the check (implicit access to every project).
	if pc.User.Role != model.UserRoleAdmin && !s.userCanAccessScope(r, p.ID, envID, pc.User.ID) {
		flashRedirect(w, r, "/portal/principals", "error", "You do not have access to this project or environment.")
		return
	}

	ttl := auth.DefaultCertPrincipalTTL
	if exp := strings.TrimSpace(r.FormValue("expires_in")); exp != "" {
		d, err := time.ParseDuration(exp)
		if err != nil {
			flashRedirect(w, r, "/portal/principals", "error", "Invalid expires_in — use Go duration syntax (24h, 168h, 8760h).")
			return
		}
		ttl = d
	}
	exp := time.Now().UTC().Add(ttl)

	principal := &model.CertPrincipal{
		UserID:      &pc.User.ID,
		Description: desc,
		ProjectID:   &p.ID,
		ReadOnly:    r.FormValue("read_only") == "1",
		ExpiresAt:   &exp,
	}
	if spiffeID != "" {
		principal.SPIFFEID = &spiffeID
	}
	if emailSAN != "" {
		principal.EmailSAN = &emailSAN
	}
	if envID != "" {
		principal.EnvID = &envID
	}

	err = s.store.CreateCertPrincipal(r.Context(), principal)
	if errors.Is(err, store.ErrConflict) {
		flashRedirect(w, r, "/portal/principals", "error", "Identifier already registered.")
		return
	}
	if err != nil {
		s.log.Error("portal principals: create", "err", err)
		flashRedirect(w, r, "/portal/principals", "error", "Register failed.")
		return
	}
	if err := s.logAudit(r, ActionCertPrincipalRegister, p.ID, identifier); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/principals", "success", "Principal registered.")
}

// handlePortalPrincipalDelete revokes one principal. Same per-user scope as
// the JSON DELETE — the store call rejects when the principal's UserID
// doesn't match.
func (s *Server) handlePortalPrincipalDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id := r.PathValue("id")
	err := s.store.DeleteCertPrincipal(r.Context(), id, pc.User.ID)
	if errors.Is(err, store.ErrNotFound) {
		flashRedirect(w, r, "/portal/principals", "error", "Principal not found.")
		return
	}
	if err != nil {
		s.log.Error("portal principals: delete", "err", err)
		flashRedirect(w, r, "/portal/principals", "error", "Revoke failed.")
		return
	}
	if err := s.logAudit(r, ActionCertPrincipalDelete, "", id); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/principals", "success", "Principal revoked.")
}
