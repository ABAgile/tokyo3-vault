package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// ── request / response types ──────────────────────────────────────────────────

type registerPrincipalRequest struct {
	Description string `json:"description"` // required
	SPIFFEID    string `json:"spiffe_id"`   // URI SAN — required unless email_san is set
	EmailSAN    string `json:"email_san"`   // rfc822Name SAN — required unless spiffe_id is set
	Project     string `json:"project"`     // slug, optional
	Env         string `json:"env"`         // slug, optional
	ReadOnly    bool   `json:"read_only"`
	ExpiresIn   string `json:"expires_in"` // Go duration, optional
}

type certPrincipalResponse struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	SPIFFEID    *string `json:"spiffe_id,omitempty"`
	EmailSAN    *string `json:"email_san,omitempty"`
	ProjectID   *string `json:"project_id,omitempty"`
	EnvID       *string `json:"env_id,omitempty"`
	ReadOnly    bool    `json:"read_only"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// ── cert auth helper (used by middleware) ─────────────────────────────────────

var errCertUnregistered = errors.New("certificate not registered as a principal")

// authFromClientCert authenticates an mTLS client certificate against registered
// cert_principals. SPIFFE URI SANs are checked first; email SANs are the fallback.
// Returns errCertUnregistered when no SAN on the cert matches any principal, so the
// caller can fall through to bearer token auth.
func (s *Server) authFromClientCert(r *http.Request) (*model.Token, error) {
	leaf := r.TLS.PeerCertificates[0]

	// Try SPIFFE URI SAN first.
	for _, u := range leaf.URIs {
		if u.Scheme != "spiffe" {
			continue
		}
		p, err := s.store.GetCertPrincipalBySPIFFEID(r.Context(), u.String())
		if errors.Is(err, store.ErrNotFound) {
			break // SPIFFE ID present but not registered; fall through to email SAN
		}
		if err != nil {
			return nil, fmt.Errorf("cert principal lookup: %w", err)
		}
		if p.ExpiresAt != nil && time.Now().UTC().After(*p.ExpiresAt) {
			return nil, fmt.Errorf("cert principal expired")
		}
		if err := s.checkPrincipalUserActive(r, p); err != nil {
			return nil, err
		}
		return certPrincipalToToken(p), nil
	}

	// Try email SANs.
	for _, email := range leaf.EmailAddresses {
		p, err := s.store.GetCertPrincipalByEmailSAN(r.Context(), email)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cert principal lookup: %w", err)
		}
		if p.ExpiresAt != nil && time.Now().UTC().After(*p.ExpiresAt) {
			return nil, fmt.Errorf("cert principal expired")
		}
		if err := s.checkPrincipalUserActive(r, p); err != nil {
			return nil, err
		}
		return certPrincipalToToken(p), nil
	}

	return nil, errCertUnregistered
}

// checkPrincipalUserActive returns an error if the principal's owning user is deprovisioned.
func (s *Server) checkPrincipalUserActive(r *http.Request, p *model.CertPrincipal) error {
	if p.UserID == nil {
		return nil
	}
	user, err := s.store.GetUserByID(r.Context(), *p.UserID)
	if err != nil {
		return fmt.Errorf("user lookup: %w", err)
	}
	if !user.Active {
		return fmt.Errorf("user account is deprovisioned")
	}
	return nil
}

// certPrincipalToToken constructs an ephemeral *model.Token from a cert principal
// so all existing authorization helpers work unchanged. TokenHash is empty —
// this token is never stored.
func certPrincipalToToken(p *model.CertPrincipal) *model.Token {
	return &model.Token{
		ID:        p.ID,
		UserID:    p.UserID,
		Name:      p.Description,
		ProjectID: p.ProjectID,
		EnvID:     p.EnvID,
		ReadOnly:  p.ReadOnly,
		ExpiresAt: p.ExpiresAt,
		CreatedAt: p.CreatedAt,
	}
}

// ── handlers ──────────────────────────────────────────────────────────────────

func (s *Server) handleRegisterCertPrincipal(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if !s.requireUnscoped(w, tok) {
		return
	}
	if tok.UserID == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req registerPrincipalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Description == "" {
		writeError(w, http.StatusBadRequest, "description is required")
		return
	}

	// Exactly one identifier must be supplied.
	hasSpiffe := req.SPIFFEID != ""
	hasEmail := req.EmailSAN != ""
	if !hasSpiffe && !hasEmail {
		writeError(w, http.StatusBadRequest, "one of spiffe_id or email_san is required")
		return
	}
	if hasSpiffe && hasEmail {
		writeError(w, http.StatusBadRequest, "only one of spiffe_id or email_san may be set")
		return
	}

	p := &model.CertPrincipal{
		UserID:      tok.UserID,
		Description: req.Description,
		ReadOnly:    req.ReadOnly,
	}

	if hasSpiffe {
		u, err := url.Parse(req.SPIFFEID)
		if err != nil || u.Scheme != "spiffe" || u.Host == "" {
			writeError(w, http.StatusBadRequest, "spiffe_id must be a valid URI with spiffe:// scheme")
			return
		}
		p.SPIFFEID = &req.SPIFFEID
	} else {
		if _, err := mail.ParseAddress(req.EmailSAN); err != nil {
			writeError(w, http.StatusBadRequest, "email_san must be a valid email address")
			return
		}
		p.EmailSAN = &req.EmailSAN
	}

	projectID, envID, httpErr := s.resolveTokenScope(w, r, req.Project, req.Env)
	if httpErr {
		return
	}
	if projectID != "" {
		p.ProjectID = &projectID
	}
	if envID != "" {
		p.EnvID = &envID
	}
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_in: use Go duration syntax e.g. 24h, 168h")
			return
		}
		t := time.Now().UTC().Add(d)
		p.ExpiresAt = &t
	}

	err := s.store.CreateCertPrincipal(r.Context(), p)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "identifier already registered")
		return
	}
	if err != nil {
		s.log.Error("create cert principal", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	identifier := req.SPIFFEID
	if identifier == "" {
		identifier = req.EmailSAN
	}
	if err := s.logAudit(r, ActionCertPrincipalRegister, "", identifier); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, principalToResp(p))
}

func (s *Server) handleListCertPrincipals(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if tok.UserID == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	principals, err := s.store.ListCertPrincipals(r.Context(), *tok.UserID)
	if err != nil {
		s.log.Error("list cert principals", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]certPrincipalResponse, 0, len(principals))
	for _, p := range principals {
		resp = append(resp, principalToResp(p))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteCertPrincipal(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if tok.UserID == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	id := r.PathValue("id")
	err := s.store.DeleteCertPrincipal(r.Context(), id, *tok.UserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "cert principal not found")
		return
	}
	if err != nil {
		s.log.Error("delete cert principal", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionCertPrincipalDelete, "", id); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func principalToResp(p *model.CertPrincipal) certPrincipalResponse {
	r := certPrincipalResponse{
		ID:          p.ID,
		Description: p.Description,
		SPIFFEID:    p.SPIFFEID,
		EmailSAN:    p.EmailSAN,
		ProjectID:   p.ProjectID,
		EnvID:       p.EnvID,
		ReadOnly:    p.ReadOnly,
		CreatedAt:   fmtAPITime(p.CreatedAt),
	}
	r.ExpiresAt = fmtOptionalTime(p.ExpiresAt)
	return r
}
