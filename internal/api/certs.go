package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// ── request / response types ──────────────────────────────────────────────────

type registerPrincipalRequest struct {
	Description string `json:"description"` // required
	SPIFFEID    string `json:"spiffe_id"`   // required URI, e.g. spiffe://cluster/ns/app/sa/svc
	Project     string `json:"project"`     // slug, optional
	Env         string `json:"env"`         // slug, optional
	ReadOnly    bool   `json:"read_only"`
	ExpiresIn   string `json:"expires_in"` // Go duration, optional
}

type certPrincipalResponse struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	SPIFFEID    string  `json:"spiffe_id"`
	ProjectID   *string `json:"project_id,omitempty"`
	EnvID       *string `json:"env_id,omitempty"`
	ReadOnly    bool    `json:"read_only"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// ── SPIFFE auth helper (used by middleware) ───────────────────────────────────

var errSPIFFEUnregistered = errors.New("SPIFFE ID not registered")

// authFromSPIFFECert extracts the SPIFFE URI SAN from the TLS peer certificate,
// looks it up in the store, and constructs an ephemeral *model.Token.
// Returns errSPIFFEUnregistered if the cert has no SPIFFE ID or the ID is unknown,
// so the caller can fall through to bearer token auth.
func (s *Server) authFromSPIFFECert(r *http.Request) (*model.Token, error) {
	leaf := r.TLS.PeerCertificates[0]

	var spiffeID string
	for _, u := range leaf.URIs {
		if u.Scheme == "spiffe" {
			spiffeID = u.String()
			break
		}
	}
	if spiffeID == "" {
		return nil, errSPIFFEUnregistered
	}

	p, err := s.store.GetCertPrincipalBySPIFFEID(r.Context(), spiffeID)
	if err == store.ErrNotFound {
		return nil, errSPIFFEUnregistered
	}
	if err != nil {
		return nil, fmt.Errorf("cert principal lookup: %w", err)
	}
	if p.ExpiresAt != nil && time.Now().UTC().After(*p.ExpiresAt) {
		return nil, fmt.Errorf("cert principal expired")
	}

	// Construct a virtual *model.Token so all existing authorization helpers work
	// unchanged. TokenHash is intentionally empty — this token is never stored.
	return &model.Token{
		ID:        p.ID,
		UserID:    p.UserID,
		Name:      p.Description,
		ProjectID: p.ProjectID,
		EnvID:     p.EnvID,
		ReadOnly:  p.ReadOnly,
		ExpiresAt: p.ExpiresAt,
		CreatedAt: p.CreatedAt,
	}, nil
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
	if req.SPIFFEID == "" {
		writeError(w, http.StatusBadRequest, "spiffe_id is required")
		return
	}
	u, err := url.Parse(req.SPIFFEID)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" {
		writeError(w, http.StatusBadRequest, "spiffe_id must be a valid URI with spiffe:// scheme")
		return
	}

	projectID, envID, httpErr := s.resolveTokenScope(w, r, req.Project, req.Env)
	if httpErr {
		return
	}

	p := &model.CertPrincipal{
		UserID:      tok.UserID,
		Description: req.Description,
		SPIFFEID:    req.SPIFFEID,
		ReadOnly:    req.ReadOnly,
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

	if err := s.store.CreateCertPrincipal(r.Context(), p); err == store.ErrConflict {
		writeError(w, http.StatusConflict, "SPIFFE ID already registered")
		return
	} else if err != nil {
		s.log.Error("create cert principal", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
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
	if err := s.store.DeleteCertPrincipal(r.Context(), id, *tok.UserID); err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "cert principal not found")
		return
	} else if err != nil {
		s.log.Error("delete cert principal", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func principalToResp(p *model.CertPrincipal) certPrincipalResponse {
	r := certPrincipalResponse{
		ID:          p.ID,
		Description: p.Description,
		SPIFFEID:    p.SPIFFEID,
		ProjectID:   p.ProjectID,
		EnvID:       p.EnvID,
		ReadOnly:    p.ReadOnly,
		CreatedAt:   p.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if p.ExpiresAt != nil {
		s := p.ExpiresAt.Format("2006-01-02T15:04:05Z")
		r.ExpiresAt = &s
	}
	return r
}
