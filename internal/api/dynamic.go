package api

import (
	"encoding/json"
	"net/http"

	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/dynamic"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// ── request / response types ──────────────────────────────────────────────────

type dynamicBackendRequest struct {
	Type       string         `json:"type"`
	Config     map[string]any `json:"config"`
	DefaultTTL int            `json:"default_ttl"`
	MaxTTL     int            `json:"max_ttl"`
}

type dynamicBackendResponse struct {
	Slug       string `json:"slug"`
	ProjectID  string `json:"project_id"`
	EnvID      string `json:"env_id"`
	Type       string `json:"type"`
	DefaultTTL int    `json:"default_ttl"`
	MaxTTL     int    `json:"max_ttl"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type dynamicRoleRequest struct {
	CreationTmpl   string `json:"creation_tmpl"`
	RevocationTmpl string `json:"revocation_tmpl"`
	TTL            *int   `json:"ttl,omitempty"`
}

type dynamicRoleResponse struct {
	Name           string `json:"name"`
	CreationTmpl   string `json:"creation_tmpl"`
	RevocationTmpl string `json:"revocation_tmpl"`
	TTL            *int   `json:"ttl,omitempty"`
	CreatedAt      string `json:"created_at"`
}

type issueCRedsRequest struct {
	TTL int `json:"ttl"` // 0 = use role/backend default
}

type issuedCredsResponse struct {
	LeaseID   string `json:"lease_id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ExpiresAt string `json:"expires_at"`
}

type leaseResponse struct {
	ID        string  `json:"id"`
	RoleName  string  `json:"role_name"`
	Username  string  `json:"username"`
	ExpiresAt string  `json:"expires_at"`
	RevokedAt *string `json:"revoked_at,omitempty"`
	CreatedBy *string `json:"created_by,omitempty"`
	CreatedAt string  `json:"created_at"`
}

// ── helpers ───────────────────────────────────────────────────────────────────

func fmtAPITime(t interface{ Format(string) string }) string {
	return t.Format("2006-01-02T15:04:05Z")
}

// ── handlers ──────────────────────────────────────────────────────────────────

func (s *Server) handleSetDynamicBackend(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	if !s.requireWrite(w, r, tokenFromCtx(r), project.ID) {
		return
	}

	backendSlug := r.PathValue("name")

	var req dynamicBackendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "type is required")
		return
	}
	if len(req.Config) == 0 {
		writeError(w, http.StatusBadRequest, "config is required")
		return
	}
	if _, err := dynamic.Get(req.Type); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DefaultTTL <= 0 {
		req.DefaultTTL = 3600
	}
	if req.MaxTTL <= 0 {
		req.MaxTTL = 86400
	}
	if req.DefaultTTL > req.MaxTTL {
		writeError(w, http.StatusBadRequest, "default_ttl must not exceed max_ttl")
		return
	}

	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid config")
		return
	}

	projectKP, err := s.projectKP.ForProject(r.Context(), project.ID, project.EncryptedPEK)
	if err != nil {
		s.log.Error("load project key", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	encConfig, encConfigDEK, err := crypto.EncryptSecret(r.Context(), projectKP, configJSON)
	if err != nil {
		s.log.Error("encrypt backend config", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	backend, err := s.store.SetDynamicBackend(r.Context(), project.ID, envID, backendSlug, req.Type, encConfig, encConfigDEK, req.DefaultTTL, req.MaxTTL)
	if err != nil {
		s.log.Error("set dynamic backend", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, dynamicBackendResponse{
		Slug:       backend.Slug,
		ProjectID:  backend.ProjectID,
		EnvID:      backend.EnvID,
		Type:       backend.Type,
		DefaultTTL: backend.DefaultTTL,
		MaxTTL:     backend.MaxTTL,
		CreatedAt:  fmtAPITime(backend.CreatedAt),
		UpdatedAt:  fmtAPITime(backend.UpdatedAt),
	})
}

func (s *Server) handleGetDynamicBackend(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}

	backendSlug := r.PathValue("name")

	backend, err := s.store.GetDynamicBackend(r.Context(), project.ID, envID, backendSlug)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "no backend configured with slug "+backendSlug)
		return
	}
	if err != nil {
		s.log.Error("get dynamic backend", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, dynamicBackendResponse{
		Slug:       backend.Slug,
		ProjectID:  backend.ProjectID,
		EnvID:      backend.EnvID,
		Type:       backend.Type,
		DefaultTTL: backend.DefaultTTL,
		MaxTTL:     backend.MaxTTL,
		CreatedAt:  fmtAPITime(backend.CreatedAt),
		UpdatedAt:  fmtAPITime(backend.UpdatedAt),
	})
}

func (s *Server) handleDeleteDynamicBackend(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	if !s.requireWrite(w, r, tokenFromCtx(r), project.ID) {
		return
	}

	backendSlug := r.PathValue("name")

	if err := s.store.DeleteDynamicBackend(r.Context(), project.ID, envID, backendSlug); err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "no backend configured with slug "+backendSlug)
		return
	} else if err != nil {
		s.log.Error("delete dynamic backend", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetDynamicRole(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	if !s.requireWrite(w, r, tokenFromCtx(r), project.ID) {
		return
	}

	backendSlug := r.PathValue("name")
	roleName := r.PathValue("role")

	backend, err := s.store.GetDynamicBackend(r.Context(), project.ID, envID, backendSlug)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "no backend configured with slug "+backendSlug)
		return
	}
	if err != nil {
		s.log.Error("get dynamic backend", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var req dynamicRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.CreationTmpl == "" || req.RevocationTmpl == "" {
		writeError(w, http.StatusBadRequest, "creation_tmpl and revocation_tmpl are required")
		return
	}

	role, err := s.store.SetDynamicRole(r.Context(), backend.ID, roleName, req.CreationTmpl, req.RevocationTmpl, req.TTL)
	if err != nil {
		s.log.Error("set dynamic role", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, dynamicRoleResponse{
		Name:           role.Name,
		CreationTmpl:   role.CreationTmpl,
		RevocationTmpl: role.RevocationTmpl,
		TTL:            role.TTL,
		CreatedAt:      fmtAPITime(role.CreatedAt),
	})
}

func (s *Server) handleListDynamicRoles(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}

	backendSlug := r.PathValue("name")

	backend, err := s.store.GetDynamicBackend(r.Context(), project.ID, envID, backendSlug)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "no backend configured with slug "+backendSlug)
		return
	}
	if err != nil {
		s.log.Error("get dynamic backend", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	roles, err := s.store.ListDynamicRoles(r.Context(), backend.ID)
	if err != nil {
		s.log.Error("list dynamic roles", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]dynamicRoleResponse, 0, len(roles))
	for _, role := range roles {
		resp = append(resp, dynamicRoleResponse{
			Name:           role.Name,
			CreationTmpl:   role.CreationTmpl,
			RevocationTmpl: role.RevocationTmpl,
			TTL:            role.TTL,
			CreatedAt:      fmtAPITime(role.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteDynamicRole(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	if !s.requireWrite(w, r, tokenFromCtx(r), project.ID) {
		return
	}

	backendSlug := r.PathValue("name")
	roleName := r.PathValue("role")

	backend, err := s.store.GetDynamicBackend(r.Context(), project.ID, envID, backendSlug)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "no backend configured with slug "+backendSlug)
		return
	}
	if err != nil {
		s.log.Error("get dynamic backend", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := s.store.DeleteDynamicRole(r.Context(), backend.ID, roleName); err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "role not found")
		return
	} else if err != nil {
		s.log.Error("delete dynamic role", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleIssueCreds(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}

	tok := tokenFromCtx(r)
	backendSlug := r.PathValue("name")
	roleName := r.PathValue("role")

	backend, err := s.store.GetDynamicBackend(r.Context(), project.ID, envID, backendSlug)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "no backend configured with slug "+backendSlug)
		return
	}
	if err != nil {
		s.log.Error("get dynamic backend", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	role, err := s.store.GetDynamicRole(r.Context(), backend.ID, roleName)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "role not found")
		return
	}
	if err != nil {
		s.log.Error("get dynamic role", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var req issueCRedsRequest
	// Ignore decode errors — body is optional.
	_ = json.NewDecoder(r.Body).Decode(&req)

	issuer, err := dynamic.Get(backend.Type)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	projectKP, err := s.projectKP.ForProject(r.Context(), project.ID, project.EncryptedPEK)
	if err != nil {
		s.log.Error("load project key", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	ttl := dynamic.EffectiveTTL(backend, role, req.TTL)
	username, password, expiresAt, err := issuer.Issue(r.Context(), projectKP, backend, role, ttl)
	if err != nil {
		s.log.Error("issue dynamic creds", "backend", backendSlug, "role", roleName, "err", err)
		writeError(w, http.StatusInternalServerError, "failed to issue credentials: "+err.Error())
		return
	}

	var createdBy *string
	if tok != nil {
		createdBy = &tok.ID
	}
	lease, err := s.store.CreateDynamicLease(r.Context(),
		project.ID, envID, backend.ID, role.ID, role.Name,
		username, role.RevocationTmpl, expiresAt, createdBy)
	if err != nil {
		s.log.Error("create dynamic lease", "err", err)
		// Creds were already created — best effort revoke.
		_ = issuer.Revoke(r.Context(), projectKP, backend, role.RevocationTmpl, username)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, issuedCredsResponse{
		LeaseID:   lease.ID,
		Username:  username,
		Password:  password,
		ExpiresAt: fmtAPITime(expiresAt),
	})
}

func (s *Server) handleListDynamicLeases(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}

	leases, err := s.store.ListDynamicLeases(r.Context(), project.ID, envID)
	if err != nil {
		s.log.Error("list dynamic leases", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]leaseResponse, 0, len(leases))
	for _, l := range leases {
		item := leaseResponse{
			ID:        l.ID,
			RoleName:  l.RoleName,
			Username:  l.Username,
			ExpiresAt: fmtAPITime(l.ExpiresAt),
			CreatedBy: l.CreatedBy,
			CreatedAt: fmtAPITime(l.CreatedAt),
		}
		if l.RevokedAt != nil {
			s := fmtAPITime(*l.RevokedAt)
			item.RevokedAt = &s
		}
		resp = append(resp, item)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRevokeDynamicLease(w http.ResponseWriter, r *http.Request) {
	project, _, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	if !s.requireWrite(w, r, tokenFromCtx(r), project.ID) {
		return
	}

	leaseID := r.PathValue("lease_id")
	lease, err := s.store.GetDynamicLease(r.Context(), leaseID)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "lease not found")
		return
	}
	if err != nil {
		s.log.Error("get dynamic lease", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if lease.RevokedAt != nil {
		writeError(w, http.StatusConflict, "lease already revoked")
		return
	}

	backend, err := s.store.GetDynamicBackendByID(r.Context(), lease.BackendID)
	if err != nil && err != store.ErrNotFound {
		s.log.Error("get dynamic backend by id", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if backend != nil {
		issuer, err := dynamic.Get(backend.Type)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		projectKP, err := s.projectKP.ForProject(r.Context(), project.ID, project.EncryptedPEK)
		if err != nil {
			s.log.Error("load project key", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if err := issuer.Revoke(r.Context(), projectKP, backend, lease.RevocationTmpl, lease.Username); err != nil {
			s.log.Error("revoke dynamic creds", "lease_id", leaseID, "err", err)
			writeError(w, http.StatusInternalServerError, "failed to revoke credentials: "+err.Error())
			return
		}
	}

	if err := s.store.RevokeDynamicLease(r.Context(), leaseID); err != nil {
		s.log.Error("mark lease revoked", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
