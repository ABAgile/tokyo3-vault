package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/abagile/tokyo3-vault/internal/store"
)

type envResponse struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"created_at"`
}

type createEnvRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (s *Server) handleListEnvs(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetProject(r.Context(), r.PathValue("project"))
	if errors.Is(err, store.ErrNotFound) {
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
	envs, err := s.store.ListEnvironments(r.Context(), p.ID)
	if err != nil {
		s.log.Error("list envs", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]envResponse, 0, len(envs))
	for _, e := range envs {
		resp = append(resp, envResponse{
			ID: e.ID, ProjectID: e.ProjectID, Name: e.Name, Slug: e.Slug,
			CreatedAt: fmtAPITime(e.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateEnv(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if !s.requireUnscoped(w, tok) {
		return
	}
	p, err := s.store.GetProject(r.Context(), r.PathValue("project"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !s.requireWrite(w, r, tok, p.ID) {
		return
	}

	var req createEnvRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Slug == "" {
		req.Slug = toSlug(req.Name)
	}
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !slugRe.MatchString(req.Slug) {
		writeError(w, http.StatusBadRequest, "slug must be lowercase alphanumeric with hyphens (2–63 chars)")
		return
	}

	e, err := s.store.CreateEnvironment(r.Context(), p.ID, req.Name, req.Slug)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "environment already exists")
		return
	}
	if err != nil {
		s.log.Error("create env", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionEnvCreate, p.ID, e.Slug); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, envResponse{
		ID: e.ID, ProjectID: e.ProjectID, Name: e.Name, Slug: e.Slug,
		CreatedAt: fmtAPITime(e.CreatedAt),
	})
}

func (s *Server) handleDeleteEnv(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if !s.requireUnscoped(w, tok) {
		return
	}
	p, err := s.store.GetProject(r.Context(), r.PathValue("project"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !s.requireWrite(w, r, tok, p.ID) {
		return
	}
	envSlug := r.PathValue("env")
	err = s.store.DeleteEnvironment(r.Context(), p.ID, envSlug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "environment not found")
		return
	}
	if err != nil {
		s.log.Error("delete env", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionEnvDelete, p.ID, envSlug); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
