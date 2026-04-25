package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$`)
var slugSanitizeRe = regexp.MustCompile(`[^a-z0-9]+`)

type projectResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"created_at"`
}

type createProjectRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// handleListProjects returns projects the token's user is a member of.
// Scoped machine tokens are blocked (they can't enumerate projects globally).
func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if !s.requireUnscoped(w, tok) {
		return
	}
	var projects []*model.Project
	var err error
	if tok.UserID != nil {
		projects, err = s.store.ListProjectsByMember(r.Context(), *tok.UserID)
	} else {
		projects, err = s.store.ListProjects(r.Context())
	}
	if err != nil {
		s.log.Error("list projects", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]projectResponse, 0, len(projects))
	for _, p := range projects {
		resp = append(resp, projectToResponse(p))
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleCreateProject creates a project and automatically adds the caller as owner.
func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if !s.requireUnscoped(w, tok) {
		return
	}
	if !s.requireWritable(w, tok) {
		return
	}
	var req createProjectRequest
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

	p, err := s.store.CreateProject(r.Context(), req.Name, req.Slug)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "project name or slug already exists")
		return
	}
	if err != nil {
		s.log.Error("create project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Generate and store a project envelope key (PEK) wrapped by the server KEK.
	// Non-fatal: if KMS is unavailable the project uses the backward-compat path
	// (master KEK directly) until operator runs `vaultd migrate-keys`.
	pek := make([]byte, 32)
	if _, randErr := rand.Read(pek); randErr == nil {
		if encPEK, wrapErr := s.kp.WrapDEK(r.Context(), pek); wrapErr == nil {
			if err := s.store.SetProjectKey(r.Context(), p.ID, encPEK, time.Now().UTC()); err != nil {
				s.log.Warn("set project key", "project", p.ID, "err", err)
			}
		} else {
			s.log.Warn("wrap project key", "project", p.ID, "err", wrapErr)
		}
	}

	// Auto-add the creating user as owner.
	if tok.UserID != nil {
		if err := s.store.AddProjectMember(r.Context(), p.ID, *tok.UserID, model.RoleOwner, nil); err != nil {
			s.log.Error("add project owner", "err", err)
			// Non-fatal: project exists, membership can be repaired. Return success.
		}
	}

	if err := s.logAudit(r, ActionProjectCreate, p.ID, p.Slug); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, projectToResponse(p))
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("project")
	p, err := s.store.GetProject(r.Context(), slug)
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
	writeJSON(w, http.StatusOK, projectToResponse(p))
}

// handleDeleteProject allows only the project owner (a user, not a machine token) to delete.
func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	slug := r.PathValue("project")
	p, err := s.store.GetProject(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !s.requireOwner(w, r, tok, p.ID) {
		return
	}
	if err := s.store.DeleteProject(r.Context(), slug); err != nil {
		s.log.Error("delete project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAudit(r, ActionProjectDelete, "", slug); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRotateProjectKey generates a fresh PEK, atomically re-wraps all project
// DEKs, and invalidates the in-memory cache. Owner-only; returns 204 on success.
func (s *Server) handleRotateProjectKey(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	slug := r.PathValue("project")
	p, err := s.store.GetProject(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.log.Error("rotate project key: get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !s.requireOwner(w, r, tok, p.ID) {
		return
	}
	if p.EncryptedPEK == nil {
		writeError(w, http.StatusConflict, "project has no envelope key; run vaultd migrate-keys first")
		return
	}

	oldPEK, err := s.kp.UnwrapDEK(r.Context(), p.EncryptedPEK)
	if err != nil {
		s.log.Error("rotate project key: unwrap old PEK", "project", slug, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	oldProjectKP := crypto.NewProjectKeyProvider(oldPEK)

	newPEK := make([]byte, 32)
	if _, err := rand.Read(newPEK); err != nil {
		s.log.Error("rotate project key: generate PEK", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	newEncPEK, err := s.kp.WrapDEK(r.Context(), newPEK)
	if err != nil {
		s.log.Error("rotate project key: wrap new PEK", "project", slug, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	newProjectKP := crypto.NewProjectKeyProvider(newPEK)

	rotatedAt := time.Now().UTC()
	err = s.store.RotateProjectPEK(r.Context(), p.ID, newEncPEK, rotatedAt, func(encDEK []byte) ([]byte, error) {
		dek, err := oldProjectKP.UnwrapDEK(r.Context(), encDEK)
		if err != nil {
			return nil, fmt.Errorf("unwrap DEK: %w", err)
		}
		return newProjectKP.WrapDEK(r.Context(), dek)
	})
	if err != nil {
		s.log.Error("rotate project key: rotate", "project", slug, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.projectKP.Invalidate(p.ID)

	if err := s.logAudit(r, ActionProjectRotateKey, p.ID, slug); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// toSlug converts a name to a URL-safe slug.
func toSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugSanitizeRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) < 2 {
		s = s + strings.Repeat("x", 2-len(s))
	}
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

func projectToResponse(p *model.Project) projectResponse {
	return projectResponse{
		ID: p.ID, Name: p.Name, Slug: p.Slug,
		CreatedAt: fmtAPITime(p.CreatedAt),
	}
}
