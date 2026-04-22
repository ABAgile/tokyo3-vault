package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

type createTokenRequest struct {
	Name      string `json:"name"`
	Project   string `json:"project"` // project slug (resolved to ID server-side)
	Env       string `json:"env"`     // environment slug within that project
	ReadOnly  bool   `json:"read_only"`
	ExpiresIn string `json:"expires_in"` // Go duration string e.g. "24h", "168h"
}

type tokenListItem struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	ProjectID *string `json:"project_id,omitempty"`
	EnvID     *string `json:"env_id,omitempty"`
	CreatedAt string  `json:"created_at"`
}

type createTokenResponse struct {
	Token string        `json:"token"`
	Meta  tokenListItem `json:"meta"`
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if tok.UserID == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	tokens, err := s.store.ListTokens(r.Context(), *tok.UserID)
	if err != nil {
		s.log.Error("list tokens", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	items := make([]tokenListItem, 0, len(tokens))
	for _, t := range tokens {
		items = append(items, tokenToItem(t))
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if tok.UserID == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.requireUnscoped(w, tok) {
		return
	}
	if !s.requireWritable(w, tok) {
		return
	}
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	var expiresIn time.Duration
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_in: use Go duration syntax e.g. 24h, 168h")
			return
		}
		expiresIn = d
	}

	projectID, envID, httpErr := s.resolveTokenScope(w, r, req.Project, req.Env)
	if httpErr {
		return
	}

	rawToken, newTok, err := auth.IssueMachineToken(r.Context(), s.store, *tok.UserID, req.Name, projectID, envID, req.ReadOnly, expiresIn)
	if err != nil {
		s.log.Error("issue machine token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.logAudit(r, ActionTokenCreate, projectID, req.Name)
	writeJSON(w, http.StatusCreated, createTokenResponse{
		Token: rawToken,
		Meta:  tokenToItem(newTok),
	})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	tok := tokenFromCtx(r)
	if tok.UserID == nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.requireWritable(w, tok) {
		return
	}
	id := r.PathValue("id")
	err := s.store.DeleteToken(r.Context(), id, *tok.UserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	if err != nil {
		s.log.Error("delete token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.logAudit(r, ActionTokenDelete, "", id)
	w.WriteHeader(http.StatusNoContent)
}

// resolveTokenScope looks up the project and optionally env slugs provided when
// creating a machine token. Returns the resolved IDs and true if an HTTP error
// was already written (caller should return immediately in that case).
func (s *Server) resolveTokenScope(w http.ResponseWriter, r *http.Request, projectSlug, envSlug string) (projectID, envID string, httpErr bool) {
	if projectSlug == "" {
		return "", "", false
	}
	p, err := s.store.GetProject(r.Context(), projectSlug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "project not found: "+projectSlug)
		return "", "", true
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", "", true
	}
	if envSlug == "" {
		return p.ID, "", false
	}
	e, err := s.store.GetEnvironment(r.Context(), p.ID, envSlug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "environment not found: "+envSlug)
		return "", "", true
	}
	if err != nil {
		s.log.Error("get environment", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", "", true
	}
	return p.ID, e.ID, false
}

func tokenToItem(t *model.Token) tokenListItem {
	return tokenListItem{
		ID:        t.ID,
		Name:      t.Name,
		ProjectID: t.ProjectID,
		EnvID:     t.EnvID,
		CreatedAt: fmtAPITime(t.CreatedAt),
	}
}
