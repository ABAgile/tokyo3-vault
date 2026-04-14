// Package api implements the Vault HTTP API.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/abagile/tokyo3-vault/internal/store"
)

// Server holds shared dependencies for all HTTP handlers.
type Server struct {
	store store.Store
	kek   []byte // master key encryption key (AES-256)
	log   *slog.Logger
}

// New returns a configured Server.
func New(st store.Store, kek []byte, log *slog.Logger) *Server {
	return &Server{store: st, kek: kek, log: log}
}

// Routes registers all API routes on mux and returns it.
// Using Go 1.22 enhanced routing: "METHOD /path/{param}".
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Audit
	mux.HandleFunc("GET /api/v1/audit", s.auth(s.handleListAuditLogs))

	// Auth
	mux.HandleFunc("POST /api/v1/auth/signup", s.handleSignup)
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("DELETE /api/v1/auth/logout", s.auth(s.handleLogout))

	// Tokens (machine tokens)
	mux.HandleFunc("GET /api/v1/tokens", s.auth(s.handleListTokens))
	mux.HandleFunc("POST /api/v1/tokens", s.auth(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.auth(s.handleDeleteToken))

	// Projects
	mux.HandleFunc("GET /api/v1/projects", s.auth(s.handleListProjects))
	mux.HandleFunc("POST /api/v1/projects", s.auth(s.handleCreateProject))
	mux.HandleFunc("GET /api/v1/projects/{project}", s.auth(s.handleGetProject))
	mux.HandleFunc("DELETE /api/v1/projects/{project}", s.auth(s.handleDeleteProject))

	// Auth
	mux.HandleFunc("PUT /api/v1/auth/password", s.auth(s.handleChangePassword))

	// Users (admin-managed)
	mux.HandleFunc("GET /api/v1/users", s.auth(s.handleListUsers))
	mux.HandleFunc("POST /api/v1/users", s.auth(s.handleCreateUser))
	mux.HandleFunc("GET /api/v1/users/lookup", s.auth(s.handleLookupUser))
	mux.HandleFunc("PUT /api/v1/users/{user_id}/password", s.auth(s.handleResetUserPassword))

	// Project members
	mux.HandleFunc("GET /api/v1/projects/{project}/members", s.auth(s.handleListMembers))
	mux.HandleFunc("POST /api/v1/projects/{project}/members", s.auth(s.handleAddMember))
	mux.HandleFunc("PUT /api/v1/projects/{project}/members/{user_id}", s.auth(s.handleUpdateMember))
	mux.HandleFunc("DELETE /api/v1/projects/{project}/members/{user_id}", s.auth(s.handleRemoveMember))

	// Environments
	mux.HandleFunc("GET /api/v1/projects/{project}/envs", s.auth(s.handleListEnvs))
	mux.HandleFunc("POST /api/v1/projects/{project}/envs", s.auth(s.handleCreateEnv))
	mux.HandleFunc("DELETE /api/v1/projects/{project}/envs/{env}", s.auth(s.handleDeleteEnv))

	// Secrets
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/secrets", s.auth(s.handleListSecrets))
	mux.HandleFunc("POST /api/v1/projects/{project}/envs/{env}/secrets", s.auth(s.handleSetSecret))
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/secrets/{key}", s.auth(s.handleGetSecret))
	mux.HandleFunc("PUT /api/v1/projects/{project}/envs/{env}/secrets/{key}", s.auth(s.handleSetSecret))
	mux.HandleFunc("DELETE /api/v1/projects/{project}/envs/{env}/secrets/{key}", s.auth(s.handleDeleteSecret))
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/secrets/{key}/versions", s.auth(s.handleListSecretVersions))
	mux.HandleFunc("POST /api/v1/projects/{project}/envs/{env}/secrets/{key}/rollback", s.auth(s.handleRollbackSecret))
	mux.HandleFunc("POST /api/v1/projects/{project}/envs/{env}/secrets/import", s.auth(s.handleImportSecrets))
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/secrets/dotenv", s.auth(s.handleDownloadDotenv))
	mux.HandleFunc("POST /api/v1/projects/{project}/envs/{env}/secrets/dotenv", s.auth(s.handleUploadDotenv))

	return mux
}

// ── response helpers ──────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
