// Package api implements the Vault HTTP API.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/crypto"
	oidcpkg "github.com/abagile/tokyo3-vault/internal/oidc"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// Server holds shared dependencies for all HTTP handlers.
type Server struct {
	store       store.Store
	kp          crypto.KeyProvider      // server KEK — used only to wrap/unwrap PEKs
	projectKP   *crypto.ProjectKeyCache // project-scoped key cache; wraps/unwraps per-secret DEKs
	log         *slog.Logger
	oidc        *oidcpkg.Provider // nil when OIDC is not configured
	oidcEnforce bool              // true = local login/signup disabled
	audit       audit.Sink        // publishes events to NATS JetStream
}

// New returns a configured Server. sink publishes audit events to NATS JetStream;
// pass audit.NoopSink{} in tests.
func New(st store.Store, kp crypto.KeyProvider, projectKP *crypto.ProjectKeyCache, log *slog.Logger, oidcProvider *oidcpkg.Provider, oidcEnforce bool, sink audit.Sink) *Server {
	return &Server{
		store:       st,
		kp:          kp,
		projectKP:   projectKP,
		log:         log,
		oidc:        oidcProvider,
		oidcEnforce: oidcEnforce,
		audit:       sink,
	}
}

// Routes registers all API routes on mux and returns it.
// Using Go 1.22 enhanced routing: "METHOD /path/{param}".
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Auth — local
	mux.HandleFunc("POST /api/v1/auth/signup", s.handleSignup)
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("DELETE /api/v1/auth/logout", s.auth(s.handleLogout))

	// Auth — OIDC/SSO
	mux.HandleFunc("GET /api/v1/auth/oidc/config", s.handleOIDCConfig)
	mux.HandleFunc("GET /api/v1/auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("GET /api/v1/auth/oidc/callback", s.handleOIDCCallback)

	// SCIM 2.0 provisioning (IdP push)
	mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", s.handleSCIMServiceProviderConfig)
	mux.HandleFunc("GET /scim/v2/ResourceTypes", s.handleSCIMResourceTypes)
	mux.HandleFunc("GET /scim/v2/Schemas", s.handleSCIMSchemas)
	mux.HandleFunc("GET /scim/v2/Users", s.scimAuth(s.handleSCIMListUsers))
	mux.HandleFunc("POST /scim/v2/Users", s.scimAuth(s.handleSCIMCreateUser))
	mux.HandleFunc("GET /scim/v2/Users/{id}", s.scimAuth(s.handleSCIMGetUser))
	mux.HandleFunc("PUT /scim/v2/Users/{id}", s.scimAuth(s.handleSCIMReplaceUser))
	mux.HandleFunc("PATCH /scim/v2/Users/{id}", s.scimAuth(s.handleSCIMPatchUser))
	mux.HandleFunc("DELETE /scim/v2/Users/{id}", s.scimAuth(s.handleSCIMDeleteUser))
	mux.HandleFunc("GET /scim/v2/Groups", s.scimAuth(s.handleSCIMListGroups))
	mux.HandleFunc("POST /scim/v2/Groups", s.scimAuth(s.handleSCIMCreateGroup))
	mux.HandleFunc("GET /scim/v2/Groups/{id}", s.scimAuth(s.handleSCIMGetGroup))
	mux.HandleFunc("PUT /scim/v2/Groups/{id}", s.scimAuth(s.handleSCIMReplaceGroup))
	mux.HandleFunc("PATCH /scim/v2/Groups/{id}", s.scimAuth(s.handleSCIMPatchGroup))
	mux.HandleFunc("DELETE /scim/v2/Groups/{id}", s.scimAuth(s.handleSCIMDeleteGroup))

	// SCIM token management (server admin only)
	mux.HandleFunc("POST /api/v1/scim/tokens", s.auth(s.handleCreateSCIMToken))
	mux.HandleFunc("GET /api/v1/scim/tokens", s.auth(s.handleListSCIMTokens))
	mux.HandleFunc("DELETE /api/v1/scim/tokens/{id}", s.auth(s.handleDeleteSCIMToken))

	// SCIM group→role mapping management (server admin only)
	mux.HandleFunc("POST /api/v1/scim/group-roles", s.auth(s.handleCreateSCIMGroupRole))
	mux.HandleFunc("GET /api/v1/scim/group-roles", s.auth(s.handleListSCIMGroupRoles))
	mux.HandleFunc("DELETE /api/v1/scim/group-roles/{id}", s.auth(s.handleDeleteSCIMGroupRole))

	// Tokens (machine tokens)
	mux.HandleFunc("GET /api/v1/tokens", s.auth(s.handleListTokens))
	mux.HandleFunc("POST /api/v1/tokens", s.auth(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.auth(s.handleDeleteToken))

	// SPIFFE/mTLS certificate principals
	mux.HandleFunc("POST /api/v1/cert-principals", s.auth(s.handleRegisterCertPrincipal))
	mux.HandleFunc("GET /api/v1/cert-principals", s.auth(s.handleListCertPrincipals))
	mux.HandleFunc("DELETE /api/v1/cert-principals/{id}", s.auth(s.handleDeleteCertPrincipal))

	// Projects
	mux.HandleFunc("GET /api/v1/projects", s.auth(s.handleListProjects))
	mux.HandleFunc("POST /api/v1/projects", s.auth(s.handleCreateProject))
	mux.HandleFunc("GET /api/v1/projects/{project}", s.auth(s.handleGetProject))
	mux.HandleFunc("DELETE /api/v1/projects/{project}", s.auth(s.handleDeleteProject))
	mux.HandleFunc("POST /api/v1/projects/{project}/rotate-key", s.auth(s.handleRotateProjectKey))

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

	// Access — unified identity list for a project+env
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/access", s.auth(s.handleListAccess))

	// Secrets
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/secrets", s.auth(s.handleListSecrets))
	mux.HandleFunc("POST /api/v1/projects/{project}/envs/{env}/secrets", s.auth(s.handleSetSecret))
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/secrets/{key}", s.auth(s.handleGetSecret))
	mux.HandleFunc("PUT /api/v1/projects/{project}/envs/{env}/secrets/{key}", s.auth(s.handleSetSecret))
	mux.HandleFunc("DELETE /api/v1/projects/{project}/envs/{env}/secrets/{key}", s.auth(s.handleDeleteSecret))
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/secrets/{key}/versions", s.auth(s.handleListSecretVersions))
	mux.HandleFunc("POST /api/v1/projects/{project}/envs/{env}/secrets/{key}/rollback", s.auth(s.handleRollbackSecret))
	mux.HandleFunc("POST /api/v1/projects/{project}/envs/{env}/secrets/import", s.auth(s.handleImportSecrets))
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/secrets/envfile", s.auth(s.handleDownloadEnvfile))
	mux.HandleFunc("POST /api/v1/projects/{project}/envs/{env}/secrets/envfile", s.auth(s.handleUploadEnvfile))

	// Dynamic backends — backend configuration (keyed by user-defined name slug)
	mux.HandleFunc("PUT /api/v1/projects/{project}/envs/{env}/dynamic/{name}", s.auth(s.handleSetDynamicBackend))
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/dynamic/{name}", s.auth(s.handleGetDynamicBackend))
	mux.HandleFunc("DELETE /api/v1/projects/{project}/envs/{env}/dynamic/{name}", s.auth(s.handleDeleteDynamicBackend))

	// Dynamic backends — roles
	mux.HandleFunc("PUT /api/v1/projects/{project}/envs/{env}/dynamic/{name}/roles/{role}", s.auth(s.handleSetDynamicRole))
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/dynamic/{name}/roles", s.auth(s.handleListDynamicRoles))
	mux.HandleFunc("DELETE /api/v1/projects/{project}/envs/{env}/dynamic/{name}/roles/{role}", s.auth(s.handleDeleteDynamicRole))

	// Dynamic backends — creds & leases (leases are project+env scoped, no backend name needed)
	mux.HandleFunc("POST /api/v1/projects/{project}/envs/{env}/dynamic/{name}/{role}/creds", s.auth(s.handleIssueCreds))
	mux.HandleFunc("GET /api/v1/projects/{project}/envs/{env}/dynamic/leases", s.auth(s.handleListDynamicLeases))
	mux.HandleFunc("DELETE /api/v1/projects/{project}/envs/{env}/dynamic/leases/{lease_id}", s.auth(s.handleRevokeDynamicLease))

	return limitBody(mux)
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		next.ServeHTTP(w, r)
	})
}

// ── response helpers ──────────────────────────────────────────────────────────

func fmtAPITime(t interface{ Format(string) string }) string {
	return t.Format("2006-01-02T15:04:05Z")
}

func fmtOptionalTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := fmtAPITime(*t)
	return &s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
