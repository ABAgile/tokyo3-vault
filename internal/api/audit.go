package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

// Audit action constants — use these everywhere instead of raw strings.
const (
	ActionAuthSignup = "auth.signup"
	ActionAuthLogin  = "auth.login"
	ActionAuthLogout = "auth.logout"

	ActionProjectCreate = "project.create"
	ActionProjectDelete = "project.delete"

	ActionEnvCreate = "env.create"
	ActionEnvDelete = "env.delete"

	ActionSecretGet            = "secret.get"
	ActionSecretSet            = "secret.set"
	ActionSecretDelete         = "secret.delete"
	ActionSecretRollback       = "secret.rollback"
	ActionSecretImport         = "secret.import"
	ActionSecretDotenvUpload   = "secret.dotenv_upload"
	ActionSecretDotenvDownload = "secret.dotenv_download"

	ActionAuthChangePassword = "auth.change_password"

	ActionTokenCreate = "token.create"
	ActionTokenDelete = "token.delete"

	ActionUserCreate = "user.create"

	ActionMemberAdd    = "member.add"
	ActionMemberUpdate = "member.update"
	ActionMemberRemove = "member.remove"

	ActionAuthLoginFailed = "auth.login_failed"

	ActionDynamicBackendSet    = "dynamic.backend.set"
	ActionDynamicBackendDelete = "dynamic.backend.delete"
	ActionDynamicRoleSet       = "dynamic.role.set"
	ActionDynamicRoleDelete    = "dynamic.role.delete"
	ActionDynamicLeaseIssue    = "dynamic.lease.issue"
	ActionDynamicLeaseRevoke   = "dynamic.lease.revoke"

	ActionCertPrincipalRegister = "cert.principal.register"
	ActionCertPrincipalDelete   = "cert.principal.delete"

	ActionAuthOIDCLogin          = "auth.oidc.login"
	ActionAuthOIDCJITProvision   = "auth.oidc.jit_provision"
	ActionAuthOIDCIdentityLinked = "auth.oidc.identity_linked"

	ActionSCIMUserCreate     = "scim.user.create"
	ActionSCIMUserUpdate     = "scim.user.update"
	ActionSCIMUserDeactivate = "scim.user.deactivate"
	ActionSCIMGroupSync      = "scim.group.sync"

	ActionSCIMTokenCreate = "scim.token.create"
	ActionSCIMTokenDelete = "scim.token.delete"
)

// logAudit publishes an audit entry to the NATS JetStream sink and returns an
// error if the publish fails. Callers must treat a non-nil error as fatal for
// the current request: write HTTP 500 and return immediately so that sensitive
// operations are never served without a durable audit record (fail-closed).
func (s *Server) logAudit(r *http.Request, action, projectID, resource string) error {
	return s.logAuditEnv(r, action, projectID, "", resource, "")
}

// logAuditEnv is the canonical audit helper. envID scopes the entry to a
// specific environment (empty for project-level or global actions). metadata
// is an optional free-form JSON string. Returns an error on publish failure.
func (s *Server) logAuditEnv(r *http.Request, action, projectID, envID, resource, metadata string) error {
	tok := tokenFromCtx(r)

	e := audit.Entry{
		ID:         uuid.NewString(),
		Action:     action,
		OccurredAt: time.Now().UTC(),
		ProjectID:  projectID,
		EnvID:      envID,
		Resource:   resource,
		Metadata:   metadata,
		IP:         clientIP(r),
	}
	if tok != nil {
		e.ActorID = tok.ID
	}

	if err := s.audit.Log(r.Context(), e); err != nil {
		s.log.Error("audit write failed — request blocked (fail-closed)",
			"action", action, "err", err)
		return err
	}
	return nil
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	}
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i != -1 {
		return addr[:i]
	}
	return addr
}

// ── Audit log HTTP handler ────────────────────────────────────────────────────

type auditLogResponse struct {
	ID        string  `json:"id"`
	Action    string  `json:"action"`
	ActorID   *string `json:"actor_id,omitempty"`
	ProjectID *string `json:"project_id,omitempty"`
	EnvID     *string `json:"env_id,omitempty"`
	Resource  *string `json:"resource,omitempty"`
	Metadata  *string `json:"metadata,omitempty"`
	IP        *string `json:"ip,omitempty"`
	CreatedAt string  `json:"created_at"`
}

// handleListAuditLogs serves GET /api/v1/audit
// Query params: project=<slug>, env=<slug>, action=<string>, limit=<int>
//
// Access:
//   - With ?project=<slug>: requires project owner role (or server admin).
//   - Without project filter: requires server admin.
//
// Results are served from the dedicated audit database (AUDIT_DATABASE_URL /
// AUDIT_DB_PATH), which is populated by vaultd audit-consumer. The NATS
// JetStream stream is the authoritative record; this endpoint serves the
// queryable projection.
func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnscoped(w, tokenFromCtx(r)) {
		return
	}

	f := audit.Filter{}

	if slug := r.URL.Query().Get("project"); slug != "" {
		p, err := s.store.GetProject(r.Context(), slug)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "project not found")
			return
		}
		if err != nil {
			s.log.Error("get project for audit", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !s.requireProjectRole(w, r, p.ID, model.RoleOwner) {
			return
		}
		f.ProjectID = p.ID

		if envSlug := r.URL.Query().Get("env"); envSlug != "" {
			env, err := s.store.GetEnvironment(r.Context(), p.ID, envSlug)
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "environment not found")
				return
			}
			if err != nil {
				s.log.Error("get environment for audit", "err", err)
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
			f.EnvID = env.ID
		}
	} else {
		if !s.requireServerAdmin(w, r) {
			return
		}
	}

	if action := r.URL.Query().Get("action"); action != "" {
		f.Action = action
	}
	if lim := r.URL.Query().Get("limit"); lim != "" {
		n, err := strconv.Atoi(lim)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit must be 1–500")
			return
		}
		f.Limit = n
	}

	logs, err := s.auditStore.ListAuditLogs(r.Context(), f)
	if err != nil {
		s.log.Error("list audit logs", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	resp := make([]auditLogResponse, 0, len(logs))
	for _, e := range logs {
		resp = append(resp, auditLogResponse{
			ID:        e.ID,
			Action:    e.Action,
			ActorID:   e.ActorID,
			ProjectID: e.ProjectID,
			EnvID:     e.EnvID,
			Resource:  e.Resource,
			Metadata:  e.Metadata,
			IP:        e.IP,
			CreatedAt: fmtAPITime(e.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}
