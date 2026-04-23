package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

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

// logAudit writes an audit entry. projectID and resource are optional.
func (s *Server) logAudit(r *http.Request, action, projectID, resource string) {
	s.logAuditMeta(r, action, projectID, resource, "")
}

// logAuditMeta is like logAudit but also stores a free-form JSON metadata string.
// Use it for operations where extra context is valuable (e.g. masked secret values).
func (s *Server) logAuditMeta(r *http.Request, action, projectID, resource, metadata string) {
	tok := tokenFromCtx(r)

	entry := &model.AuditLog{
		ID:        uuid.NewString(),
		Action:    action,
		CreatedAt: time.Now().UTC(),
	}
	if tok != nil {
		entry.ActorID = &tok.ID
	}
	if projectID != "" {
		entry.ProjectID = &projectID
	}
	if resource != "" {
		entry.Resource = &resource
	}
	if metadata != "" {
		entry.Metadata = &metadata
	}
	ip := clientIP(r)
	if ip != "" {
		entry.IP = &ip
	}

	if err := s.store.CreateAuditLog(r.Context(), entry); err != nil {
		s.log.Error("write audit log", "action", action, "err", err)
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	}
	// RemoteAddr is "host:port" — strip the port.
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
	Resource  *string `json:"resource,omitempty"`
	Metadata  *string `json:"metadata,omitempty"`
	IP        *string `json:"ip,omitempty"`
	CreatedAt string  `json:"created_at"`
}

// handleListAuditLogs serves GET /api/v1/audit
// Query params: project=<slug>, action=<string>, limit=<int>
//
// Access:
//   - With ?project=<slug>: requires project owner role (or server admin).
//   - Without project filter: requires server admin.
func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnscoped(w, tokenFromCtx(r)) {
		return
	}

	filter := store.AuditFilter{}

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
		// Project-scoped view: require owner role (server admin bypasses via requireProjectRole).
		if !s.requireProjectRole(w, r, p.ID, model.RoleOwner) {
			return
		}
		filter.ProjectID = p.ID
	} else {
		// Global view: require server admin.
		if !s.requireServerAdmin(w, r) {
			return
		}
	}

	if action := r.URL.Query().Get("action"); action != "" {
		filter.Action = action
	}
	if lim := r.URL.Query().Get("limit"); lim != "" {
		n, err := strconv.Atoi(lim)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit must be 1–500")
			return
		}
		filter.Limit = n
	}

	logs, err := s.store.ListAuditLogs(r.Context(), filter)
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
			Resource:  e.Resource,
			Metadata:  e.Metadata,
			IP:        e.IP,
			CreatedAt: fmtAPITime(e.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}
