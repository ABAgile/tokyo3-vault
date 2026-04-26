package api

import (
	"net/http"
	"time"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/google/uuid"
)

// Audit action constants — use these everywhere instead of raw strings.
const (
	ActionAuthSignup = "auth.signup"
	ActionAuthLogin  = "auth.login"
	ActionAuthLogout = "auth.logout"

	ActionProjectCreate    = "project.create"
	ActionProjectDelete    = "project.delete"
	ActionProjectRotateKey = "project.rotate_key"

	ActionEnvCreate = "env.create"
	ActionEnvDelete = "env.delete"

	ActionSecretGet             = "secret.get"
	ActionSecretSet             = "secret.set"
	ActionSecretDelete          = "secret.delete"
	ActionSecretRollback        = "secret.rollback"
	ActionSecretImport          = "secret.import"
	ActionSecretEnvfileUpload   = "secret.envfile_upload"
	ActionSecretEnvfileDownload = "secret.envfile_download"

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
