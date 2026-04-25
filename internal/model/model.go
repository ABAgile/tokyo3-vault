package model

import "time"

// ── Server-level constants ────────────────────────────────────────────────────

// Server-level user roles.
const (
	UserRoleMember = "member"
	UserRoleAdmin  = "admin"
)

// Project member roles — ordered by privilege (lowest → highest).
const (
	RoleViewer = "viewer"
	RoleEditor = "editor"
	RoleOwner  = "owner"
)

// ── Core identity types ───────────────────────────────────────────────────────

type User struct {
	ID             string
	Email          string
	PasswordHash   string  // empty for OIDC-only users
	Role           string  // UserRoleAdmin | UserRoleMember
	OIDCIssuer     *string // nil for local accounts
	OIDCSubject    *string // nil for local accounts; unique per issuer when set
	Active         bool    // false = deprovisioned by SCIM
	SCIMExternalID *string // IdP externalId for correlation
	CreatedAt      time.Time
}

type SCIMToken struct {
	ID          string
	TokenHash   string
	Description string
	CreatedAt   time.Time
}

type SCIMGroupRole struct {
	ID          string
	GroupID     string
	DisplayName string
	ProjectID   *string
	EnvID       *string
	Role        string
	CreatedAt   time.Time
}

// Token covers both user session tokens (UserID set, ProjectID nil) and
// machine tokens (may have ProjectID/EnvID scope and ReadOnly flag).
type Token struct {
	ID        string
	UserID    *string
	TokenHash string
	Name      string
	ProjectID *string
	EnvID     *string
	ReadOnly  bool // if true, token cannot perform any write operation
	ExpiresAt *time.Time
	CreatedAt time.Time
}

// CertPrincipal maps a certificate identity to vault authorization scope.
// Exactly one of SPIFFEID or EmailSAN must be non-nil.
//   - SPIFFEID: URI SAN with spiffe:// scheme (workload / SPIFFE identity)
//   - EmailSAN: rfc822Name SAN (human user with corporate PKI cert or tbot cert)
type CertPrincipal struct {
	ID          string
	UserID      *string // owner — who registered this mapping
	Description string
	SPIFFEID    *string // URI SAN, e.g. spiffe://cluster.local/ns/myapp/sa/server
	EmailSAN    *string // email SAN, e.g. alice@corp.example.com
	ProjectID   *string // nil = unscoped (any project)
	EnvID       *string // nil = any env
	ReadOnly    bool
	ExpiresAt   *time.Time // when this mapping expires (independent of cert lifetime)
	CreatedAt   time.Time
}

// ── Project and environment types ────────────────────────────────────────────

type Project struct {
	ID           string
	Name         string
	Slug         string
	EncryptedPEK []byte // PEK wrapped by server KEK; nil until migrated
	CreatedAt    time.Time
}

type Environment struct {
	ID        string
	ProjectID string
	Name      string
	Slug      string
	CreatedAt time.Time
}

// ProjectMember records a user's role in a project or a specific environment.
// EnvID nil means project-level access (all environments). Non-nil means access
// is scoped to that single environment only.
type ProjectMember struct {
	ProjectID string
	UserID    string
	EnvID     *string // nil = project-level; non-nil = env-specific
	Role      string  // RoleViewer | RoleEditor | RoleOwner
	CreatedAt time.Time
}

// ── Secret types ─────────────────────────────────────────────────────────────

type Secret struct {
	ID               string
	ProjectID        string
	EnvID            string
	Key              string
	Comment          string // raw text preceding this key in a .env file
	Position         int    // insertion order: rowid in SQLite, sequence in Postgres
	CurrentVersionID *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type SecretVersion struct {
	ID             string
	SecretID       string
	EncryptedValue []byte
	EncryptedDEK   []byte
	Version        int
	CreatedAt      time.Time
	CreatedBy      *string
}

// ── Audit log ─────────────────────────────────────────────────────────────────

// AuditLog records a single auditable action taken by an actor.
type AuditLog struct {
	ID        string
	Action    string
	ActorID   *string // token ID; nil for unauthenticated actions
	ProjectID *string
	EnvID     *string
	Resource  *string // e.g. secret key name
	Metadata  *string // free-form JSON string for extra context
	IP        *string
	CreatedAt time.Time
}

// ── Dynamic secrets types ─────────────────────────────────────────────────────

// DynamicBackend holds the encrypted connection config for a named backend
// within a project+environment. Uniqueness is (project_id, env_id, slug).
// Multiple backends of the same type can coexist under different slugs.
type DynamicBackend struct {
	ID                 string
	ProjectID          string
	EnvID              string
	Slug               string // user-defined slug, e.g. "primary", "analytics"
	Type               string // backend type, e.g. "postgresql"
	EncryptedConfig    []byte
	EncryptedConfigDEK []byte
	DefaultTTL         int // seconds
	MaxTTL             int // seconds
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// DynamicRole defines templates for creating and revoking credentials.
// Placeholders: {{username}}, {{password}}, {{expiry}}.
type DynamicRole struct {
	ID             string
	BackendID      string
	Name           string
	CreationTmpl   string
	RevocationTmpl string
	TTL            *int // nil = use backend DefaultTTL
	CreatedAt      time.Time
}

// DynamicLease records a single issued credential pair.
// Rows are never deleted — RevokedAt marks revocation.
// RevocationTmpl and BackendID are denormalized from the role at issuance time
// so leases can be revoked even if the role or backend is later deleted.
type DynamicLease struct {
	ID             string
	ProjectID      string
	EnvID          string
	BackendID      string
	RoleID         string
	RoleName       string
	Username       string
	RevocationTmpl string
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	CreatedBy      *string
	CreatedAt      time.Time
}
