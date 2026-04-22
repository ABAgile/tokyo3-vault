package model

import "time"

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

type User struct {
	ID           string
	Email        string
	PasswordHash string
	Role         string // UserRoleAdmin | UserRoleMember
	CreatedAt    time.Time
}

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

type Project struct {
	ID        string
	Name      string
	Slug      string
	CreatedAt time.Time
}

type Environment struct {
	ID        string
	ProjectID string
	Name      string
	Slug      string
	CreatedAt time.Time
}

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

// AuditLog records a single auditable action taken by an actor.
type AuditLog struct {
	ID        string
	Action    string
	ActorID   *string // token ID; nil for unauthenticated actions
	ProjectID *string
	Resource  *string // e.g. secret key name
	Metadata  *string // free-form JSON string for extra context
	IP        *string
	CreatedAt time.Time
}

// ProjectMember records a user's role in a project.
type ProjectMember struct {
	ProjectID string
	UserID    string
	Role      string // RoleViewer | RoleEditor | RoleOwner
	CreatedAt time.Time
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
// Placeholders: {{name}}, {{password}}, {{expiry}}.
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
