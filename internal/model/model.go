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
