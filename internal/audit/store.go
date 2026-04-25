package audit

import (
	"context"

	"github.com/abagile/tokyo3-vault/internal/model"
)

// Filter controls which audit log entries Store.ListAuditLogs returns.
type Filter struct {
	ProjectID string // empty = all projects
	EnvID     string // empty = all environments
	Action    string // empty = all actions
	Limit     int    // 0 = default (50)
}

// Store is the read/write interface for the audit database.
// Satisfied by *postgres.DB and *sqlite.DB.
type Store interface {
	UpsertAuditLog(ctx context.Context, e Entry) error
	ListAuditLogs(ctx context.Context, f Filter) ([]*model.AuditLog, error)
	Close() error
}
