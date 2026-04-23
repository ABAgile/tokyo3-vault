// Package audit provides the audit event pipeline for vaultd.
//
// Write path (vaultd serve):
//
//	Handler → Sink.Log → NATS JetStream "AUDIT" stream (authoritative record)
//
// Read path (vaultd audit-consumer + vaultd serve):
//
//	JetStream → audit-consumer → DB.UpsertAuditLog → audit database
//	API handler → DB.ListAuditLogs → response
//
// The JetStream stream is the tamper-resistant, authoritative record (DenyDelete,
// DenyPurge, FileStorage). The audit database is a queryable projection rebuilt
// from the stream by the consumer; it can be dropped and replayed at any time.
//
// Credential separation:
//   - vaultd serve uses a NATS publisher credential (PUBLISH-only on audit.events)
//     and an audit DB reader credential (SELECT-only on audit_logs).
//   - vaultd audit-consumer uses a NATS consumer credential (SUBSCRIBE + consumer
//     management) and an audit DB writer credential (INSERT-only on audit_logs).
//   - Neither credential can perform the other role's operations.
package audit

import (
	"context"
	"time"
)

// Entry is the canonical shape of a single audit event. It is JSON-serialised
// as the NATS message payload and stored verbatim in the audit database by
// the consumer. Fields are omitted from JSON when empty to keep payloads lean.
type Entry struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	ActorID    string    `json:"actor_id,omitempty"`
	ProjectID  string    `json:"project_id,omitempty"`
	Resource   string    `json:"resource,omitempty"`
	IP         string    `json:"ip,omitempty"`
	Metadata   string    `json:"metadata,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// Sink accepts audit events for durable, tamper-resistant storage.
// Log must be safe for concurrent callers. Close drains pending work and
// frees resources — call it on server shutdown.
type Sink interface {
	Log(ctx context.Context, e Entry) error
	Close() error
}

// NoopSink discards all events. Use in tests and when NATS is not configured.
type NoopSink struct{}

func (NoopSink) Log(_ context.Context, _ Entry) error { return nil }
func (NoopSink) Close() error                         { return nil }
