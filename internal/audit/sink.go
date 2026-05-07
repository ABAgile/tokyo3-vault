// Package audit provides the audit event pipeline for vaultd.
//
// Write path (vaultd serve):
//
//	Handler → journal.EncodedSink[Entry].Append → JetStream "vault_audit"
//	                                              stream (authoritative record)
//
// Read/consume path (vault-audit — separate binary):
//
//	JetStream → vault-audit consume → DB.UpsertAuditLog → audit database
//	vault-audit query → DB.ListAuditLogs → terminal output
//
// The JetStream stream is the tamper-resistant, authoritative record (DenyDelete,
// DenyPurge, FileStorage). The audit database is a queryable projection rebuilt
// from the stream by vault-audit; it can be dropped and replayed at any time.
//
// Credential separation:
//   - vaultd serve uses a NATS publisher credential (PUBLISH-only on vault.audit.events).
//   - vault-audit consume uses a NATS consumer credential (SUBSCRIBE + consumer
//     management) and an audit DB writer credential (INSERT-only on audit_logs).
//   - Neither credential can perform the other role's operations.
//
// The Entry → JSON adapter and JetStream transport are provided by
// base/journal: vaultd wires up `journal.NewJSONSink[Entry](jetstreamInner)`
// and handlers call Append directly. Vault keeps only the Entry shape and
// the wire-config constants (Subject / StreamName / StreamMaxAge); the
// transport and the marshalling are not vault concerns.
package audit

import (
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// Wire-format constants for the audit pipeline. Subject and StreamName are
// the NATS subject that vaultd publishes to and the JetStream stream that
// vault-audit consumes from. StreamMaxAge is the retention floor for
// PCI-DSS 10.5 (12 months); 13 months gives a comfortable roll-over buffer.
const (
	Subject      = "vault.audit.events"
	StreamName   = "vault_audit"
	StreamMaxAge = 400 * 24 * time.Hour
)

// Sink is a type alias for the typed JSON-encoding journal sink that vaultd
// uses to publish audit Entries. Construct with
// journal.NewJSONSink[Entry](innerSink) — the alias is purely an
// ergonomic shortcut, not a distinct type.
type Sink = *journal.EncodedSink[Entry]

// NoopSink is a shared audit sink that discards every event. Use in tests
// and dev environments where the audit journal is not configured. Safe for
// concurrent use; the underlying journal.Noop is stateless.
var NoopSink Sink = journal.NewJSONSink[Entry](journal.Noop{})

// Entry is the canonical shape of a single audit event. It is JSON-serialised
// as the journal payload and stored verbatim in the audit database by the
// consumer. Fields are omitted from JSON when empty to keep payloads lean.
type Entry struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	ActorID    string    `json:"actor_id,omitempty"`
	ProjectID  string    `json:"project_id,omitempty"`
	EnvID      string    `json:"env_id,omitempty"`
	Resource   string    `json:"resource,omitempty"`
	IP         string    `json:"ip,omitempty"`
	Metadata   string    `json:"metadata,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}
