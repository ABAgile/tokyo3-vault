// Package audit provides the audit event types for vaultd.
//
// Write path (vaultd serve):
//
//	Handler → journal.EncodedSink[Entry].Append → JetStream "vault_audit"
//	                                              stream (authoritative store)
//
// Read paths (both off the same stream):
//
//	/portal/admin/audit/sse → journal/sse.Handler → live tail in browser
//	vaultd audit-query      → journal/jetstream.Source → terminal output
//
// The JetStream stream is the tamper-resistant authoritative record
// (DenyDelete, DenyPurge, FileStorage, 13-month retention); there is no
// separate projection database. Querying back is a thin reader on top of
// journal.Source — same primitive both UI and CLI use.
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

// Wire-format constants for the audit journal. Subject is what vaultd
// publishes to; StreamName is the JetStream stream covering it. StreamMaxAge
// is the retention floor for PCI-DSS 10.5 (12 months); 13 months gives a
// comfortable roll-over buffer.
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
// concurrent use; the underlying journal.NoopSink is stateless.
var NoopSink Sink = journal.NewJSONSink[Entry](journal.NoopSink{})

// Entry is the canonical shape of a single audit event. It is JSON-serialised
// as the journal payload and stored verbatim in the audit database by the
// consumer. Fields are omitted from JSON when empty to keep payloads lean.
//
// ActorEmail/ActorName/ProjectSlug/EnvSlug are denormalised name snapshots
// resolved at publish time so live tail viewers can render rows without
// round-tripping the UUIDs. For human-user actor tokens ActorEmail comes
// from the linked user; for machine tokens ActorName is the token's
// descriptive name and ActorEmail is empty. ProjectSlug/EnvSlug are the
// human-readable slugs for the corresponding IDs. Any of these fields may
// be empty if the referenced row has been deleted before audit.
type Entry struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`
	ActorID     string    `json:"actor_id,omitempty"`
	ActorEmail  string    `json:"actor_email,omitempty"`
	ActorName   string    `json:"actor_name,omitempty"`
	ProjectID   string    `json:"project_id,omitempty"`
	ProjectSlug string    `json:"project_slug,omitempty"`
	EnvID       string    `json:"env_id,omitempty"`
	EnvSlug     string    `json:"env_slug,omitempty"`
	Resource    string    `json:"resource,omitempty"`
	IP          string    `json:"ip,omitempty"`
	Metadata    string    `json:"metadata,omitempty"`
	OccurredAt  time.Time `json:"occurred_at"`
}
