package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/abagile/tokyo3-base/journal/jetstream"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/abagile/tokyo3-vault/internal/audit"
)

// runAuditQuery prints the most recent N audit events from the vault_audit
// JetStream stream as one JSON object per line on stdout, then exits.
//
// Connects to NATS via VAULT_NATS_URL + VAULT_NATS_CERT/KEY/CA — same
// credentials the publisher uses, since vault_audit is the authoritative
// store and there is no separate projection. Reuses journal/jetstream.Source
// (the same primitive backing the portal admin live-tail page) so the CLI
// and the UI share one read path.
//
// Filtering (--action, --actor, --project, --since) is intentionally not
// surfaced yet; add it as flags here when the use case demands.
func runAuditQuery(ctx context.Context, limit int) error {
	if limit < 1 || limit > 1000 {
		return fmt.Errorf("--limit must be between 1 and 1000")
	}
	url := os.Getenv("VAULT_NATS_URL")
	if url == "" {
		return fmt.Errorf("VAULT_NATS_URL is not set — cannot query audit journal")
	}
	tlsCfg, err := btls.FromFiles(
		os.Getenv("VAULT_NATS_CERT"),
		os.Getenv("VAULT_NATS_KEY"),
		os.Getenv("VAULT_NATS_CA"),
	)
	if err != nil {
		return fmt.Errorf("nats audit TLS: %w", err)
	}
	src, err := jetstream.NewSource(jetstream.SourceConfig{
		URL:        url,
		StreamName: audit.StreamName,
		Subject:    audit.Subject,
		TLS:        tlsCfg,
	})
	if err != nil {
		return fmt.Errorf("open audit source: %w", err)
	}
	defer src.Close()

	queryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	msgs, err := src.Subscribe(queryCtx, limit, 0)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	// After delivering the backfill window the consumer would tail new
	// records indefinitely, but a `query` is a one-shot read. Exit when
	// either --limit records are seen or the stream has gone quiet for
	// idleTimeout — whichever comes first.
	const idleTimeout = 2 * time.Second
	idle := time.NewTimer(idleTimeout)
	defer idle.Stop()

	count := 0
	for count < limit {
		select {
		case <-queryCtx.Done():
			return nil
		case <-idle.C:
			return nil
		case m, ok := <-msgs:
			if !ok {
				return nil
			}
			if _, err := os.Stdout.Write(m.Data); err != nil {
				return err
			}
			if _, err := os.Stdout.Write([]byte("\n")); err != nil {
				return err
			}
			count++
			if !idle.Stop() {
				<-idle.C
			}
			idle.Reset(idleTimeout)
		}
	}
	return nil
}
