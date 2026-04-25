// vault-audit is the standalone audit pipeline tool for the Vault secret manager.
//
// Subcommands:
//
//	vault-audit consume   Read audit events from NATS JetStream and upsert them
//	                      into the dedicated audit database. Runs until SIGINT/SIGTERM.
//	vault-audit query     Query the audit database and print matching entries.
//
// # Environment variables (both subcommands share the database vars)
//
//	VAULT_AUDIT_DATABASE_URL   Postgres DSN with DDL + DML + SELECT rights on the
//	                           audit database; mutually exclusive with VAULT_AUDIT_DB_PATH.
//	VAULT_AUDIT_DB_PATH        SQLite path (default for consume: audit.db).
//	VAULT_AUDIT_DB_CERT    Client cert PEM path for audit DB mTLS.
//	VAULT_AUDIT_DB_KEY     Client key PEM path. Required when VAULT_AUDIT_DB_CERT is set.
//	VAULT_AUDIT_DB_CA      CA cert PEM path for verifying the audit DB server cert.
//
// # consume-only environment variables
//
//	VAULT_AUDIT_NATS_URL    NATS server URL (required for consume).
//	VAULT_AUDIT_NATS_CERT   Consumer client certificate PEM path (mTLS).
//	VAULT_AUDIT_NATS_KEY    Consumer client key PEM path.
//	VAULT_AUDIT_NATS_CA     CA certificate PEM path for NATS server verification.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abagile/tokyo3-vault/internal/audit"
	auditpg "github.com/abagile/tokyo3-vault/internal/audit/postgres"
	auditsqlite "github.com/abagile/tokyo3-vault/internal/audit/sqlite"
	"github.com/abagile/tokyo3-vault/internal/tlsutil"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/spf13/cobra"
)

const consumerName = "audit-db-writer"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	root := &cobra.Command{
		Use:           "vault-audit",
		Short:         "Audit pipeline tool for the Vault secret manager",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newConsumeCmd(ctx, log), newQueryCmd(ctx))

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// openAuditDB opens the audit database from VAULT_AUDIT_DATABASE_URL (Postgres)
// or VAULT_AUDIT_DB_PATH (SQLite). The returned audit.Store is used for migrations,
// writes, and queries — the single credential requires DDL + INSERT + SELECT rights.
// defaultPath is used when VAULT_AUDIT_DB_PATH is unset; pass "" to require an
// explicit path (query command) or a fallback (consume command).
func openAuditDB(log *slog.Logger, defaultPath string) (audit.Store, error) {
	if dsn := os.Getenv("VAULT_AUDIT_DATABASE_URL"); dsn != "" {
		tlsCfg, err := tlsutil.FromFiles(
			os.Getenv("VAULT_AUDIT_DB_CERT"),
			os.Getenv("VAULT_AUDIT_DB_KEY"),
			os.Getenv("VAULT_AUDIT_DB_CA"),
		)
		if err != nil {
			return nil, fmt.Errorf("audit db TLS: %w", err)
		}
		if err := auditpg.Migrate(dsn, tlsCfg); err != nil {
			return nil, fmt.Errorf("audit db migration: %w", err)
		}
		if tlsCfg != nil {
			log.Info("audit db: postgres with mTLS client cert")
		} else {
			log.Info("audit db: postgres")
		}
		return auditpg.Open(dsn, tlsCfg)
	}
	path := os.Getenv("VAULT_AUDIT_DB_PATH")
	if path == "" {
		if defaultPath == "" {
			return nil, fmt.Errorf("VAULT_AUDIT_DATABASE_URL or VAULT_AUDIT_DB_PATH is required")
		}
		path = defaultPath
	}
	log.Info("audit db: sqlite", "path", path)
	return auditsqlite.Open(path)
}

// ── consume ───────────────────────────────────────────────────────────────────

func newConsumeCmd(ctx context.Context, log *slog.Logger) *cobra.Command {
	return &cobra.Command{
		Use:   "consume",
		Short: "Read audit events from NATS JetStream and write to the audit database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConsume(ctx, log)
		},
	}
}

func runConsume(ctx context.Context, log *slog.Logger) error {
	adb, err := openAuditDB(log, "audit.db")
	if err != nil {
		return fmt.Errorf("open audit db: %w", err)
	}
	defer adb.Close()

	nc, err := connectConsumerNATS(log)
	if err != nil {
		return fmt.Errorf("nats connect: %w", err)
	}
	defer nc.Drain()

	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("jetstream client: %w", err)
	}

	// Ensure the AUDIT stream exists. In production the NATS operator should
	// provision the stream; CreateOrUpdateStream is idempotent so it is safe
	// to call here as a convenience for development and first-run scenarios.
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       audit.StreamName,
		Subjects:   []string{audit.Subject},
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		MaxAge:     audit.StreamMaxAge,
		DenyDelete: true,
		DenyPurge:  true,
	})
	if err != nil {
		return fmt.Errorf("ensure audit stream: %w", err)
	}

	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       consumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: audit.Subject,
		MaxAckPending: 256,
	})
	if err != nil {
		return fmt.Errorf("create audit consumer: %w", err)
	}

	log.Info("consume: running", "stream", audit.StreamName, "consumer", consumerName)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		batch, err := cons.Fetch(64, jetstream.FetchMaxWait(2*time.Second))
		if err != nil {
			log.Warn("consume: fetch error", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}

		for msg := range batch.Messages() {
			var e audit.Entry
			if err := json.Unmarshal(msg.Data(), &e); err != nil {
				// Malformed payload: ack to skip rather than loop forever on redelivery.
				log.Error("consume: unmarshal failed, discarding", "err", err, "data", string(msg.Data()))
				msg.Ack()
				continue
			}
			if err := adb.UpsertAuditLog(ctx, e); err != nil {
				log.Error("consume: upsert failed, nacking", "err", err)
				msg.Nak()
				continue
			}
			msg.Ack()
		}
		if err := batch.Error(); err != nil {
			log.Warn("consume: batch error", "err", err)
		}
	}
}

func connectConsumerNATS(log *slog.Logger) (*nats.Conn, error) {
	url := os.Getenv("VAULT_AUDIT_NATS_URL")
	if url == "" {
		return nil, fmt.Errorf("VAULT_AUDIT_NATS_URL is required for consume")
	}
	tlsCfg, err := tlsutil.FromFiles(
		os.Getenv("VAULT_AUDIT_NATS_CERT"),
		os.Getenv("VAULT_AUDIT_NATS_KEY"),
		os.Getenv("VAULT_AUDIT_NATS_CA"),
	)
	if err != nil {
		return nil, fmt.Errorf("nats consumer TLS: %w", err)
	}
	var opts []nats.Option
	if tlsCfg != nil {
		log.Info("consume: NATS mTLS enabled", "url", url)
		opts = append(opts, nats.Secure(tlsCfg))
	} else {
		log.Warn("consume: VAULT_AUDIT_NATS_CERT not set — connecting without mTLS (not for production)")
	}
	return nats.Connect(url, opts...)
}

// ── query ─────────────────────────────────────────────────────────────────────

func newQueryCmd(ctx context.Context) *cobra.Command {
	var projectID, envID, action string
	var limit int

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query the audit database and print matching entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuery(ctx, projectID, envID, action, limit)
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Filter by project UUID")
	cmd.Flags().StringVar(&envID, "env-id", "", "Filter by environment UUID")
	cmd.Flags().StringVar(&action, "action", "", "Filter by action (e.g. secret.get)")
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum entries to return (1–500)")
	return cmd
}

func runQuery(ctx context.Context, projectID, envID, action string, limit int) error {
	if limit < 1 || limit > 500 {
		return fmt.Errorf("--limit must be between 1 and 500")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	db, err := openAuditDB(log, "")
	if err != nil {
		return fmt.Errorf("open audit db: %w", err)
	}
	defer db.Close()

	logs, err := db.ListAuditLogs(ctx, audit.Filter{
		ProjectID: projectID,
		EnvID:     envID,
		Action:    action,
		Limit:     limit,
	})
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	if len(logs) == 0 {
		fmt.Println("No audit entries found.")
		return nil
	}

	fmt.Printf("%-22s  %-24s  %-30s  %s\n", "TIME", "ACTION", "RESOURCE", "ACTOR")
	for _, e := range logs {
		resource := "-"
		if e.Resource != nil {
			resource = *e.Resource
		}
		actor := "-"
		if e.ActorID != nil && len(*e.ActorID) >= 8 {
			actor = (*e.ActorID)[:8] + "…"
		} else if e.ActorID != nil {
			actor = *e.ActorID
		}
		fmt.Printf("%-22s  %-24s  %-30s  %s\n",
			e.CreatedAt.Local().Format("2006-01-02 15:04:05"),
			e.Action, resource, actor)
	}
	return nil
}
