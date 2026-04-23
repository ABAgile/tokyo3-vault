package main

// vaultd audit-consumer — reads audit events from the NATS JetStream AUDIT stream
// and upserts them into the dedicated audit database, building the queryable
// projection used by GET /api/v1/audit.
//
// Environment variables:
//
//	NATS_URL                      NATS server URL (required)
//	NATS_CONSUMER_CERT            Consumer client certificate PEM path (mTLS)
//	NATS_CONSUMER_KEY             Consumer client key PEM path
//	NATS_CONSUMER_CA              CA certificate PEM path for NATS server verification
//	AUDIT_WRITE_DATABASE_URL      Postgres DSN (vault_audit_writer user)
//	AUDIT_WRITE_DB_PATH           SQLite path (alternative to Postgres; default: audit.db)
//	AUDIT_WRITE_DB_SSL_CERT       Client cert for audit DB mTLS
//	AUDIT_WRITE_DB_SSL_KEY        Client key for audit DB mTLS
//	AUDIT_WRITE_DB_SSL_ROOTCERT   CA cert for audit DB server verification
//
// The consumer connects to NATS with a credential that has SUBSCRIBE + consumer
// management rights on audit.events — distinct from the publisher credential
// used by vaultd serve, which has PUBLISH-only rights.
//
// The audit DB write credential (vault_audit_writer) has INSERT-only rights on
// audit_logs; it cannot SELECT, UPDATE, or DELETE rows.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/tlsutil"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const auditConsumerName = "audit-db-writer"

// runAuditConsumer is the entry point for `vaultd audit-consumer`. It blocks
// until ctx is cancelled (SIGINT/SIGTERM).
func runAuditConsumer(ctx context.Context, log *slog.Logger) error {
	adb, err := openAuditWriteDB(log)
	if err != nil {
		return fmt.Errorf("open audit write db: %w", err)
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
		Durable:       auditConsumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: audit.Subject,
		MaxAckPending: 256,
	})
	if err != nil {
		return fmt.Errorf("create audit consumer: %w", err)
	}

	log.Info("audit-consumer: running",
		"stream", audit.StreamName,
		"consumer", auditConsumerName,
	)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		batch, err := cons.Fetch(64, jetstream.FetchMaxWait(2*time.Second))
		if err != nil {
			log.Warn("audit-consumer: fetch error", "err", err)
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
				log.Error("audit-consumer: unmarshal failed, discarding message",
					"err", err, "data", string(msg.Data()))
				msg.Ack()
				continue
			}
			if err := adb.UpsertAuditLog(ctx, e); err != nil {
				log.Error("audit-consumer: upsert failed, nacking", "err", err)
				msg.Nak()
				continue
			}
			msg.Ack()
		}
		if err := batch.Error(); err != nil {
			log.Warn("audit-consumer: batch error", "err", err)
		}
	}
}

func openAuditWriteDB(log *slog.Logger) (*audit.DB, error) {
	if dsn := os.Getenv("AUDIT_WRITE_DATABASE_URL"); dsn != "" {
		tlsCfg, err := tlsutil.FromFiles(
			os.Getenv("AUDIT_WRITE_DB_SSL_CERT"),
			os.Getenv("AUDIT_WRITE_DB_SSL_KEY"),
			os.Getenv("AUDIT_WRITE_DB_SSL_ROOTCERT"),
		)
		if err != nil {
			return nil, fmt.Errorf("audit write db TLS: %w", err)
		}
		if tlsCfg != nil {
			log.Info("audit write: postgres with mTLS client cert")
		} else {
			log.Info("audit write: postgres")
		}
		return audit.OpenPostgres(dsn, tlsCfg)
	}
	path := os.Getenv("AUDIT_WRITE_DB_PATH")
	if path == "" {
		path = "audit.db"
	}
	log.Info("audit write: sqlite", "path", path)
	return audit.OpenSQLite(path)
}

func connectConsumerNATS(log *slog.Logger) (*nats.Conn, error) {
	url := os.Getenv("NATS_URL")
	if url == "" {
		return nil, fmt.Errorf("NATS_URL is required for audit-consumer")
	}
	tlsCfg, err := tlsutil.FromFiles(
		os.Getenv("NATS_CONSUMER_CERT"),
		os.Getenv("NATS_CONSUMER_KEY"),
		os.Getenv("NATS_CONSUMER_CA"),
	)
	if err != nil {
		return nil, fmt.Errorf("nats consumer TLS: %w", err)
	}
	var opts []nats.Option
	if tlsCfg != nil {
		log.Info("audit-consumer: NATS mTLS enabled", "url", url)
		opts = append(opts, nats.Secure(tlsCfg))
	} else {
		log.Warn("audit-consumer: NATS_CONSUMER_CERT not set — connecting without mTLS (not for production)")
	}
	return nats.Connect(url, opts...)
}
