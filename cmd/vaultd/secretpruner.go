package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/abagile/tokyo3-vault/internal/store"
)

const versionSweepEvery = 24 * time.Hour

// VersionPruner periodically removes secret versions outside the retention window.
type VersionPruner struct {
	store    store.Store
	log      *slog.Logger
	minCount int
	minAge   time.Duration
}

func newVersionPruner(st store.Store, log *slog.Logger, minCount int, minAge time.Duration) *VersionPruner {
	return &VersionPruner{store: st, log: log, minCount: minCount, minAge: minAge}
}

// Run sweeps for pruneable versions at startup then every 24 hours until ctx is cancelled.
func (p *VersionPruner) Run(ctx context.Context) {
	p.sweep(ctx)
	ticker := time.NewTicker(versionSweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.sweep(ctx)
		}
	}
}

func (p *VersionPruner) sweep(ctx context.Context) {
	secrets, err := p.store.ListSecretsForPrune(ctx)
	if err != nil {
		p.log.Error("version pruner: list secrets", "err", err)
		return
	}
	cutoff := time.Now().UTC().Add(-p.minAge)
	processed, failed := 0, 0
	for _, pair := range secrets {
		secretID, currentVersionID := pair[0], pair[1]
		if currentVersionID == "" {
			continue
		}
		if err := p.store.PruneSecretVersions(ctx, secretID, currentVersionID, p.minCount, cutoff); err != nil {
			p.log.Error("version pruner: prune versions", "secret_id", secretID, "err", err)
			failed++
			continue
		}
		processed++
	}
	if processed > 0 || failed > 0 {
		p.log.Info("version pruner: sweep complete", "secrets_processed", processed, "failed", failed)
	}
}
