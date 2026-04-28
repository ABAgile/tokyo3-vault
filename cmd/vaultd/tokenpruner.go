package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/abagile/tokyo3-vault/internal/store"
)

const tokenSweepEvery = time.Hour

// TokenPruner periodically removes expired token rows from the database.
type TokenPruner struct {
	store store.Store
	log   *slog.Logger
}

func newTokenPruner(st store.Store, log *slog.Logger) *TokenPruner {
	return &TokenPruner{store: st, log: log}
}

// Run sweeps for expired tokens at startup then every hour until ctx is cancelled.
func (p *TokenPruner) Run(ctx context.Context) {
	p.sweep(ctx)
	ticker := time.NewTicker(tokenSweepEvery)
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

func (p *TokenPruner) sweep(ctx context.Context) {
	n, err := p.store.DeleteExpiredTokens(ctx)
	if err != nil {
		p.log.Error("token pruner: delete expired tokens", "err", err)
		return
	}
	if n > 0 {
		p.log.Info("token pruner: removed expired tokens", "count", n)
	}
}
