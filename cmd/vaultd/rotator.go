package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/abagile/tokyo3-vault/internal/audit"
	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

// actionProjectRotateKey mirrors api.ActionProjectRotateKey for system-initiated rotations.
const actionProjectRotateKey = "project.rotate_key"

// PEKRotator periodically rotates project envelope keys (PEKs) that are older
// than period. Each rotation atomically re-wraps all DEKs and updates the stored
// PEK in a single transaction, so a crash mid-rotation leaves the DB unchanged.
type PEKRotator struct {
	store     store.Store
	kp        crypto.KeyProvider
	projectKP *crypto.ProjectKeyCache
	audit     audit.Sink
	period    time.Duration
	log       *slog.Logger
}

func newPEKRotator(st store.Store, kp crypto.KeyProvider, projectKP *crypto.ProjectKeyCache, auditSink audit.Sink, period time.Duration, log *slog.Logger) *PEKRotator {
	return &PEKRotator{store: st, kp: kp, projectKP: projectKP, audit: auditSink, period: period, log: log}
}

// Run sweeps for stale PEKs at startup then every hour until ctx is cancelled.
func (r *PEKRotator) Run(ctx context.Context) {
	r.sweep(ctx)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sweep(ctx)
		}
	}
}

func (r *PEKRotator) sweep(ctx context.Context) {
	// Warn on any projects that have never been migrated — the rotator cannot
	// rotate them until migrate-keys has run.
	all, err := r.store.ListProjects(ctx)
	if err != nil {
		r.log.Error("pek rotator: list projects", "err", err)
		return
	}
	for _, p := range all {
		if p.EncryptedPEK == nil {
			r.log.Warn("pek rotator: project has no PEK, run vaultd migrate-keys", "slug", p.Slug)
		}
	}

	threshold := time.Now().UTC().Add(-r.period)
	stale, err := r.store.ListProjectsForPEKRotation(ctx, threshold)
	if err != nil {
		r.log.Error("pek rotator: list stale projects", "err", err)
		return
	}
	for _, p := range stale {
		if err := r.rotateProjectPEK(ctx, p); err != nil {
			r.log.Error("pek rotator: rotate PEK", "slug", p.Slug, "err", err)
		}
	}
}

func (r *PEKRotator) rotateProjectPEK(ctx context.Context, p *model.Project) error {
	oldPEK, err := r.kp.UnwrapDEK(ctx, p.EncryptedPEK)
	if err != nil {
		return fmt.Errorf("unwrap old PEK: %w", err)
	}
	oldProjectKP := crypto.NewProjectKeyProvider(oldPEK)

	newPEK := make([]byte, 32)
	if _, err := rand.Read(newPEK); err != nil {
		return fmt.Errorf("generate PEK: %w", err)
	}
	newEncPEK, err := r.kp.WrapDEK(ctx, newPEK)
	if err != nil {
		return fmt.Errorf("wrap new PEK: %w", err)
	}
	newProjectKP := crypto.NewProjectKeyProvider(newPEK)

	rotatedAt := time.Now().UTC()
	err = r.store.RotateProjectPEK(ctx, p.ID, newEncPEK, rotatedAt, func(encDEK []byte) ([]byte, error) {
		dek, err := oldProjectKP.UnwrapDEK(ctx, encDEK)
		if err != nil {
			return nil, err
		}
		return newProjectKP.WrapDEK(ctx, dek)
	})
	if err != nil {
		return fmt.Errorf("rotate project PEK: %w", err)
	}

	r.projectKP.Invalidate(p.ID)
	r.log.Info("pek rotator: rotated PEK", "slug", p.Slug, "rotated_at", rotatedAt)

	// Audit is best-effort: the rotation already committed to the DB, so a NATS
	// failure here should not surface as a rotation failure.
	if err := r.audit.Log(ctx, audit.Entry{
		ID:         uuid.NewString(),
		Action:     actionProjectRotateKey,
		ProjectID:  p.ID,
		Resource:   p.Slug,
		OccurredAt: rotatedAt,
	}); err != nil {
		r.log.Error("pek rotator: audit write failed", "slug", p.Slug, "err", err)
	}

	return nil
}
