package dynamic

import (
	"context"
	"log/slog"
	"time"

	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// Revoker periodically queries for expired leases and drops the corresponding
// credentials. It also sweeps on startup to handle any leases that expired
// while the server was down.
type Revoker struct {
	store store.Store
	kp    crypto.KeyProvider
	log   *slog.Logger
}

// NewRevoker returns a Revoker backed by the given store and key provider.
func NewRevoker(st store.Store, kp crypto.KeyProvider, log *slog.Logger) *Revoker {
	return &Revoker{store: st, kp: kp, log: log}
}

// Run blocks until ctx is cancelled, sweeping for expired leases every minute.
func (r *Revoker) Run(ctx context.Context) {
	r.sweep(ctx)
	ticker := time.NewTicker(60 * time.Second)
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

func (r *Revoker) sweep(ctx context.Context) {
	leases, err := r.store.ListExpiredDynamicLeases(ctx)
	if err != nil {
		r.log.Error("dynamic revoker: list expired leases", "err", err)
		return
	}
	for _, lease := range leases {
		if err := r.revokeLease(ctx, lease); err != nil {
			r.log.Error("dynamic revoker: revoke lease",
				"lease_id", lease.ID,
				"username", lease.Username,
				"err", err)
		}
	}
}

func (r *Revoker) revokeLease(ctx context.Context, lease *model.DynamicLease) error {
	backend, err := r.store.GetDynamicBackendByID(ctx, lease.BackendID)
	if err == store.ErrNotFound {
		// Backend deleted — mark revoked without running revocation template.
		r.log.Warn("dynamic revoker: backend gone, marking lease revoked",
			"lease_id", lease.ID, "backend_id", lease.BackendID)
		return r.store.RevokeDynamicLease(ctx, lease.ID)
	}
	if err != nil {
		return err
	}

	issuer, err := Get(backend.Type)
	if err != nil {
		return err
	}
	if err := issuer.Revoke(ctx, r.kp, backend, lease.RevocationTmpl, lease.Username); err != nil {
		return err
	}
	return r.store.RevokeDynamicLease(ctx, lease.ID)
}

// EffectiveTTL resolves the TTL for a role: role.TTL overrides backend.DefaultTTL,
// and the result is capped at backend.MaxTTL. ttlOverride of 0 means "use role default".
func EffectiveTTL(backend *model.DynamicBackend, role *model.DynamicRole, ttlOverride int) time.Duration {
	ttl := backend.DefaultTTL
	if role.TTL != nil {
		ttl = *role.TTL
	}
	if ttlOverride > 0 {
		ttl = ttlOverride
	}
	if ttl > backend.MaxTTL {
		ttl = backend.MaxTTL
	}
	return time.Duration(ttl) * time.Second
}
