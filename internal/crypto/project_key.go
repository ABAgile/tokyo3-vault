package crypto

import (
	"context"
	"fmt"
	"sync"
	"time"

	lcrypto "github.com/abagile/tokyo3-lcl/crypto"
	"golang.org/x/sync/singleflight"
)

// projectKeyProvider implements lcrypto.KeyProvider using a plaintext in-memory
// PEK. All operations are pure AES-256-GCM via lcrypto.Seal/Open.
type projectKeyProvider struct{ pek []byte }

func (p *projectKeyProvider) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	return lcrypto.Seal(p.pek, dek)
}

func (p *projectKeyProvider) Unwrap(_ context.Context, enc []byte) ([]byte, error) {
	return lcrypto.Open(p.pek, enc)
}

// NewProjectKeyProvider returns a KeyProvider backed by the given 32-byte PEK.
// Use this when constructing a project KP outside this package (e.g. migration).
func NewProjectKeyProvider(pek []byte) lcrypto.KeyProvider {
	return &projectKeyProvider{pek: pek}
}

// pekCacheEntry holds a cached project key and its expiry.
type pekCacheEntry struct {
	kp        *projectKeyProvider
	expiresAt time.Time
}

// ProjectKeyCache caches per-project plaintext PEKs to minimise calls to the
// server-level KeyProvider (KMS). ForProject returns a project-scoped KeyProvider;
// the server KEK is called at most once per project per TTL period.
//
// `unwrap` collapses concurrent cache misses for the same project — when N
// goroutines miss simultaneously (cold start, post-TTL, or post-Invalidate),
// only one calls master.Unwrap; the rest piggyback on its result.
type ProjectKeyCache struct {
	master lcrypto.KeyProvider
	mu     sync.RWMutex
	keys   map[string]*pekCacheEntry
	ttl    time.Duration
	unwrap singleflight.Group
}

// NewProjectKeyCache returns a ProjectKeyCache backed by master (the server
// KEK/KMS). ttl controls how long a decrypted PEK stays in memory; 5 minutes
// is a reasonable default that keeps KMS costs low without holding keys
// indefinitely.
func NewProjectKeyCache(master lcrypto.KeyProvider, ttl time.Duration) *ProjectKeyCache {
	return &ProjectKeyCache{
		master: master,
		keys:   make(map[string]*pekCacheEntry),
		ttl:    ttl,
	}
}

// ForProject returns a KeyProvider for the given project.
//
//   - If encPEK is nil the project has not been migrated yet; the server-level
//     master KeyProvider is returned so existing per-secret DEKs continue to
//     work without any data migration.
//   - Otherwise the PEK is unwrapped (via master) on cache miss and cached for
//     ttl; subsequent calls within that window are free.
func (c *ProjectKeyCache) ForProject(ctx context.Context, projectID string, encPEK []byte) (lcrypto.KeyProvider, error) {
	if encPEK == nil {
		return c.master, nil
	}

	// Fast path: cache hit.
	c.mu.RLock()
	entry, ok := c.keys[projectID]
	if ok && time.Now().Before(entry.expiresAt) {
		kp := entry.kp
		c.mu.RUnlock()
		return kp, nil
	}
	c.mu.RUnlock()

	// Slow path: collapse concurrent misses for the same project into a single
	// Unwrap call. The leader runs with its own ctx; waiters share its result
	// (or its error — failure paths dedupe too).
	v, err, _ := c.unwrap.Do(projectID, func() (any, error) {
		// Re-check after acquiring the singleflight slot — a previous leader
		// may have populated the cache while we were queued.
		c.mu.RLock()
		entry, ok := c.keys[projectID]
		c.mu.RUnlock()
		if ok && time.Now().Before(entry.expiresAt) {
			return entry.kp, nil
		}

		pek, err := c.master.Unwrap(ctx, encPEK)
		if err != nil {
			return nil, fmt.Errorf("unwrap project key: %w", err)
		}
		kp := &projectKeyProvider{pek: pek}
		c.mu.Lock()
		c.keys[projectID] = &pekCacheEntry{kp: kp, expiresAt: time.Now().Add(c.ttl)}
		c.mu.Unlock()
		return kp, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(lcrypto.KeyProvider), nil
}

// Invalidate removes a project's cached PEK, forcing the next ForProject call
// to re-unwrap from the store. Call after rotating a project's PEK.
func (c *ProjectKeyCache) Invalidate(projectID string) {
	c.mu.Lock()
	delete(c.keys, projectID)
	c.mu.Unlock()
}
