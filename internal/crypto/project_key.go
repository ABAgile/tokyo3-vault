package crypto

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// projectKeyProvider implements KeyProvider using a plaintext in-memory PEK.
// All operations are pure AES-256-GCM via the package-private seal/open helpers.
type projectKeyProvider struct{ pek []byte }

func (p *projectKeyProvider) WrapDEK(_ context.Context, dek []byte) ([]byte, error) {
	return seal(p.pek, dek)
}

func (p *projectKeyProvider) UnwrapDEK(_ context.Context, enc []byte) ([]byte, error) {
	return open(p.pek, enc)
}

// NewProjectKeyProvider returns a KeyProvider backed by the given 32-byte PEK.
// Use this when constructing a project KP outside this package (e.g. migration).
func NewProjectKeyProvider(pek []byte) KeyProvider {
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
type ProjectKeyCache struct {
	master KeyProvider
	mu     sync.RWMutex
	keys   map[string]*pekCacheEntry
	ttl    time.Duration
}

// NewProjectKeyCache returns a ProjectKeyCache backed by master (the server
// KEK/KMS). ttl controls how long a decrypted PEK stays in memory; 5 minutes
// is a reasonable default that keeps KMS costs low without holding keys
// indefinitely.
func NewProjectKeyCache(master KeyProvider, ttl time.Duration) *ProjectKeyCache {
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
func (c *ProjectKeyCache) ForProject(ctx context.Context, projectID string, encPEK []byte) (KeyProvider, error) {
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

	// Slow path: unwrap PEK via master KeyProvider (may call KMS).
	pek, err := c.master.UnwrapDEK(ctx, encPEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap project key: %w", err)
	}

	kp := &projectKeyProvider{pek: pek}
	c.mu.Lock()
	c.keys[projectID] = &pekCacheEntry{kp: kp, expiresAt: time.Now().Add(c.ttl)}
	c.mu.Unlock()

	return kp, nil
}

// Invalidate removes a project's cached PEK, forcing the next ForProject call
// to re-unwrap from the store. Call after rotating a project's PEK.
func (c *ProjectKeyCache) Invalidate(projectID string) {
	c.mu.Lock()
	delete(c.keys, projectID)
	c.mu.Unlock()
}
