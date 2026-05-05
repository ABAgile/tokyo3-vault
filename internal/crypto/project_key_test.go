package crypto

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// makeKEK returns a deterministic 32-byte KEK for tests.
func makeKEK() []byte {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	return kek
}

// TestProjectKeyProvider_WrapUnwrap tests round-trip of WrapDEK/UnwrapDEK.
func TestProjectKeyProvider_WrapUnwrap(t *testing.T) {
	pek := make([]byte, 32)
	for i := range pek {
		pek[i] = byte(i + 10)
	}
	kp := NewProjectKeyProvider(pek)
	ctx := context.Background()

	dek := []byte("my-secret-dek-value-32-bytes!!!!")

	enc, err := kp.WrapDEK(ctx, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if len(enc) == 0 {
		t.Fatal("WrapDEK returned empty ciphertext")
	}

	dec, err := kp.UnwrapDEK(ctx, enc)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if string(dec) != string(dek) {
		t.Errorf("round-trip mismatch: got %q, want %q", dec, dek)
	}
}

// TestProjectKeyCache_NilEncPEK tests that nil encPEK returns master.
func TestProjectKeyCache_NilEncPEK(t *testing.T) {
	kek := makeKEK()
	master := NewLocalKeyProvider(kek)
	cache := NewProjectKeyCache(master, time.Minute)

	kp, err := cache.ForProject(context.Background(), "proj-1", nil)
	if err != nil {
		t.Fatalf("ForProject(nil): %v", err)
	}
	if kp != master {
		t.Error("expected master KeyProvider when encPEK is nil")
	}
}

// TestProjectKeyCache_CacheHit tests that ForProject caches the result.
func TestProjectKeyCache_CacheHit(t *testing.T) {
	kek := makeKEK()
	master := NewLocalKeyProvider(kek)
	cache := NewProjectKeyCache(master, time.Minute)
	ctx := context.Background()

	// Create a real PEK wrapped by the master KEK.
	pek := make([]byte, 32)
	for i := range pek {
		pek[i] = byte(i + 5)
	}
	encPEK, err := master.WrapDEK(ctx, pek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	kp1, err := cache.ForProject(ctx, "proj-x", encPEK)
	if err != nil {
		t.Fatalf("first ForProject: %v", err)
	}
	kp2, err := cache.ForProject(ctx, "proj-x", encPEK)
	if err != nil {
		t.Fatalf("second ForProject: %v", err)
	}
	if kp1 != kp2 {
		t.Error("second call should return cached provider (same pointer)")
	}
}

// TestProjectKeyCache_Invalidate tests that Invalidate removes the cache entry.
func TestProjectKeyCache_Invalidate(t *testing.T) {
	kek := makeKEK()
	master := NewLocalKeyProvider(kek)
	cache := NewProjectKeyCache(master, time.Minute)
	ctx := context.Background()

	pek := make([]byte, 32)
	for i := range pek {
		pek[i] = byte(i + 7)
	}
	encPEK, _ := master.WrapDEK(ctx, pek)

	kp1, _ := cache.ForProject(ctx, "proj-inv", encPEK)
	cache.Invalidate("proj-inv")
	kp2, _ := cache.ForProject(ctx, "proj-inv", encPEK)

	if kp1 == kp2 {
		t.Error("after Invalidate, ForProject should return a fresh provider")
	}
}

// TestProjectKeyCache_ExpiredTTL tests that a negative TTL forces cache miss every time.
func TestProjectKeyCache_ExpiredTTL(t *testing.T) {
	kek := makeKEK()
	master := NewLocalKeyProvider(kek)
	cache := NewProjectKeyCache(master, -1*time.Second) // TTL already expired
	ctx := context.Background()

	pek := make([]byte, 32)
	for i := range pek {
		pek[i] = byte(i + 3)
	}
	encPEK, _ := master.WrapDEK(ctx, pek)

	kp1, err := cache.ForProject(ctx, "proj-exp", encPEK)
	if err != nil {
		t.Fatalf("first ForProject: %v", err)
	}
	kp2, err := cache.ForProject(ctx, "proj-exp", encPEK)
	if err != nil {
		t.Fatalf("second ForProject: %v", err)
	}
	// With expired TTL every call re-creates the provider.
	if kp1 == kp2 {
		t.Error("expired TTL should bypass cache; expected new provider each call")
	}
}

// errKeyProvider is a KeyProvider that always fails UnwrapDEK.
type errKeyProvider struct{}

func (errKeyProvider) WrapDEK(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("wrap error")
}
func (errKeyProvider) UnwrapDEK(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("unwrap error")
}

// TestProjectKeyCache_UnwrapError tests that an unwrap failure propagates.
func TestProjectKeyCache_UnwrapError(t *testing.T) {
	cache := NewProjectKeyCache(errKeyProvider{}, time.Minute)
	_, err := cache.ForProject(context.Background(), "proj-err", []byte("bogus"))
	if err == nil {
		t.Fatal("expected error from unwrap failure, got nil")
	}
}

// countingKeyProvider records UnwrapDEK calls and sleeps briefly so concurrent
// callers overlap in the slow path. The exact PEK bytes don't matter for the
// dedupe assertion — only the call count.
type countingKeyProvider struct {
	calls atomic.Int64
	delay time.Duration
}

func (p *countingKeyProvider) WrapDEK(_ context.Context, dek []byte) ([]byte, error) {
	return append([]byte(nil), dek...), nil
}
func (p *countingKeyProvider) UnwrapDEK(_ context.Context, _ []byte) ([]byte, error) {
	p.calls.Add(1)
	time.Sleep(p.delay)
	return make([]byte, 32), nil
}

// TestProjectKeyCache_SingleflightDedupe asserts that concurrent cold misses
// for the same projectID collapse into a single master.UnwrapDEK call. Without
// singleflight the count would be `concurrency`; with it, exactly 1.
func TestProjectKeyCache_SingleflightDedupe(t *testing.T) {
	master := &countingKeyProvider{delay: 50 * time.Millisecond}
	cache := NewProjectKeyCache(master, time.Minute)

	const concurrency = 10
	encPEK := []byte("any-encpek-bytes")
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for range concurrency {
		go func() {
			defer wg.Done()
			<-start // release all goroutines simultaneously
			if _, err := cache.ForProject(context.Background(), "proj-dedupe", encPEK); err != nil {
				t.Errorf("ForProject: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := master.calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 UnwrapDEK call from %d concurrent misses, got %d", concurrency, got)
	}
}
