package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewRateLimiter verifies that newRateLimiter creates a limiter and that the
// background sweep goroutine doesn't panic.
func TestNewRateLimiter(t *testing.T) {
	rl := newRateLimiter(60, 5)
	if rl == nil {
		t.Fatal("expected non-nil rateLimiter")
	}
	if len(rl.ips) != 0 {
		t.Errorf("expected empty ips map, got %d entries", len(rl.ips))
	}
}

// TestRateLimiter_Get verifies the get method creates and returns an IP limiter.
func TestRateLimiter_Get(t *testing.T) {
	rl := newRateLimiter(60, 5)
	lim1 := rl.get("192.168.1.1")
	if lim1 == nil {
		t.Fatal("expected non-nil limiter for new IP")
	}
	lim2 := rl.get("192.168.1.1")
	if lim2 != lim1 {
		t.Error("same IP should return the same limiter instance")
	}
	lim3 := rl.get("10.0.0.1")
	if lim3 == lim1 {
		t.Error("different IPs should return different limiters")
	}
	if len(rl.ips) != 2 {
		t.Errorf("expected 2 IP entries, got %d", len(rl.ips))
	}
}

// TestRateLimit_Allow verifies that the rateLimit middleware allows requests
// within burst capacity and blocks when exhausted.
func TestRateLimit_Allow(t *testing.T) {
	// High burst: first request should always be allowed.
	srv := newTestServer(t, &mockStore{})
	srv.authLimiter = newRateLimiter(600, 10) // 10 req/s, burst=10

	called := false
	handler := srv.rateLimit(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	r.RemoteAddr = "203.0.113.5:4321"
	w := httptest.NewRecorder()
	handler(w, r)

	if !called {
		t.Error("inner handler should have been called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestRateLimit_Exhausted verifies that requests are blocked after the burst is exceeded.
func TestRateLimit_Exhausted(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	// Very low rate and burst=1 so the second request is rate-limited.
	srv.authLimiter = newRateLimiter(1, 1)

	handler := srv.rateLimit(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ip := "203.0.113.42:1234"
	// First request should succeed (burst=1).
	r1 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	r1.RemoteAddr = ip
	w1 := httptest.NewRecorder()
	handler(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", w1.Code)
	}

	// Second request immediately after should be rate-limited.
	r2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	r2.RemoteAddr = ip
	w2 := httptest.NewRecorder()
	handler(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want 429", w2.Code)
	}
}
