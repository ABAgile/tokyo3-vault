package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-base/ratelimit"
)

// TestRateLimit_Allow verifies that the rateLimit middleware allows requests
// within burst capacity.
func TestRateLimit_Allow(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	srv.authLimiter = ratelimit.New(ratelimit.Config{RPS: 10, Burst: 10}) // 10 req/s, burst=10

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

// TestRateLimit_Exhausted verifies that requests are blocked after the burst is
// exceeded, and that the throttled response is vault's JSON 429.
func TestRateLimit_Exhausted(t *testing.T) {
	srv := newTestServer(t, &mockStore{})
	// Very low rate and burst=1 so the second request is rate-limited. Configure
	// the JSON OnThrottle exactly as New does, to lock the 429 body contract.
	srv.authLimiter = ratelimit.New(ratelimit.Config{
		RPS:   1.0 / 60.0,
		Burst: 1,
		OnThrottle: func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusTooManyRequests, "too many requests — try again later")
		},
	})

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

	// Second request immediately after should be rate-limited with a JSON body.
	r2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	r2.RemoteAddr = ip
	w2 := httptest.NewRecorder()
	handler(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want 429", w2.Code)
	}
	if ct := w2.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Error("429 should carry a Retry-After header")
	}
}
