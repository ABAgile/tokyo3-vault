package api

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipLimiter struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

type rateLimiter struct {
	mu    sync.Mutex
	ips   map[string]*ipLimiter
	r     rate.Limit
	burst int
}

// newRateLimiter creates a per-IP token-bucket limiter.
// perMin is the sustained request rate per minute; burst is the maximum instantaneous burst.
func newRateLimiter(perMin int, burst int) *rateLimiter {
	rl := &rateLimiter{ips: make(map[string]*ipLimiter), r: rate.Limit(float64(perMin) / 60.0), burst: burst}
	go rl.sweep()
	return rl
}

func (rl *rateLimiter) get(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.ips[ip]
	if !ok {
		e = &ipLimiter{lim: rate.NewLimiter(rl.r, rl.burst)}
		rl.ips[ip] = e
	}
	e.lastSeen = time.Now()
	return e.lim
}

// sweep removes entries that have been idle for more than 10 minutes.
func (rl *rateLimiter) sweep() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		rl.mu.Lock()
		for ip, e := range rl.ips {
			if time.Since(e.lastSeen) > 10*time.Minute {
				delete(rl.ips, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// rateLimit wraps a handler with per-IP rate limiting using the server's auth limiter.
func (s *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authLimiter.get(s.clientIP(r)).Allow() {
			writeError(w, http.StatusTooManyRequests, "too many requests — try again later")
			return
		}
		next(w, r)
	}
}
