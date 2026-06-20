package api

import "net/http"

// rateLimit wraps an auth-endpoint handler with the server's per-IP limiter
// (base/ratelimit). It is applied per-route — only the auth endpoints are
// limited — rather than as global middleware, preserving vault's scope. The
// limiter keys on the same trusted-proxy set as clientIP and renders a JSON 429
// (see New, where the limiter and its OnThrottle are configured).
func (s *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return s.authLimiter.Middleware(next).ServeHTTP
}
