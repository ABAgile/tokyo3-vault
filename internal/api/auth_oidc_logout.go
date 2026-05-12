package api

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/abagile/tokyo3-vault/internal/store"
)

// backchannelLogoutJTIWindow is the dedup window for jti values. logout_tokens
// are signed with a 2-minute exp; a 5-minute window comfortably covers worst-
// case clock skew while still bounding memory. Entries are evicted on the
// next sweep after their expiry, which happens once per minute on the lazy
// path inside acceptLogoutJTI.
const backchannelLogoutJTIWindow = 5 * time.Minute

// jtiCache provides single-binary replay protection for incoming
// logout_tokens. A POSTed jti that's been seen within the window is rejected
// regardless of whether its signature still verifies — the JWT spec leaves
// replay defense to relying parties, and OIDC Back-Channel Logout §2.6
// explicitly recommends it.
//
// Single-replica deployment so an in-memory map is sufficient. A multi-
// replica deployment would want a DB-backed table or a Redis SET; the
// interface is small enough to swap later without churning the handler.
type jtiCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newJTICache() *jtiCache { return &jtiCache{seen: map[string]time.Time{}} }

// acceptJTI records jti and returns true iff it's the first time we've
// seen it within the window. Returns false (replay) on a duplicate.
// Sweeps expired entries on every call — cheap, since the map is small
// (one entry per RP-side logout in the last 5 minutes).
func (c *jtiCache) acceptJTI(jti string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-backchannelLogoutJTIWindow)
	for k, t := range c.seen {
		if t.Before(cutoff) {
			delete(c.seen, k)
		}
	}
	if _, dup := c.seen[jti]; dup {
		return false
	}
	c.seen[jti] = now
	return true
}

// handleOIDCBackchannelLogout consumes OIDC Back-Channel Logout 1.0 tokens
// from the IdP and revokes the corresponding vault tokens.
//
// Per §2.5 the request is `application/x-www-form-urlencoded` with a single
// `logout_token` form field; the body carries no client credentials — the
// JWT signature is the authentication.
//
// Per §2.8 the response is `Cache-Control: no-store` and a 200 on success;
// errors are 4xx (no logout_token / invalid token / replay) or 5xx (only
// for unexpected internal failures). Failures do NOT cause the OP to retry,
// so the audit row is the only post-mortem signal.
func (s *Server) handleOIDCBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if s.oidc == nil {
		writeError(w, http.StatusBadRequest, "OIDC is not configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form body")
		return
	}
	raw := r.PostFormValue("logout_token")
	if raw == "" {
		writeError(w, http.StatusBadRequest, "logout_token required")
		return
	}

	claims, err := s.oidc.VerifyLogoutToken(r.Context(), raw)
	if err != nil {
		s.log.Warn("oidc backchannel logout: verify", "err", err)
		writeError(w, http.StatusBadRequest, "invalid logout_token")
		return
	}
	if !s.bcLogoutJTI.acceptJTI(claims.JTI, time.Now()) {
		s.log.Warn("oidc backchannel logout: replay", "jti", claims.JTI)
		writeError(w, http.StatusBadRequest, "logout_token replay")
		return
	}

	// Session-scoped (sid present) is the precise path: delete every vault
	// token chained to that OP session. Falls back to whole-user deletion
	// when only sub is supplied — broader but still correct.
	var (
		deleted int64
		scope   string
		email   string
	)
	if claims.SessionID != "" {
		n, dErr := s.store.DeleteTokensByOIDCSession(r.Context(), claims.SessionID)
		if dErr != nil {
			s.log.Error("oidc backchannel logout: delete by sid", "err", dErr)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		deleted = n
		scope = "session"
	} else {
		user, uErr := s.store.GetUserByOIDCSubject(r.Context(), claims.Issuer, claims.Subject)
		if errors.Is(uErr, store.ErrNotFound) {
			// We don't know this user — treat as success (idempotent) so the
			// OP doesn't keep retrying. Still audit-log so an operator can
			// spot persistent unknown-user notifications.
			s.log.Info("oidc backchannel logout: unknown user", "sub", claims.Subject)
		} else if uErr != nil {
			s.log.Error("oidc backchannel logout: lookup user", "err", uErr)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		} else {
			if dErr := s.store.DeleteAllTokensForUser(r.Context(), user.ID); dErr != nil {
				s.log.Error("oidc backchannel logout: delete by sub", "err", dErr)
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
			email = user.Email
		}
		scope = "user"
	}

	meta := `{"via":"backchannel","scope":"` + scope + `","jti":"` + claims.JTI + `"}`
	if err := s.logAuditEnv(r, ActionAuthOIDCBackchannelLogout, "", "", email,
		backchannelLogoutAuditMeta(scope, claims.JTI, deleted),
	); err != nil {
		// Audit fail-closed: tokens already deleted is fine, but we let the
		// OP know its notification didn't fully land so monitoring picks it up.
		s.log.Error("oidc backchannel logout: audit", "err", err)
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	_ = meta // currently unused; reserved for richer structured metadata

	w.WriteHeader(http.StatusOK)
}

// backchannelLogoutAuditMeta builds the audit metadata JSON for a single
// back-channel logout notification — captures the scope (sid vs. sub) and
// the deletion count so an operator skimming the journal can verify the
// effect of each OP notification.
func backchannelLogoutAuditMeta(scope, jti string, deleted int64) string {
	return `{"via":"backchannel","scope":"` + scope + `","jti":"` + jti + `","deleted":` + itoa(deleted) + `}`
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = digits[n%10]
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
