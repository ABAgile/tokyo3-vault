// Package auth handles password hashing, opaque token generation and validation.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// Default expiry durations applied when the caller does not specify one.
const (
	DefaultSessionTTL         = 15 * time.Minute     // human login sessions (sliding — reset on every request)
	DefaultSessionAbsoluteTTL = 4 * time.Hour        // hard ceiling from CreatedAt for IsSession tokens; no slide can extend past it
	DefaultMachineTokenTTL    = 90 * 24 * time.Hour  // machine / CI tokens
	DefaultCertPrincipalTTL   = 365 * 24 * time.Hour // cert principal mappings
)

// SessionEffectiveAnchor returns the timestamp from which the absolute
// session cap is measured for a session token. Prefers AuthTime (the
// human-authentication moment, carried across silent-SSO re-issuances), but
// falls back to CreatedAt when AuthTime is nil (pre-migration rows). Caller
// is responsible for fast-pathing on !tok.IsSession.
func SessionEffectiveAnchor(tok *model.Token) time.Time {
	if tok.AuthTime != nil {
		return *tok.AuthTime
	}
	return tok.CreatedAt
}

// SessionAbsoluteCapExceeded reports whether a session token has aged past
// the absolute lifetime cap, measured from the user's last interactive
// authentication moment (AuthTime, falling back to CreatedAt).
func SessionAbsoluteCapExceeded(tok *model.Token, now time.Time) bool {
	return now.Sub(SessionEffectiveAnchor(tok)) > DefaultSessionAbsoluteTTL
}

// CapSessionSlide returns min(deadline, anchor + DefaultSessionAbsoluteTTL),
// where anchor is the session's AuthTime (or CreatedAt as fallback). Used
// to clamp sliding-expiry extensions so no slide pushes past the session's
// absolute lifetime; re-auth at /auth/oidc/login mints a new row.
func CapSessionSlide(deadline time.Time, tok *model.Token) time.Time {
	cap := SessionEffectiveAnchor(tok).Add(DefaultSessionAbsoluteTTL)
	if deadline.After(cap) {
		return cap
	}
	return deadline
}

// HashPassword returns a bcrypt hash of the password.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword returns true if password matches the bcrypt hash.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// GenerateRawToken returns a cryptographically random 32-byte hex string.
func GenerateRawToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken returns the SHA-256 hex digest of a raw token string.
// Only the hash is stored in the database.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// IssueUserToken creates a session token for a human user. authTime is the
// moment of *interactive* authentication (password + MFA). For local-login
// flows pass time.Now(); for OIDC-bootstrapped sessions pass the IdP's
// auth_time claim so the absolute session cap follows the human
// authentication clock rather than the credential mint clock.
//
// Returns the raw token (sent to client once, never stored) and the DB record.
func IssueUserToken(ctx context.Context, st store.Store, userID, name string, authTime time.Time) (rawToken string, t *model.Token, err error) {
	rawToken, err = GenerateRawToken()
	if err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	now := time.Now().UTC()
	exp := now.Add(DefaultSessionTTL)
	at := authTime.UTC()
	t = &model.Token{
		ID:        uuid.NewString(),
		UserID:    &userID,
		TokenHash: HashToken(rawToken),
		Name:      name,
		IsSession: true,
		ExpiresAt: &exp,
		AuthTime:  &at,
		CreatedAt: now,
	}
	if err := st.CreateToken(ctx, t); err != nil {
		return "", nil, fmt.Errorf("store token: %w", err)
	}
	return rawToken, t, nil
}

// IssueMachineToken creates a scoped machine token (for CI / automation).
// projectID and envID may be empty strings to indicate no scope restriction.
// Set readOnly=true to prevent any write operations.
// expiresIn of 0 applies DefaultMachineTokenTTL.
func IssueMachineToken(ctx context.Context, st store.Store, userID, name, projectID, envID string, readOnly bool, expiresIn time.Duration) (rawToken string, t *model.Token, err error) {
	rawToken, err = GenerateRawToken()
	if err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	tok := &model.Token{
		ID:        uuid.NewString(),
		UserID:    &userID,
		TokenHash: HashToken(rawToken),
		Name:      name,
		ReadOnly:  readOnly,
		CreatedAt: time.Now().UTC(),
	}
	if projectID != "" {
		tok.ProjectID = &projectID
	}
	if envID != "" {
		tok.EnvID = &envID
	}
	if expiresIn == 0 {
		expiresIn = DefaultMachineTokenTTL
	}
	exp := time.Now().UTC().Add(expiresIn)
	tok.ExpiresAt = &exp
	if err := st.CreateToken(ctx, tok); err != nil {
		return "", nil, fmt.Errorf("store token: %w", err)
	}
	return rawToken, tok, nil
}

// Validate looks up a raw bearer token and returns the DB record.
// Returns store.ErrNotFound if the token does not exist.
func Validate(ctx context.Context, st store.Store, rawToken string) (*model.Token, error) {
	return st.GetTokenByHash(ctx, HashToken(rawToken))
}
