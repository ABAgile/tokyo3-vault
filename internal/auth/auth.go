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

// generateRawToken is the unexported alias for internal use.
func generateRawToken() (string, error) { return GenerateRawToken() }

// HashToken returns the SHA-256 hex digest of a raw token string.
// Only the hash is stored in the database.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// IssueUserToken creates a session token for a human user.
// Returns the raw token (sent to client once, never stored) and the DB record.
func IssueUserToken(ctx context.Context, st store.Store, userID, name string) (rawToken string, t *model.Token, err error) {
	rawToken, err = generateRawToken()
	if err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	t = &model.Token{
		ID:        uuid.NewString(),
		UserID:    &userID,
		TokenHash: HashToken(rawToken),
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
	if err := st.CreateToken(ctx, t); err != nil {
		return "", nil, fmt.Errorf("store token: %w", err)
	}
	return rawToken, t, nil
}

// IssueMachineToken creates a scoped machine token (for CI / automation).
// projectID and envID may be empty strings to indicate no scope restriction.
// Set readOnly=true to prevent any write operations.
// expiresIn of 0 means no expiry.
func IssueMachineToken(ctx context.Context, st store.Store, userID, name, projectID, envID string, readOnly bool, expiresIn time.Duration) (rawToken string, t *model.Token, err error) {
	rawToken, err = generateRawToken()
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
	if expiresIn > 0 {
		exp := time.Now().UTC().Add(expiresIn)
		tok.ExpiresAt = &exp
	}
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
