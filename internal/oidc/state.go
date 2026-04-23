package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type statePayload struct {
	CodeVerifier string `json:"cv"`
	Nonce        string `json:"n"`
	CLICallback  string `json:"cb,omitempty"`
	Exp          int64  `json:"exp"`
}

// newStateToken signs a state payload using HMAC-SHA256.
// The resulting token is safe to pass as the OAuth2 state parameter.
func newStateToken(key []byte, cv, nonce, cliCallback string) (string, error) {
	p := statePayload{
		CodeVerifier: cv,
		Nonce:        nonce,
		CLICallback:  cliCallback,
		Exp:          time.Now().Add(10 * time.Minute).Unix(),
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, nil
}

// verifyStateToken validates the HMAC and expiry, then returns the payload fields.
func verifyStateToken(key []byte, token string) (cv, nonce, cliCallback string, err error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", "", "", errors.New("malformed state token")
	}
	payload, sig := parts[0], parts[1]

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", "", "", errors.New("invalid state token signature")
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", "", "", fmt.Errorf("decode state payload: %w", err)
	}
	var p statePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", "", "", fmt.Errorf("unmarshal state payload: %w", err)
	}
	if time.Now().Unix() > p.Exp {
		return "", "", "", errors.New("state token expired")
	}
	return p.CodeVerifier, p.Nonce, p.CLICallback, nil
}

// randomBase64URL returns n random bytes encoded as base64url without padding.
func randomBase64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// s256Challenge computes the PKCE S256 code_challenge from a code_verifier.
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
