// Package oidc wraps go-oidc to handle the Authorization Code + PKCE flow.
package oidc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Claims holds the identity fields extracted from an ID token.
//
// AuthTime is the IdP's `auth_time` claim — the moment the user actually
// authenticated at the OP (password+MFA), distinct from when the ID token
// itself was minted. Zero value when the IdP omitted the claim; callers
// fall back to time.Now() in that case.
//
// SessionID is the IdP's `sid` claim — a stable identifier for the OP-side
// session, persisted on each vault token at mint time so a future OIDC
// Back-Channel Logout 1.0 POST from the IdP can target exactly the vault
// tokens minted under that OP session. Empty when the IdP doesn't emit
// `sid` (back-channel logout would then fall back to sub-based deletion).
type Claims struct {
	Issuer    string
	Subject   string
	Email     string
	AuthTime  time.Time
	SessionID string
}

// Provider manages the OIDC Authorization Code + PKCE flow.
type Provider struct {
	verifier *gooidc.IDTokenVerifier
	oauthCfg oauth2.Config
	stateKey []byte // HMAC-SHA256 key derived from client secret
}

// Config holds the OIDC integration settings from env vars.
type Config struct {
	Issuer       string // e.g. https://authentik.example.com/application/o/vault/
	ClientID     string
	ClientSecret string
	RedirectURL  string // VAULT_OIDC_REDIRECT_URI — must match what the IdP expects
}

// New creates a Provider by fetching the IdP's OIDC discovery document.
// Returns an error if the issuer is unreachable or the document is invalid.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	p, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discover %s: %w", cfg.Issuer, err)
	}
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     p.Endpoint(),
		Scopes:       []string{gooidc.ScopeOpenID, "email", "profile"},
	}
	key := sha256.Sum256([]byte(cfg.ClientSecret))
	return &Provider{
		verifier: p.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		oauthCfg: oauthCfg,
		stateKey: key[:],
	}, nil
}

// BeginAuth starts the authorization code flow.
//
// cliCallback, if non-empty, is stored in the state token and returned after
// callback completion so the handler can redirect the browser to the CLI's
// local HTTP server.
//
// Returns the IdP authorization URL to redirect/open in a browser, plus the
// opaque state token that must be passed back to CompleteAuth.
func (p *Provider) BeginAuth(cliCallback string) (authURL, stateToken string, err error) {
	cv, err := randomBase64URL(32)
	if err != nil {
		return "", "", fmt.Errorf("generate code verifier: %w", err)
	}
	nonce, err := randomBase64URL(16)
	if err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}
	stateToken, err = newStateToken(p.stateKey, cv, nonce, cliCallback)
	if err != nil {
		return "", "", fmt.Errorf("sign state: %w", err)
	}
	authURL = p.oauthCfg.AuthCodeURL(
		stateToken,
		oauth2.SetAuthURLParam("code_challenge", s256Challenge(cv)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	return authURL, stateToken, nil
}

// CompleteAuth finishes the authorization code exchange.
//
// It verifies the state token HMAC and expiry, exchanges the code for tokens
// using PKCE, then verifies the ID token's signature and nonce.
//
// Returns the verified identity claims and the cliCallback that was embedded
// in the state during BeginAuth (empty string if the flow was browser-only).
func (p *Provider) CompleteAuth(ctx context.Context, code, state string) (claims *Claims, cliCallback string, err error) {
	cv, nonce, cliCallback, err := verifyStateToken(p.stateKey, state)
	if err != nil {
		return nil, "", fmt.Errorf("verify state: %w", err)
	}

	tok, err := p.oauthCfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", cv),
	)
	if err != nil {
		return nil, "", fmt.Errorf("exchange code: %w", err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, "", fmt.Errorf("no id_token in token response")
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != nonce {
		return nil, "", fmt.Errorf("nonce mismatch")
	}

	var raw struct {
		Email    string `json:"email"`
		AuthTime int64  `json:"auth_time"`
		SID      string `json:"sid"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return nil, "", fmt.Errorf("extract claims: %w", err)
	}
	if raw.Email == "" {
		return nil, "", fmt.Errorf("id_token missing email claim — ensure the IdP includes email in the token")
	}
	var authTime time.Time
	if raw.AuthTime > 0 {
		authTime = time.Unix(raw.AuthTime, 0).UTC()
	}

	return &Claims{
		Issuer:    idToken.Issuer,
		Subject:   idToken.Subject,
		Email:     raw.Email,
		AuthTime:  authTime,
		SessionID: raw.SID,
	}, cliCallback, nil
}

// LogoutClaims is the verified subset of an OIDC Back-Channel Logout 1.0
// logout_token (§2.4). Subject and/or SessionID will be non-empty after a
// successful Verify — the spec guarantees at least one of them is present.
// JTI is exposed so callers can implement replay protection across their
// own replica set / process boundaries.
type LogoutClaims struct {
	Issuer    string
	Subject   string
	SessionID string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// VerifyLogoutToken validates an OIDC Back-Channel Logout 1.0 logout_token
// per §2.6 — signature + standard claims via the same JWKS-backed verifier
// used for ID tokens, plus the back-channel-specific rules:
//
//   - `events` MUST contain the back-channel-logout event URI as a member
//     whose value is the empty object.
//   - `nonce` MUST NOT be present (defense against ID-token replay).
//   - At least one of `sub` and `sid` MUST be present.
//
// JTI replay protection is the caller's responsibility (typically a small
// time-bounded cache keyed on JTI).
func (p *Provider) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutClaims, error) {
	tok, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify logout token: %w", err)
	}
	var body struct {
		SID    string                    `json:"sid"`
		Nonce  string                    `json:"nonce"`
		JTI    string                    `json:"jti"`
		IAT    int64                     `json:"iat"`
		Exp    int64                     `json:"exp"`
		Events map[string]map[string]any `json:"events"`
	}
	if err := tok.Claims(&body); err != nil {
		return nil, fmt.Errorf("decode logout claims: %w", err)
	}
	if body.Nonce != "" {
		return nil, fmt.Errorf("logout_token has nonce claim (forbidden by spec §2.6)")
	}
	if _, ok := body.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return nil, fmt.Errorf("logout_token missing backchannel-logout event")
	}
	if tok.Subject == "" && body.SID == "" {
		return nil, fmt.Errorf("logout_token missing both sub and sid claims")
	}
	if body.JTI == "" {
		return nil, fmt.Errorf("logout_token missing jti")
	}
	return &LogoutClaims{
		Issuer:    tok.Issuer,
		Subject:   tok.Subject,
		SessionID: body.SID,
		JTI:       body.JTI,
		IssuedAt:  time.Unix(body.IAT, 0).UTC(),
		ExpiresAt: time.Unix(body.Exp, 0).UTC(),
	}, nil
}
