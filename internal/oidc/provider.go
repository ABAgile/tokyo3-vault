// Package oidc wraps go-oidc to handle the Authorization Code + PKCE flow.
package oidc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	boidc "github.com/abagile/tokyo3-base/oidc"
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

// Provider manages the OIDC Authorization Code + PKCE flow. Token verification
// (ID tokens and back-channel logout_tokens) is delegated to base/oidc; this
// type owns only the vault-specific orchestration — the stateless HMAC state
// token, PKCE, and the code exchange.
type Provider struct {
	verifier *boidc.HTTPVerifier
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
	// The verifier performs OIDC discovery; its Endpoint() gives us the
	// authorization/token URLs for the code exchange — one discovery, shared.
	ver, err := boidc.NewHTTPVerifier(ctx, cfg.Issuer, cfg.ClientID)
	if err != nil {
		return nil, fmt.Errorf("oidc discover %s: %w", cfg.Issuer, err)
	}
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     ver.Endpoint(),
		Scopes:       []string{"openid", "email", "profile"},
	}
	key := sha256.Sum256([]byte(cfg.ClientSecret))
	return &Provider{
		verifier: ver,
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
	verified, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("verify id_token: %w", err)
	}
	if verified.Nonce != nonce {
		return nil, "", fmt.Errorf("nonce mismatch")
	}
	if verified.Email == "" {
		return nil, "", fmt.Errorf("id_token missing email claim — ensure the IdP includes email in the token")
	}

	return &Claims{
		Issuer:    verified.Issuer,
		Subject:   verified.Subject,
		Email:     verified.Email,
		AuthTime:  verified.AuthTime,
		SessionID: verified.SessionID,
	}, cliCallback, nil
}

// VerifyLogoutToken validates an OIDC Back-Channel Logout 1.0 logout_token via
// the shared base verifier (§2.6: signature + the backchannel-logout event,
// no nonce, at least one of sub/sid, jti present). The returned
// [boidc.LogoutClaims] exposes JTI so the caller can apply replay protection
// (vault does so via its jtiCache).
func (p *Provider) VerifyLogoutToken(ctx context.Context, raw string) (*boidc.LogoutClaims, error) {
	return p.verifier.VerifyLogoutToken(ctx, raw)
}
