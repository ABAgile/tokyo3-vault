// Package oidc wraps go-oidc to handle the Authorization Code + PKCE flow.
package oidc

import (
	"context"
	"crypto/sha256"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Claims holds the identity fields extracted from an ID token.
type Claims struct {
	Issuer  string
	Subject string
	Email   string
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
		Email string `json:"email"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return nil, "", fmt.Errorf("extract claims: %w", err)
	}
	if raw.Email == "" {
		return nil, "", fmt.Errorf("id_token missing email claim — ensure the IdP includes email in the token")
	}

	return &Claims{
		Issuer:  idToken.Issuer,
		Subject: idToken.Subject,
		Email:   raw.Email,
	}, cliCallback, nil
}
