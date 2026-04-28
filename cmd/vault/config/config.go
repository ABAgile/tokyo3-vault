// Package config manages CLI-side configuration:
//   - ~/.vault/config  — global: server URL + auth token
//   - .vault.toml      — per-repo: default project + environment
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Global holds the user-level config stored in ~/.vault/config.
type Global struct {
	ServerURL      string `toml:"server_url"`
	Token          string `toml:"token"`
	TLSSkipVerify  bool   `toml:"tls_skip_verify"`
	CACertPath     string `toml:"ca_cert_path"`     // path to CA PEM; read fresh on every use
	ClientCertPath string `toml:"client_cert_path"` // path to client cert PEM for principal auth
	ClientKeyPath  string `toml:"client_key_path"`  // path to client key PEM for principal auth

	caCert     []byte           // loaded from CACertPath at runtime; never serialised
	clientCert *tls.Certificate // loaded from ClientCertPath+ClientKeyPath; never serialised
}

// CACertPEM returns the CA certificate PEM loaded from CACertPath.
func (g Global) CACertPEM() []byte { return g.caCert }

// ClientCert returns the TLS client certificate loaded from ClientCertPath/ClientKeyPath.
func (g Global) ClientCert() *tls.Certificate { return g.clientCert }

// DynamicRun declares a dynamic backend credential to issue during vault run.
// Slug is the backend slug; Role is the role name. TTL overrides the role default (0 = use default).
type DynamicRun struct {
	Slug string `toml:"slug"`
	Role string `toml:"role"`
	TTL  int    `toml:"ttl"`
}

// Repo holds the per-repository config stored in .vault.toml.
type Repo struct {
	Project string       `toml:"project"`
	Env     string       `toml:"env"`
	Dynamic []DynamicRun `toml:"dynamic"`
}

// GlobalPath returns the absolute path to ~/.vault/config.
func GlobalPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".vault", "config"), nil
}

// loadCACert reads a PEM file from path and returns its contents.
func loadCACert(path string) ([]byte, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca cert %s: %w", path, err)
	}
	return pem, nil
}

// LoadGlobal reads ~/.vault/config. Returns zero-value Global if the file does not exist.
// If CACertPath is set, the certificate is read from disk so callers always get a fresh copy.
func LoadGlobal() (Global, error) {
	path, err := GlobalPath()
	if err != nil {
		return Global{}, err
	}
	var cfg Global
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Global{}, nil
		}
		return Global{}, fmt.Errorf("read %s: %w", path, err)
	}
	if cfg.CACertPath != "" {
		cfg.caCert, err = loadCACert(cfg.CACertPath)
		if err != nil {
			return Global{}, err
		}
	}
	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return Global{}, fmt.Errorf("load client cert: %w", err)
		}
		cfg.clientCert = &cert
	}
	return cfg, nil
}

// SaveGlobal writes g to ~/.vault/config, creating the directory if needed.
func SaveGlobal(g Global) error {
	path, err := GlobalPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(g)
}

// LoadRepo walks up from the current directory looking for .vault.toml.
// Returns zero-value Repo if not found.
func LoadRepo() (Repo, error) {
	dir, err := os.Getwd()
	if err != nil {
		return Repo{}, err
	}
	for {
		candidate := filepath.Join(dir, ".vault.toml")
		var r Repo
		if _, err := toml.DecodeFile(candidate, &r); err == nil {
			return r, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return Repo{}, nil
}

// LoadRepoLocal reads .vault.toml from the current directory only — it does NOT
// walk up to parent directories. Returns (Repo, true) if found, (Repo{}, false) otherwise.
// Use this in delete/cleanup paths where you only want to act on the immediate link.
func LoadRepoLocal() (Repo, bool) {
	var r Repo
	if _, err := toml.DecodeFile(".vault.toml", &r); err != nil {
		return Repo{}, false
	}
	return r, true
}

// RemoveRepo deletes .vault.toml from the current directory.
// Returns nil if the file does not exist.
func RemoveRepo() error {
	err := os.Remove(".vault.toml")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// SaveRepo writes r to .vault.toml in the current directory.
func SaveRepo(r Repo) error {
	f, err := os.OpenFile(".vault.toml", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(r)
}

// MustToken returns auth config, preferring env vars over ~/.vault/config.
//
// Env vars for machine/CI contexts (never written to disk):
//   - VAULT_TOKEN + VAULT_SERVER_URL  — bearer token auth
//   - VAULT_CLIENT_CERT + VAULT_CLIENT_KEY + VAULT_SERVER_URL — principal cert auth
//   - VAULT_CA_CERT — path to CA PEM for server verification (optional in both modes)
func MustToken() (Global, error) {
	serverURL := os.Getenv("VAULT_SERVER_URL")
	tok := os.Getenv("VAULT_TOKEN")
	certFile := os.Getenv("VAULT_CLIENT_CERT")
	keyFile := os.Getenv("VAULT_CLIENT_KEY")

	if tok != "" || certFile != "" {
		if serverURL == "" {
			return Global{}, errors.New("VAULT_SERVER_URL is required")
		}
		g := Global{Token: tok, ServerURL: serverURL}
		if caFile := os.Getenv("VAULT_CA_CERT"); caFile != "" {
			pem, err := loadCACert(caFile)
			if err != nil {
				return Global{}, fmt.Errorf("VAULT_CA_CERT: %w", err)
			}
			g.CACertPath = caFile
			g.caCert = pem
		}
		if certFile != "" && keyFile != "" {
			g.ClientCertPath = certFile
			g.ClientKeyPath = keyFile
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return Global{}, fmt.Errorf("load VAULT_CLIENT_CERT: %w", err)
			}
			g.clientCert = &cert
		}
		return g, nil
	}

	g, err := LoadGlobal()
	if err != nil {
		return g, err
	}
	if g.ServerURL == "" {
		return g, errors.New("server URL not set — run: vault login")
	}
	if g.Token == "" && g.ClientCertPath == "" {
		return g, errors.New("not logged in — run: vault login")
	}
	return g, nil
}
