// Package config manages CLI-side configuration:
//   - ~/.vault/config  — global: server URL + auth token
//   - .vault.toml      — per-repo: default project + environment
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Global holds the user-level config stored in ~/.vault/config.
type Global struct {
	ServerURL string `toml:"server_url"`
	Token     string `toml:"token"`
}

// Repo holds the per-repository config stored in .vault.toml.
type Repo struct {
	Project string `toml:"project"`
	Env     string `toml:"env"`
}

// GlobalPath returns the absolute path to ~/.vault/config.
func GlobalPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".vault", "config"), nil
}

// LoadGlobal reads ~/.vault/config. Returns zero-value Global if the file does not exist.
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

// MustToken returns auth config, preferring VAULT_TOKEN+VAULT_SERVER_URL env vars
// over ~/.vault/config. The env var path is intended for machine/CI contexts where
// the token is injected at runtime and must never be written to disk.
func MustToken() (Global, error) {
	if tok := os.Getenv("VAULT_TOKEN"); tok != "" {
		serverURL := os.Getenv("VAULT_SERVER_URL")
		if serverURL == "" {
			return Global{}, errors.New("VAULT_SERVER_URL is required when VAULT_TOKEN is set")
		}
		return Global{Token: tok, ServerURL: serverURL}, nil
	}
	g, err := LoadGlobal()
	if err != nil {
		return g, err
	}
	if g.Token == "" {
		return g, errors.New("not logged in — run: vault login")
	}
	if g.ServerURL == "" {
		return g, errors.New("server URL not set — run: vault login")
	}
	return g, nil
}
