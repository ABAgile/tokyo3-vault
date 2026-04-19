package config

import (
	"os"
	"testing"
)

func TestMustTokenEnvVar(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "tok_test")
	t.Setenv("VAULT_SERVER_URL", "https://vault.example.com")

	g, err := MustToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Token != "tok_test" {
		t.Errorf("token = %q, want %q", g.Token, "tok_test")
	}
	if g.ServerURL != "https://vault.example.com" {
		t.Errorf("server_url = %q, want %q", g.ServerURL, "https://vault.example.com")
	}
}

func TestMustTokenEnvVarMissingServerURL(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "tok_test")
	os.Unsetenv("VAULT_SERVER_URL")

	_, err := MustToken()
	if err == nil {
		t.Fatal("expected error when VAULT_SERVER_URL is missing, got nil")
	}
}

func TestMustTokenEnvVarTakesPrecedenceOverFile(t *testing.T) {
	// Write a config file with a different token.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := os.MkdirAll(dir+"/.vault", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/.vault/config", []byte("server_url = \"https://other.example.com\"\ntoken = \"tok_from_file\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("VAULT_TOKEN", "tok_from_env")
	t.Setenv("VAULT_SERVER_URL", "https://vault.example.com")

	g, err := MustToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Token != "tok_from_env" {
		t.Errorf("token = %q, want env var value %q", g.Token, "tok_from_env")
	}
}

func TestMustTokenFallsBackToFile(t *testing.T) {
	os.Unsetenv("VAULT_TOKEN")
	os.Unsetenv("VAULT_SERVER_URL")

	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := os.MkdirAll(dir+"/.vault", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/.vault/config", []byte("server_url = \"https://vault.example.com\"\ntoken = \"tok_file\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	g, err := MustToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Token != "tok_file" {
		t.Errorf("token = %q, want %q", g.Token, "tok_file")
	}
}
