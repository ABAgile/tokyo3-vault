package config

import (
	"os"
	"path/filepath"
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

func TestGlobalPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	p, err := GlobalPath()
	if err != nil {
		t.Fatalf("GlobalPath: %v", err)
	}
	want := filepath.Join(dir, ".vault", "config")
	if p != want {
		t.Errorf("GlobalPath = %q, want %q", p, want)
	}
}

func TestLoadGlobal_FileNotExist(t *testing.T) {
	os.Unsetenv("VAULT_TOKEN")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	g, err := LoadGlobal()
	if err != nil {
		t.Fatalf("LoadGlobal missing file: %v", err)
	}
	if g.Token != "" || g.ServerURL != "" {
		t.Errorf("expected zero Global, got %+v", g)
	}
}

func TestSaveGlobal_LoadGlobal_RoundTrip(t *testing.T) {
	os.Unsetenv("VAULT_TOKEN")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	want := Global{ServerURL: "https://vault.example.com", Token: "tok-abc123"}
	if err := SaveGlobal(want); err != nil {
		t.Fatalf("SaveGlobal: %v", err)
	}

	got, err := LoadGlobal()
	if err != nil {
		t.Fatalf("LoadGlobal: %v", err)
	}
	if got != want {
		t.Errorf("LoadGlobal = %+v, want %+v", got, want)
	}
}

func TestMustToken_NoTokenInFile(t *testing.T) {
	os.Unsetenv("VAULT_TOKEN")
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// No .vault/config file — LoadGlobal returns zero value, MustToken must error.
	_, err := MustToken()
	if err == nil {
		t.Fatal("expected error when no token configured")
	}
}

func TestMustToken_TokenButNoServerURL(t *testing.T) {
	os.Unsetenv("VAULT_TOKEN")
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, ".vault"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".vault", "config"), []byte("token = \"tok\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := MustToken()
	if err == nil {
		t.Fatal("expected error when server_url is missing from file")
	}
}

func TestSaveRepo_LoadRepoLocal_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	want := Repo{Project: "myapp", Env: "production", Dynamic: []DynamicRun{{Slug: "pg", Role: "readonly"}}}
	if err := SaveRepo(want); err != nil {
		t.Fatalf("SaveRepo: %v", err)
	}

	got, ok := LoadRepoLocal()
	if !ok {
		t.Fatal("LoadRepoLocal: expected file to be found")
	}
	if got.Project != want.Project || got.Env != want.Env {
		t.Errorf("LoadRepoLocal = %+v, want %+v", got, want)
	}
	if len(got.Dynamic) != 1 || got.Dynamic[0].Slug != "pg" {
		t.Errorf("LoadRepoLocal Dynamic = %+v", got.Dynamic)
	}
}

func TestLoadRepoLocal_NotFound(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	_, ok := LoadRepoLocal()
	if ok {
		t.Error("expected LoadRepoLocal to return false when file absent")
	}
}

func TestRemoveRepo_NotFound(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	if err := RemoveRepo(); err != nil {
		t.Errorf("RemoveRepo on absent file: %v", err)
	}
}

func TestRemoveRepo_Exists(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	if err := SaveRepo(Repo{Project: "x", Env: "dev"}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRepo(); err != nil {
		t.Fatalf("RemoveRepo: %v", err)
	}
	if _, err := os.Stat(".vault.toml"); !os.IsNotExist(err) {
		t.Error("expected .vault.toml to be removed")
	}
}

func TestLoadRepo_WalkUp(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub", "project")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}

	// Write .vault.toml in parent dir.
	if err := os.WriteFile(filepath.Join(dir, ".vault.toml"), []byte("project = \"parentapp\"\nenv = \"staging\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(sub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	r, err := LoadRepo()
	if err != nil {
		t.Fatalf("LoadRepo: %v", err)
	}
	if r.Project != "parentapp" {
		t.Errorf("LoadRepo.Project = %q, want %q", r.Project, "parentapp")
	}
}

func TestLoadRepo_NotFound(t *testing.T) {
	// Use a temp dir that has no .vault.toml anywhere in its tree.
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	r, err := LoadRepo()
	if err != nil {
		t.Fatalf("LoadRepo: %v", err)
	}
	if r.Project != "" || r.Env != "" {
		t.Errorf("expected zero Repo, got %+v", r)
	}
}
