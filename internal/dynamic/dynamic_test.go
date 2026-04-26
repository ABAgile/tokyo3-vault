package dynamic

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/testutil/mockstore"
)

func TestGet_KnownType(t *testing.T) {
	issuer, err := Get("postgresql")
	if err != nil {
		t.Fatalf("Get postgresql: %v", err)
	}
	if issuer == nil {
		t.Fatal("expected non-nil issuer for postgresql")
	}
}

func TestGet_UnknownType(t *testing.T) {
	_, err := Get("mysql")
	if err == nil {
		t.Error("expected error for unknown backend type")
	}
}

func TestKnownTypes(t *testing.T) {
	types := KnownTypes()
	if len(types) == 0 {
		t.Fatal("expected at least one known type")
	}
	found := false
	for _, ty := range types {
		if ty == "postgresql" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected postgresql in KnownTypes, got %v", types)
	}
}

func TestEffectiveTTL(t *testing.T) {
	ttl1800, ttl900 := 1800, 900
	tests := []struct {
		name     string
		defTTL   int
		maxTTL   int
		roleTTL  *int
		override int
		want     time.Duration
	}{
		{
			name:   "backend default, no role TTL, no override",
			defTTL: 3600, maxTTL: 7200,
			roleTTL: nil, override: 0,
			want: 3600 * time.Second,
		},
		{
			name:   "role TTL overrides backend default",
			defTTL: 3600, maxTTL: 7200,
			roleTTL: &ttl1800, override: 0,
			want: 1800 * time.Second,
		},
		{
			name:   "ttlOverride beats role TTL",
			defTTL: 3600, maxTTL: 7200,
			roleTTL: &ttl1800, override: ttl900,
			want: 900 * time.Second,
		},
		{
			name:   "capped at MaxTTL",
			defTTL: 3600, maxTTL: 600,
			roleTTL: nil, override: 0,
			want: 600 * time.Second,
		},
		{
			name:   "override capped at MaxTTL",
			defTTL: 3600, maxTTL: 1200,
			roleTTL: nil, override: 9999,
			want: 1200 * time.Second,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := &model.DynamicBackend{DefaultTTL: tc.defTTL, MaxTTL: tc.maxTTL}
			role := &model.DynamicRole{TTL: tc.roleTTL}
			got := EffectiveTTL(backend, role, tc.override)
			if got != tc.want {
				t.Errorf("EffectiveTTL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInterpolate(t *testing.T) {
	exp := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	tmpl := "CREATE ROLE {{username}} WITH PASSWORD '{{password}}' VALID UNTIL '{{expiry}}';"
	result := interpolate(tmpl, "vault_user", "s3cr3t", exp)

	if !strings.Contains(result, "vault_user") {
		t.Errorf("username not in result: %s", result)
	}
	if !strings.Contains(result, "s3cr3t") {
		t.Errorf("password not in result: %s", result)
	}
	if !strings.Contains(result, "2026-01-15") {
		t.Errorf("expiry not in result: %s", result)
	}
	if strings.Contains(result, "{{") {
		t.Errorf("unresolved placeholder in result: %s", result)
	}
}

func TestGenerateUsername(t *testing.T) {
	u := generateUsername()
	if !strings.HasPrefix(u, "vault_") {
		t.Errorf("username %q does not start with vault_", u)
	}
	// "vault_" (6 chars) + hex(8 bytes) = 6+16 = 22
	if len(u) != 22 {
		t.Errorf("username length = %d, want 22", len(u))
	}
	if u == generateUsername() {
		t.Error("generated identical usernames — likely not random")
	}
}

func TestGeneratePassword(t *testing.T) {
	p := generatePassword()
	if len(p) != 48 { // hex(24 bytes) = 48 chars
		t.Errorf("password length = %d, want 48", len(p))
	}
	if p == generatePassword() {
		t.Error("generated identical passwords — likely not random")
	}
}

func TestNewRevoker(t *testing.T) {
	st := &mockstore.Stub{}
	kp := crypto.NewLocalKeyProvider(make([]byte, 32))
	projectKP := crypto.NewProjectKeyCache(kp, time.Minute)

	r := NewRevoker(st, kp, projectKP, slog.Default())
	if r == nil {
		t.Fatal("NewRevoker returned nil")
	}
}

func TestRevoker_Run_CancelImmediately(t *testing.T) {
	st := &mockstore.Stub{}
	kp := crypto.NewLocalKeyProvider(make([]byte, 32))
	projectKP := crypto.NewProjectKeyCache(kp, time.Minute)

	r := NewRevoker(st, kp, projectKP, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Revoker.Run did not exit after context cancellation")
	}
}
