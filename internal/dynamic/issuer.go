package dynamic

import (
	"context"
	"fmt"
	"time"

	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
)

// Issuer handles credential issuance and revocation for one backend type.
type Issuer interface {
	Issue(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend, role *model.DynamicRole, ttl time.Duration) (username, password string, expiresAt time.Time, err error)
	Revoke(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend, revocationTmpl, username string) error
}

var registry = map[string]Issuer{
	"postgresql": &PostgresIssuer{},
}

// Get returns the Issuer for the given backend type.
func Get(backendType string) (Issuer, error) {
	i, ok := registry[backendType]
	if !ok {
		return nil, fmt.Errorf("unknown backend type %q", backendType)
	}
	return i, nil
}

// KnownTypes returns all registered backend type names.
func KnownTypes() []string {
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	return out
}
