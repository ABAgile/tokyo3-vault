// Package dynamic implements ephemeral credential issuance and revocation
// for dynamic backends.
package dynamic

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/abagile/tokyo3-vault/internal/model"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresIssuer implements Issuer for PostgreSQL backends.
// The backend's EncryptedConfig decrypts to a JSON object: {"dsn": "postgres://..."}.
type PostgresIssuer struct{}

func (p *PostgresIssuer) Issue(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend, role *model.DynamicRole, ttl time.Duration) (username, password string, expiresAt time.Time, err error) {
	dsn, err := decryptDSN(ctx, kp, backend)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("decrypt config: %w", err)
	}
	expiresAt = time.Now().UTC().Add(ttl)
	username = generateUsername()
	password = generatePassword()
	creationSQL := interpolate(role.CreationTmpl, username, password, expiresAt)
	if err := execOnTarget(ctx, dsn, creationSQL); err != nil {
		return "", "", time.Time{}, fmt.Errorf("execute creation template: %w", err)
	}
	return username, password, expiresAt, nil
}

func (p *PostgresIssuer) Revoke(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend, revocationTmpl, username string) error {
	dsn, err := decryptDSN(ctx, kp, backend)
	if err != nil {
		return fmt.Errorf("decrypt config: %w", err)
	}
	stmt := strings.ReplaceAll(revocationTmpl, "{{username}}", username)
	return execOnTarget(ctx, dsn, stmt)
}

// pgConfig is the JSON structure stored in EncryptedConfig for postgresql backends.
type pgConfig struct {
	DSN string `json:"dsn"`
}

func decryptDSN(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend) (string, error) {
	plaintext, err := crypto.DecryptSecret(ctx, kp, backend.EncryptedConfigDEK, backend.EncryptedConfig)
	if err != nil {
		return "", err
	}
	var cfg pgConfig
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		return "", fmt.Errorf("decode pg config: %w", err)
	}
	return cfg.DSN, nil
}

func execOnTarget(ctx context.Context, dsn, query string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open connection: %w", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, query); err != nil {
		return err
	}
	return nil
}

// interpolate replaces {{username}}, {{password}}, and {{expiry}} in the template.
func interpolate(tmpl, username, password string, expiresAt time.Time) string {
	return strings.NewReplacer(
		"{{username}}", username,
		"{{password}}", password,
		"{{expiry}}", expiresAt.Format("2006-01-02 15:04:05+00"),
	).Replace(tmpl)
}

func generateUsername() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "vault_" + hex.EncodeToString(b)
}

func generatePassword() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
