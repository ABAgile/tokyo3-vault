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
	"github.com/abagile/tokyo3-vault/internal/tlsutil"
	"github.com/jackc/pgx/v5"
	pgxstdlib "github.com/jackc/pgx/v5/stdlib"
)

// PostgresIssuer implements Issuer for PostgreSQL backends.
// The backend's EncryptedConfig decrypts to a JSON object: {"dsn": "postgres://..."}.
type PostgresIssuer struct{}

func (p *PostgresIssuer) Issue(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend, role *model.DynamicRole, ttl time.Duration) (username, password string, expiresAt time.Time, err error) {
	cfg, err := decryptConfig(ctx, kp, backend)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("decrypt config: %w", err)
	}
	expiresAt = time.Now().UTC().Add(ttl)
	username = generateUsername()
	password = generatePassword()
	creationSQL := interpolate(role.CreationTmpl, username, password, expiresAt)
	if err := execOnTarget(ctx, cfg, creationSQL); err != nil {
		return "", "", time.Time{}, fmt.Errorf("execute creation template: %w", err)
	}
	return username, password, expiresAt, nil
}

func (p *PostgresIssuer) Revoke(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend, revocationTmpl, username string) error {
	cfg, err := decryptConfig(ctx, kp, backend)
	if err != nil {
		return fmt.Errorf("decrypt config: %w", err)
	}
	stmt := strings.ReplaceAll(revocationTmpl, "{{username}}", username)
	return execOnTarget(ctx, cfg, stmt)
}

// pgConfig is the JSON structure stored in EncryptedConfig for postgresql backends.
// ClientCert, ClientKey, and CACert are optional PEM-encoded strings for client
// certificate authentication (e.g. Teleport-issued or manually provisioned certs).
type pgConfig struct {
	DSN        string `json:"dsn"`
	ClientCert string `json:"client_cert,omitempty"` // PEM-encoded client certificate
	ClientKey  string `json:"client_key,omitempty"`  // PEM-encoded client private key
	CACert     string `json:"ca_cert,omitempty"`     // PEM-encoded CA for server verification
}

func decryptConfig(ctx context.Context, kp crypto.KeyProvider, backend *model.DynamicBackend) (pgConfig, error) {
	plaintext, err := crypto.DecryptSecret(ctx, kp, backend.EncryptedConfigDEK, backend.EncryptedConfig)
	if err != nil {
		return pgConfig{}, err
	}
	var cfg pgConfig
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		return pgConfig{}, fmt.Errorf("decode pg config: %w", err)
	}
	return cfg, nil
}

func execOnTarget(ctx context.Context, cfg pgConfig, query string) error {
	var db *sql.DB
	if cfg.ClientCert != "" {
		tlsCfg, err := tlsutil.FromPEM(cfg.ClientCert, cfg.ClientKey, cfg.CACert)
		if err != nil {
			return fmt.Errorf("build tls config: %w", err)
		}
		connCfg, err := pgx.ParseConfig(cfg.DSN)
		if err != nil {
			return fmt.Errorf("parse dsn: %w", err)
		}
		connCfg.TLSConfig = tlsCfg
		db = pgxstdlib.OpenDB(*connCfg)
	} else {
		var err error
		db, err = sql.Open("pgx", cfg.DSN)
		if err != nil {
			return fmt.Errorf("open connection: %w", err)
		}
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
