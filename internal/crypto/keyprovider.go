package crypto

import "context"

// KeyProvider wraps and unwraps Data Encryption Keys (DEKs).
// LocalKeyProvider uses an in-memory AES-256 master key (dev).
// KMSKeyProvider delegates to AWS KMS (production).
type KeyProvider interface {
	WrapDEK(ctx context.Context, dek []byte) ([]byte, error)
	UnwrapDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error)
}

// LocalKeyProvider implements KeyProvider with an in-memory AES-256 KEK.
// Use this in development via VAULT_MASTER_KEY.
type LocalKeyProvider struct {
	kek []byte
}

// NewLocalKeyProvider returns a LocalKeyProvider backed by the given 32-byte KEK.
func NewLocalKeyProvider(kek []byte) *LocalKeyProvider {
	return &LocalKeyProvider{kek: kek}
}

func (p *LocalKeyProvider) WrapDEK(_ context.Context, dek []byte) ([]byte, error) {
	return seal(p.kek, dek)
}

func (p *LocalKeyProvider) UnwrapDEK(_ context.Context, encryptedDEK []byte) ([]byte, error) {
	return open(p.kek, encryptedDEK)
}
