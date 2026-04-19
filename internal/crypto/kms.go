package crypto

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// KMSKeyProvider implements KeyProvider using AWS KMS Encrypt/Decrypt to wrap DEKs.
// Use this in production via VAULT_KMS_KEY_ID.
// AWS credentials are loaded from the standard chain (env vars, IAM role, etc.).
type KMSKeyProvider struct {
	client *kms.Client
	keyID  string
}

// NewKMSKeyProvider creates a KMSKeyProvider that wraps DEKs with the given KMS key ID or ARN.
func NewKMSKeyProvider(ctx context.Context, keyID string) (*KMSKeyProvider, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &KMSKeyProvider{
		client: kms.NewFromConfig(cfg),
		keyID:  keyID,
	}, nil
}

func (p *KMSKeyProvider) WrapDEK(ctx context.Context, dek []byte) ([]byte, error) {
	out, err := p.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(p.keyID),
		Plaintext: dek,
	})
	if err != nil {
		return nil, fmt.Errorf("kms encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}

func (p *KMSKeyProvider) UnwrapDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	out, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(p.keyID),
		CiphertextBlob: encryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("kms decrypt: %w", err)
	}
	return out.Plaintext, nil
}
