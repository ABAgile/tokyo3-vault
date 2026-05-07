// Package awskms is an AWS KMS implementation of bcrypto.KeyProvider.
//
// It wraps DEKs by calling KMS Encrypt/Decrypt against a configured key ID
// or ARN. AWS credentials are loaded from the standard SDK chain (env vars,
// IAM role, instance profile, etc.).
package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Provider implements bcrypto.KeyProvider against AWS KMS. Construct with
// New; pass to anything that accepts a bcrypto.KeyProvider.
type Provider struct {
	client *kms.Client
	keyID  string
}

// New returns a Provider that wraps DEKs with the given KMS key ID or ARN.
func New(ctx context.Context, keyID string) (*Provider, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &Provider{
		client: kms.NewFromConfig(cfg),
		keyID:  keyID,
	}, nil
}

func (p *Provider) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	out, err := p.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(p.keyID),
		Plaintext: dek,
	})
	if err != nil {
		return nil, fmt.Errorf("kms encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}

func (p *Provider) Unwrap(ctx context.Context, wrappedDEK []byte) ([]byte, error) {
	out, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(p.keyID),
		CiphertextBlob: wrappedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("kms decrypt: %w", err)
	}
	return out.Plaintext, nil
}
