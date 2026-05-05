// Package crypto provides AES-256-GCM encryption using a DEK+KEK model.
//
// Each secret version gets its own random Data Encryption Key (DEK).
// The DEK is wrapped (encrypted) by the master Key Encryption Key (KEK).
// This means rotating the KEK only requires re-wrapping DEKs, never
// re-encrypting secret values themselves.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// RandomBytes returns n cryptographically random bytes from crypto/rand.
// Used to mint KEKs, DEKs, and AES-GCM nonces — all of which require
// uniformly random material.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ParseKEK decodes a 64-hex-character string into a 32-byte key.
// The KEK is typically loaded from the VAULT_MASTER_KEY environment variable.
func ParseKEK(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid master key encoding: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	return b, nil
}

// GenerateKEK returns a random 32-byte key encoded as a 64-char hex string,
// suitable for use as VAULT_MASTER_KEY.
func GenerateKEK() (string, error) {
	b, err := RandomBytes(32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Seal encrypts plaintext with key using AES-256-GCM.
// Output format: nonce || ciphertext+tag (nonce is prepended).
func Seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	nonce, err := RandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts ciphertext (nonce || ciphertext+tag) with key.
func Open(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// EncryptSecret encrypts plaintext under a fresh random DEK, then wraps the DEK
// using kp. Returns (encryptedValue, encryptedDEK, error).
func EncryptSecret(ctx context.Context, kp KeyProvider, plaintext []byte) (encryptedValue, encryptedDEK []byte, err error) {
	dek, err := RandomBytes(32)
	if err != nil {
		return nil, nil, fmt.Errorf("generate dek: %w", err)
	}
	encryptedValue, err = Seal(dek, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("seal value: %w", err)
	}
	encryptedDEK, err = kp.WrapDEK(ctx, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap dek: %w", err)
	}
	return encryptedValue, encryptedDEK, nil
}

// DecryptSecret unwraps the DEK using kp, then decrypts the value.
func DecryptSecret(ctx context.Context, kp KeyProvider, encryptedDEK, encryptedValue []byte) ([]byte, error) {
	dek, err := kp.UnwrapDEK(ctx, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	plaintext, err := Open(dek, encryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decrypt value: %w", err)
	}
	return plaintext, nil
}

// RewrapDEK unwraps a DEK under oldKP and re-wraps it under newKP.
// Use this when rotating the master key without re-encrypting secret values.
func RewrapDEK(ctx context.Context, oldKP, newKP KeyProvider, encryptedDEK []byte) ([]byte, error) {
	dek, err := oldKP.UnwrapDEK(ctx, encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	newEncryptedDEK, err := newKP.WrapDEK(ctx, dek)
	if err != nil {
		return nil, fmt.Errorf("rewrap dek: %w", err)
	}
	return newEncryptedDEK, nil
}
