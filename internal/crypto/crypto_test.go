package crypto

import (
	"bytes"
	"testing"
)

func TestParseKEK(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid 64-char hex",
			input: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		},
		{
			name:    "too short",
			input:   "deadbeef",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
			wantErr: true,
		},
		{
			name:    "non-hex characters",
			input:   "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKEK(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != 32 {
				t.Errorf("key length = %d, want 32", len(got))
			}
		})
	}
}

func TestGenerateKEK(t *testing.T) {
	a, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	if len(a) != 64 {
		t.Errorf("len = %d, want 64", len(a))
	}

	// Two calls should produce different keys.
	b, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK second call: %v", err)
	}
	if a == b {
		t.Error("two GenerateKEK calls returned the same key")
	}

	// Generated key must parse successfully.
	if _, err := ParseKEK(a); err != nil {
		t.Errorf("generated key failed ParseKEK: %v", err)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kekHex, _ := GenerateKEK()
	kek, _ := ParseKEK(kekHex)

	plaintexts := []string{
		"",
		"short",
		"postgres://user:pass@host:5432/db",
		"a secret with spaces and symbols: !@#$%^&*()",
		string(make([]byte, 4096)), // large value
	}

	for _, pt := range plaintexts {
		label := pt
		if len(label) > 20 {
			label = label[:20]
		}
		t.Run(label, func(t *testing.T) {
			encVal, encDEK, err := EncryptSecret(kek, []byte(pt))
			if err != nil {
				t.Fatalf("EncryptSecret: %v", err)
			}

			got, err := DecryptSecret(kek, encDEK, encVal)
			if err != nil {
				t.Fatalf("DecryptSecret: %v", err)
			}

			if !bytes.Equal(got, []byte(pt)) {
				t.Errorf("decrypted value mismatch:\ngot  %q\nwant %q", got, pt)
			}
		})
	}
}

func TestEncryptProducesUniqueCiphertexts(t *testing.T) {
	kekHex, _ := GenerateKEK()
	kek, _ := ParseKEK(kekHex)
	pt := []byte("same plaintext")

	enc1, _, err := EncryptSecret(kek, pt)
	if err != nil {
		t.Fatal(err)
	}
	enc2, _, err := EncryptSecret(kek, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc1, enc2) {
		t.Error("two encryptions of the same value produced identical ciphertexts (nonce reuse)")
	}
}

func TestDecryptWithWrongKEK(t *testing.T) {
	kekHex, _ := GenerateKEK()
	kek, _ := ParseKEK(kekHex)

	wrongHex, _ := GenerateKEK()
	wrongKEK, _ := ParseKEK(wrongHex)

	encVal, encDEK, err := EncryptSecret(kek, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptSecret(wrongKEK, encDEK, encVal)
	if err == nil {
		t.Error("expected error decrypting with wrong KEK, got nil")
	}
}

func TestRewrapDEK(t *testing.T) {
	oldHex, _ := GenerateKEK()
	oldKEK, _ := ParseKEK(oldHex)

	newHex, _ := GenerateKEK()
	newKEK, _ := ParseKEK(newHex)

	plaintext := []byte("my secret value")
	encVal, encDEK, err := EncryptSecret(oldKEK, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Rewrap the DEK under the new KEK.
	newEncDEK, err := RewrapDEK(oldKEK, newKEK, encDEK)
	if err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}

	// Old DEK ciphertext and new should differ.
	if bytes.Equal(encDEK, newEncDEK) {
		t.Error("rewrapped DEK is identical to original")
	}

	// Decrypting the original ciphertext with the rewrapped DEK should work.
	got, err := DecryptSecret(newKEK, newEncDEK, encVal)
	if err != nil {
		t.Fatalf("DecryptSecret after rewrap: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("got %q, want %q", got, plaintext)
	}

	// Old KEK must no longer decrypt.
	_, err = DecryptSecret(oldKEK, newEncDEK, encVal)
	if err == nil {
		t.Error("expected error using old KEK on rewrapped DEK")
	}
}
