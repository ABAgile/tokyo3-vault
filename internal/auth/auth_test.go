package auth

import (
	"testing"
)

func TestHashAndCheckPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"common password", "hunter2"},
		{"long password", "this is a much longer passphrase with spaces and symbols !@#"},
		{"empty password", ""},
		{"unicode", "パスワード🔑"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := HashPassword(tc.password)
			if err != nil {
				t.Fatalf("HashPassword: %v", err)
			}
			if hash == "" {
				t.Fatal("hash is empty")
			}
			if hash == tc.password {
				t.Error("hash equals plaintext password")
			}
			if !CheckPassword(hash, tc.password) {
				t.Error("CheckPassword returned false for correct password")
			}
		})
	}
}

func TestCheckPasswordRejectsWrongPassword(t *testing.T) {
	hash, err := HashPassword("correct")
	if err != nil {
		t.Fatal(err)
	}
	if CheckPassword(hash, "wrong") {
		t.Error("CheckPassword returned true for wrong password")
	}
	if CheckPassword(hash, "") {
		t.Error("CheckPassword returned true for empty password")
	}
}

func TestHashPasswordProducesUniqueHashes(t *testing.T) {
	// bcrypt uses a random salt, so two hashes of the same password differ.
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("two hashes of the same password are identical (no salt?)")
	}
	// Both must still verify.
	if !CheckPassword(h1, "same") || !CheckPassword(h2, "same") {
		t.Error("hashes do not verify")
	}
}

func TestHashToken(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"normal token", "abc123def456"},
		{"empty", ""},
		{"long", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := HashToken(tc.raw)
			if h == "" {
				t.Fatal("HashToken returned empty string")
			}
			// SHA-256 produces 32 bytes = 64 hex chars.
			if len(h) != 64 {
				t.Errorf("hash length = %d, want 64", len(h))
			}
			// Deterministic.
			if HashToken(tc.raw) != h {
				t.Error("HashToken is not deterministic")
			}
		})
	}
}

func TestHashTokenDifferentInputsDifferentHashes(t *testing.T) {
	h1 := HashToken("tokenA")
	h2 := HashToken("tokenB")
	if h1 == h2 {
		t.Error("different tokens produced the same hash")
	}
}
