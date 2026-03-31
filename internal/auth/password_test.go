package auth

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("validpass123")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	if hash == "validpass123" {
		t.Fatal("hash equals plaintext")
	}
}

func TestHashPasswordTooShort(t *testing.T) {
	_, err := HashPassword("short")
	if err == nil {
		t.Fatal("expected error for short password")
	}
}

func TestHashPasswordExactMinLength(t *testing.T) {
	_, err := HashPassword("12345678")
	if err != nil {
		t.Fatalf("8-char password should be valid: %v", err)
	}
}

func TestCheckPasswordCorrect(t *testing.T) {
	hash, _ := HashPassword("testpassword")
	if !CheckPassword("testpassword", hash) {
		t.Fatal("correct password should match")
	}
}

func TestCheckPasswordWrong(t *testing.T) {
	hash, _ := HashPassword("testpassword")
	if CheckPassword("wrongpassword", hash) {
		t.Fatal("wrong password should not match")
	}
}

func TestCheckPasswordEmpty(t *testing.T) {
	hash, _ := HashPassword("testpassword")
	if CheckPassword("", hash) {
		t.Fatal("empty password should not match")
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	hash1, _ := HashPassword("samepassword")
	hash2, _ := HashPassword("samepassword")
	if hash1 == hash2 {
		t.Fatal("same password should produce different hashes (different salts)")
	}
}
