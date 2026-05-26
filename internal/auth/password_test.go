// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
