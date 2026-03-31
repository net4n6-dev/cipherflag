package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var testSecret = GenerateSecret("test-secret-seed")

func TestSignAndVerifyJWT(t *testing.T) {
	token, err := SignJWT(testSecret, "user-123", "admin@test.com", "admin")
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}

	claims, err := VerifyJWT(testSecret, token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if claims.Sub != "user-123" {
		t.Errorf("sub = %q, want %q", claims.Sub, "user-123")
	}
	if claims.Email != "admin@test.com" {
		t.Errorf("email = %q, want %q", claims.Email, "admin@test.com")
	}
	if claims.Role != "admin" {
		t.Errorf("role = %q, want %q", claims.Role, "admin")
	}
}

func TestVerifyJWTWrongSecret(t *testing.T) {
	token, _ := SignJWT(testSecret, "user-123", "admin@test.com", "admin")
	wrongSecret := GenerateSecret("wrong-secret")

	_, err := VerifyJWT(wrongSecret, token)
	if err == nil {
		t.Fatal("expected error with wrong secret")
	}
}

func TestVerifyJWTMalformed(t *testing.T) {
	_, err := VerifyJWT(testSecret, "not-a-jwt")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestVerifyJWTEmpty(t *testing.T) {
	_, err := VerifyJWT(testSecret, "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestVerifyJWTTampered(t *testing.T) {
	token, _ := SignJWT(testSecret, "user-123", "admin@test.com", "admin")
	// Tamper with the payload
	tampered := token[:len(token)-5] + "XXXXX"

	_, err := VerifyJWT(testSecret, tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestJWTExpiry(t *testing.T) {
	token, _ := SignJWT(testSecret, "user-123", "admin@test.com", "admin")

	claims, err := VerifyJWT(testSecret, token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	// Token should expire in ~24 hours
	expiry := time.Unix(claims.Exp, 0)
	diff := time.Until(expiry)
	if diff < 23*time.Hour || diff > 25*time.Hour {
		t.Errorf("expiry diff = %v, want ~24h", diff)
	}
}

func TestSetAndGetTokenCookie(t *testing.T) {
	token, _ := SignJWT(testSecret, "user-123", "admin@test.com", "admin")

	// Set cookie
	w := httptest.NewRecorder()
	SetTokenCookie(w, token)

	// Read cookie back
	resp := w.Result()
	cookies := resp.Cookies()

	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == CookieName {
			found = c
			break
		}
	}

	if found == nil {
		t.Fatal("cookie not set")
	}
	if found.Value != token {
		t.Error("cookie value doesn't match token")
	}
	if !found.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if found.SameSite != http.SameSiteStrictMode {
		t.Error("cookie should be SameSite=Strict")
	}
}

func TestClearTokenCookie(t *testing.T) {
	w := httptest.NewRecorder()
	ClearTokenCookie(w)

	resp := w.Result()
	cookies := resp.Cookies()

	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == CookieName {
			found = c
			break
		}
	}

	if found == nil {
		t.Fatal("clear cookie not set")
	}
	if found.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", found.MaxAge)
	}
}

func TestGetTokenFromCookie(t *testing.T) {
	token, _ := SignJWT(testSecret, "user-123", "admin@test.com", "admin")

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: token})

	got := GetTokenFromCookie(req)
	if got != token {
		t.Error("GetTokenFromCookie didn't return the token")
	}
}

func TestGetTokenFromCookieMissing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	got := GetTokenFromCookie(req)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestGenerateSecretDeterministic(t *testing.T) {
	s1 := GenerateSecret("same-seed")
	s2 := GenerateSecret("same-seed")
	if string(s1) != string(s2) {
		t.Error("same seed should produce same secret")
	}
}

func TestGenerateSecretDifferentSeeds(t *testing.T) {
	s1 := GenerateSecret("seed-a")
	s2 := GenerateSecret("seed-b")
	if string(s1) == string(s2) {
		t.Error("different seeds should produce different secrets")
	}
}
