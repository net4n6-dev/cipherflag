package venafi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func TestImportCertificate_SendsCorrectAuthAndBody(t *testing.T) {
	var authCalls int32

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&authCalls, 1)

		if r.URL.Path != "/authorize/oauth" {
			t.Errorf("auth path = %q, want /authorize/oauth", r.URL.Path)
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decoding auth body: %v", err)
		}

		if body["client_id"] != "test-client" {
			t.Errorf("client_id = %q, want %q", body["client_id"], "test-client")
		}
		if body["refresh_token"] != "initial-refresh-token" {
			t.Errorf("refresh_token = %q, want %q", body["refresh_token"], "initial-refresh-token")
		}
		if body["grant_type"] != "refresh_token" {
			t.Errorf("grant_type = %q, want %q", body["grant_type"], "refresh_token")
		}

		resp := tokenResponse{
			AccessToken:  "test-access-token",
			RefreshToken: "new-refresh-token",
			Expires:      3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer authServer.Close()

	var importBody importRequest
	var importAuthHeader string

	sdkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certificates/import" {
			t.Errorf("import path = %q, want /certificates/import", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("import method = %q, want POST", r.Method)
		}

		importAuthHeader = r.Header.Get("Authorization")

		data, _ := io.ReadAll(r.Body)
		json.Unmarshal(data, &importBody)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"CertificateDN":"\\VED\\Policy\\Test"}`))
	}))
	defer sdkServer.Close()

	client := NewClient(sdkServer.URL, authServer.URL, "test-client", "initial-refresh-token")

	cert := &model.Certificate{
		RawPEM:            "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		FingerprintSHA256: "abc123",
		Subject: model.DistinguishedName{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	err := client.ImportCertificate(context.Background(), cert, "\\VED\\Policy\\Certificates")
	if err != nil {
		t.Fatalf("ImportCertificate returned error: %v", err)
	}

	// Verify auth header
	if importAuthHeader != "Bearer test-access-token" {
		t.Errorf("Authorization = %q, want %q", importAuthHeader, "Bearer test-access-token")
	}

	// Verify import body
	if importBody.CertificateData != cert.RawPEM {
		t.Errorf("CertificateData = %q, want %q", importBody.CertificateData, cert.RawPEM)
	}
	if importBody.PolicyDN != "\\VED\\Policy\\Certificates" {
		t.Errorf("PolicyDN = %q, want %q", importBody.PolicyDN, "\\VED\\Policy\\Certificates")
	}
}

func TestTokenRefreshCalledOnFirstRequest(t *testing.T) {
	var authCalls int32

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&authCalls, 1)

		resp := tokenResponse{
			AccessToken:  "fresh-token",
			RefreshToken: "updated-refresh",
			Expires:      3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer authServer.Close()

	sdkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer sdkServer.Close()

	client := NewClient(sdkServer.URL, authServer.URL, "my-client", "my-refresh")

	cert := &model.Certificate{
		RawPEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}

	// First call should trigger token refresh.
	err := client.ImportCertificate(context.Background(), cert, "\\VED\\Policy\\Test")
	if err != nil {
		t.Fatalf("ImportCertificate returned error: %v", err)
	}

	calls := atomic.LoadInt32(&authCalls)
	if calls != 1 {
		t.Errorf("expected 1 auth call on first request, got %d", calls)
	}

	// Second call should reuse the cached token (not expired).
	err = client.ImportCertificate(context.Background(), cert, "\\VED\\Policy\\Test")
	if err != nil {
		t.Fatalf("second ImportCertificate returned error: %v", err)
	}

	calls = atomic.LoadInt32(&authCalls)
	if calls != 1 {
		t.Errorf("expected still 1 auth call after second request (cached token), got %d", calls)
	}
}

func TestTokenRefreshOnExpiry(t *testing.T) {
	var authCalls int32

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&authCalls, 1)

		resp := tokenResponse{
			AccessToken:  "token-" + string(rune('0'+atomic.LoadInt32(&authCalls))),
			RefreshToken: "refresh-updated",
			Expires:      1, // Expires in 1 second (within 60s buffer, so always expired)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer authServer.Close()

	sdkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer sdkServer.Close()

	client := NewClient(sdkServer.URL, authServer.URL, "client", "refresh")

	cert := &model.Certificate{
		RawPEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}

	// First call.
	err := client.ImportCertificate(context.Background(), cert, "\\VED\\Policy\\Test")
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	// Second call — token should be expired (1s expires, 60s buffer), so re-auth.
	err = client.ImportCertificate(context.Background(), cert, "\\VED\\Policy\\Test")
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	calls := atomic.LoadInt32(&authCalls)
	if calls != 2 {
		t.Errorf("expected 2 auth calls (token expired), got %d", calls)
	}
}
