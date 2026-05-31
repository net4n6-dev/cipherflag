// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package defender

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// twoEndpointServer routes /oauth2/v2.0/token to tokenHandler and any other
// path to queryHandler. Returns the server, the per-handler call counts,
// and the captured query body from the most recent query call.
type twoEndpointServer struct {
	server         *httptest.Server
	tokenCalls     atomic.Int32
	queryCalls     atomic.Int32
	lastQueryBody  string
	lastAuthHeader string
}

func newTwoEndpointServer(tokenStatus, queryStatus int, queryBody string) *twoEndpointServer {
	s := &twoEndpointServer{}
	s.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/oauth2/v2.0/token") {
			s.tokenCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if tokenStatus != http.StatusOK {
				w.WriteHeader(tokenStatus)
				_, _ = w.Write([]byte(`{"error": "test"}`))
				return
			}
			_, _ = w.Write([]byte(`{
				"token_type": "Bearer",
				"expires_in": 3600,
				"access_token": "test.access.token.value"
			}`))
			return
		}

		// Query endpoint.
		s.queryCalls.Add(1)
		s.lastAuthHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		s.lastQueryBody = string(body)

		w.Header().Set("Content-Type", "application/json")
		if queryStatus == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(queryStatus)
			_, _ = w.Write([]byte(`{"error": {"message": "rate limited"}}`))
			return
		}
		if queryStatus != http.StatusOK {
			w.WriteHeader(queryStatus)
			_, _ = w.Write([]byte(`{"error": "test"}`))
			return
		}
		_, _ = w.Write([]byte(queryBody))
	}))
	return s
}

func TestOAuthClient_TokenAndQuery(t *testing.T) {
	queryBody := `{
		"Schema": [{"Name": "DeviceId", "Type": "String"}],
		"Results": [{"DeviceId": "d1", "SoftwareName": "OpenSSL"}]
	}`
	s := newTwoEndpointServer(http.StatusOK, http.StatusOK, queryBody)
	defer s.server.Close()

	client, err := NewClient(Config{
		TenantID:     "test-tenant",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		APIBaseURL:   s.server.URL,
		TokenURL:     s.server.URL + "/test-tenant/oauth2/v2.0/token",
		HTTPTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Override the HTTP client to skip TLS verification (httptest uses self-signed cert).
	client.(*OAuthClient).http = s.server.Client()

	rows, err := client.RunAdvancedQuery(context.Background(), "DeviceTvmSoftwareInventory | take 10")
	if err != nil {
		t.Fatalf("RunAdvancedQuery: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Columns["DeviceId"] != "d1" {
		t.Errorf("rows[0].DeviceId = %v", rows[0].Columns["DeviceId"])
	}

	if !strings.HasPrefix(s.lastAuthHeader, "Bearer ") {
		t.Errorf("Authorization header = %q, want Bearer prefix", s.lastAuthHeader)
	}
	if !strings.Contains(s.lastQueryBody, "DeviceTvmSoftwareInventory") {
		t.Errorf("query body should include KQL: %s", s.lastQueryBody)
	}
	if s.tokenCalls.Load() != 1 {
		t.Errorf("token calls = %d, want 1", s.tokenCalls.Load())
	}
	if s.queryCalls.Load() != 1 {
		t.Errorf("query calls = %d, want 1", s.queryCalls.Load())
	}
}

func TestOAuthClient_TokenCaching(t *testing.T) {
	queryBody := `{"Schema": [], "Results": []}`
	s := newTwoEndpointServer(http.StatusOK, http.StatusOK, queryBody)
	defer s.server.Close()

	client, _ := NewClient(Config{
		TenantID:     "test-tenant",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		APIBaseURL:   s.server.URL,
		TokenURL:     s.server.URL + "/test-tenant/oauth2/v2.0/token",
		HTTPTimeout:  5 * time.Second,
	})
	defer client.Close()
	client.(*OAuthClient).http = s.server.Client()

	for i := 0; i < 2; i++ {
		_, err := client.RunAdvancedQuery(context.Background(), "irrelevant")
		if err != nil {
			t.Fatalf("RunAdvancedQuery #%d: %v", i, err)
		}
	}

	if s.tokenCalls.Load() != 1 {
		t.Errorf("token calls = %d, want 1 (cached)", s.tokenCalls.Load())
	}
	if s.queryCalls.Load() != 2 {
		t.Errorf("query calls = %d, want 2", s.queryCalls.Load())
	}
}

func TestOAuthClient_RateLimit(t *testing.T) {
	s := newTwoEndpointServer(http.StatusOK, http.StatusTooManyRequests, "")
	defer s.server.Close()

	client, _ := NewClient(Config{
		TenantID:     "test-tenant",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		APIBaseURL:   s.server.URL,
		TokenURL:     s.server.URL + "/test-tenant/oauth2/v2.0/token",
		HTTPTimeout:  5 * time.Second,
	})
	defer client.Close()
	client.(*OAuthClient).http = s.server.Client()

	_, err := client.RunAdvancedQuery(context.Background(), "irrelevant")
	if err == nil {
		t.Fatal("expected error on 429")
	}

	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	if rl.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v, want 30s", rl.RetryAfter)
	}
}

func TestOAuthClient_RequiredFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"missing tenant", Config{ClientID: "c", ClientSecret: "s"}},
		{"missing client_id", Config{TenantID: "t", ClientSecret: "s"}},
		{"missing client_secret", Config{TenantID: "t", ClientID: "c"}},
	}
	for _, tt := range tests {
		_, err := NewClient(tt.cfg)
		if err == nil {
			t.Errorf("%s: expected error for missing field", tt.name)
		}
	}
}
