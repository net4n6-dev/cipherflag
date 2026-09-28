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

package crtsh

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCrtsh_QueryDomain_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify wildcard prefix when include_subdomains=true.
		if !strings.Contains(r.URL.RawQuery, "q=%25.example.com") {
			t.Errorf("query = %q, want substring %q", r.URL.RawQuery, "q=%25.example.com")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"id": 100, "common_name": "a.example.com", "name_value": "a.example.com", "issuer_name": "Let's Encrypt", "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00", "entry_timestamp": "2026-01-01T00:00:00"},
			{"id": 200, "common_name": "b.example.com", "name_value": "b.example.com", "issuer_name": "DigiCert", "not_before": "2026-02-01T00:00:00", "not_after": "2026-05-01T00:00:00", "entry_timestamp": "2026-02-01T00:00:00"}
		]`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	entries, err := c.QueryDomain(context.Background(), "example.com", true)
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	if entries[0].ID != 100 || entries[1].ID != 200 {
		t.Errorf("ids = %d, %d; want 100, 200", entries[0].ID, entries[1].ID)
	}
}

func TestCrtsh_QueryDomain_NoSubdomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify NO wildcard prefix when include_subdomains=false.
		if strings.Contains(r.URL.RawQuery, "%25") {
			t.Errorf("query = %q, must NOT include wildcard", r.URL.RawQuery)
		}
		if !strings.Contains(r.URL.RawQuery, "q=example.com") {
			t.Errorf("query = %q, want substring %q", r.URL.RawQuery, "q=example.com")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := c.QueryDomain(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
}

func TestCrtsh_FetchPEM_HappyPath(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAJZ...\n-----END CERTIFICATE-----\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "d=42") {
			t.Errorf("query = %q, want substring %q", r.URL.RawQuery, "d=42")
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(pem))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	got, err := c.FetchPEM(context.Background(), 42)
	if err != nil {
		t.Fatalf("FetchPEM: %v", err)
	}
	if got != pem {
		t.Errorf("PEM = %q, want %q", got, pem)
	}
}

func TestCrtsh_QueryDomain_429Backoff(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	// Override backoff base for fast test execution.
	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client(), BackoffBase: 1 * time.Millisecond}
	_, err := c.QueryDomain(context.Background(), "example.com", true)
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3 (2 retries + 1 success)", calls)
	}
}

func TestCrtsh_QueryDomain_RetriesOn502_504(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusGatewayTimeout} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls < 3 {
					w.WriteHeader(status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[]`))
			}))
			defer srv.Close()

			c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client(), BackoffBase: 1 * time.Millisecond}
			_, err := c.QueryDomain(context.Background(), "example.com", true)
			if err != nil {
				t.Fatalf("QueryDomain (status %d): %v", status, err)
			}
			if calls != 3 {
				t.Errorf("calls = %d, want 3 (2 retries + 1 success)", calls)
			}
		})
	}
}

func TestCrtsh_FetchPEM_RetriesOn502(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client(), BackoffBase: 1 * time.Millisecond}
	pem, err := c.FetchPEM(context.Background(), 12345)
	if err != nil {
		t.Fatalf("FetchPEM: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
	if !strings.Contains(pem, "BEGIN CERTIFICATE") {
		t.Errorf("PEM missing BEGIN CERTIFICATE marker")
	}
}

func TestCrtsh_FetchPEM_GivesUpAfter2Retries(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client(), BackoffBase: 1 * time.Millisecond}
	_, err := c.FetchPEM(context.Background(), 12345)
	if err == nil {
		t.Fatal("FetchPEM returned nil error after persistent 502")
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3 (1 initial + 2 retries)", calls)
	}
}

func TestCrtsh_QueryDomain_GivesUpAfter5Retries(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client(), BackoffBase: 1 * time.Millisecond}
	_, err := c.QueryDomain(context.Background(), "example.com", true)
	if err == nil {
		t.Fatal("QueryDomain returned nil error after persistent 429")
	}
	if calls != 6 {
		t.Errorf("calls = %d, want 6 (1 initial + 5 retries)", calls)
	}
}
