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
package tanium

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient_RequiresAPIToken(t *testing.T) {
	if _, err := NewClient(Config{ConsoleURL: "https://x"}); err == nil {
		t.Fatal("expected error for missing APIToken")
	}
}

func TestNewClient_RequiresConsoleURL(t *testing.T) {
	if _, err := NewClient(Config{APIToken: "tok"}); err == nil {
		t.Fatal("expected error for missing ConsoleURL")
	}
}

func TestListEndpoints_SendsSessionHeaderAndQueryBody(t *testing.T) {
	var gotAuth string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Path != "/plugin/products/gateway/graphql" {
			t.Errorf("path = %q", r.URL.Path)
		}
		gotAuth = r.Header.Get("session")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
"data":{"endpoints":{
  "pageInfo":{"hasNextPage":false,"endCursor":""},
  "edges":[{"node":{
    "id":"e1","name":"host-1","ipAddress":"10.0.0.1",
    "operatingSystem":{"platform":"Linux"},
    "sensorReadings":[
      {"sensor":{"name":"CipherFlag.Crypto.Libraries"},
       "columns":[{"name":"output","values":["{\"type\":\"library\",\"name\":\"openssl\",\"version\":\"3.0.14\"}"]}]}
    ]
  }}]
}}}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{APIToken: "tok-1", ConsoleURL: srv.URL, HTTPTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	page, err := c.ListEndpoints(context.Background(), "")
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	if gotAuth != "tok-1" {
		t.Errorf("session header = %q, want tok-1", gotAuth)
	}
	for _, frag := range []string{"CipherFlag.Crypto.Certificates", "CipherFlag.Crypto.SSHKeys", "CipherFlag.Crypto.Libraries", "CipherFlag.Crypto.Configs", "Installed Applications"} {
		if !strings.Contains(gotBody, frag) {
			t.Errorf("query body missing %q", frag)
		}
	}
	if len(page.Endpoints) != 1 || page.Endpoints[0].EndpointID != "e1" {
		t.Fatalf("endpoints = %+v", page.Endpoints)
	}
	if page.HasNext {
		t.Errorf("HasNext = true, want false")
	}
	if page.Endpoints[0].Hostname != "host-1" {
		t.Errorf("Hostname = %q", page.Endpoints[0].Hostname)
	}
	if page.Endpoints[0].OSPlatform != "Linux" {
		t.Errorf("OSPlatform = %q", page.Endpoints[0].OSPlatform)
	}
	if len(page.Endpoints[0].Sensors) != 1 {
		t.Fatalf("sensors = %d", len(page.Endpoints[0].Sensors))
	}
}

func TestListEndpoints_PropagatesAfterCursor(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"endpoints":{"pageInfo":{"hasNextPage":false,"endCursor":""},"edges":[]}}}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
	defer c.Close()

	_, _ = c.ListEndpoints(context.Background(), "cursor-xyz")
	if !strings.Contains(gotBody, "cursor-xyz") {
		t.Errorf("query body missing cursor-xyz, got %s", gotBody)
	}
}

func TestListEndpoints_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
	defer c.Close()

	_, err := c.ListEndpoints(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
	rl, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("want *RateLimitError, got %T: %v", err, err)
	}
	if rl.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v", rl.RetryAfter)
	}
}

func TestListEndpoints_AuthError(t *testing.T) {
	for _, code := range []int{401, 403} {
		code := code
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte("denied"))
		}))

		c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
		_, err := c.ListEndpoints(context.Background(), "")
		srv.Close()
		c.Close()

		ae, ok := err.(*AuthError)
		if !ok {
			t.Fatalf("code %d: want *AuthError, got %T: %v", code, err, err)
		}
		if ae.StatusCode != code {
			t.Errorf("code %d: AuthError.StatusCode = %d", code, ae.StatusCode)
		}
	}
}

func TestListEndpoints_GraphQLErrorsEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"schema error"}]}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
	defer c.Close()

	_, err := c.ListEndpoints(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "schema error") {
		t.Fatalf("want error containing schema error, got %v", err)
	}
}

func TestListEndpoints_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
	defer c.Close()

	_, err := c.ListEndpoints(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want 500 error, got %v", err)
	}
}
