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
package sentinelone

import (
	"context"
	"io"
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

func TestListInstalledApplications_SendsApiTokenAndReturnsRows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "ApiToken test-token" {
			t.Errorf("Authorization = %q, want ApiToken test-token", got)
		}
		if r.URL.Path != "/web/api/v2.1/installed-applications" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("name__contains") == "" {
			t.Errorf("missing name__contains filter")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
{"agentDetails":{"uuid":"uuid-1","computerName":"host-1","osType":"linux"},
 "name":"OpenSSL","vendor":"OpenSSL Project","version":"3.0.14",
 "installedAt":"2026-04-10T12:00:00Z"}]}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{APIToken: "test-token", ConsoleURL: srv.URL, HTTPTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	rows, err := c.ListInstalledApplications(context.Background(), time.Unix(0, 0), []string{"openssl"})
	if err != nil {
		t.Fatalf("ListInstalledApplications: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].AgentUUID != "uuid-1" {
		t.Errorf("AgentUUID = %q", rows[0].AgentUUID)
	}
	if rows[0].AppName != "OpenSSL" || rows[0].AppVersion != "3.0.14" {
		t.Errorf("app = %+v", rows[0])
	}
}

func TestListInstalledApplications_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
	defer c.Close()

	_, err := c.ListInstalledApplications(context.Background(), time.Now(), []string{"openssl"})
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

func TestListInstalledApplications_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
	defer c.Close()

	_, err := c.ListInstalledApplications(context.Background(), time.Now(), []string{"openssl"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want 500 error, got %v", err)
	}
}

func TestExecuteRemoteScript_ReturnsTaskID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Path != "/web/api/v2.1/remote-scripts/execute" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "ApiToken t" {
			t.Errorf("auth = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"parentTaskId":"parent-123","affected":42}}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
	defer c.Close()

	id, err := c.ExecuteRemoteScript(context.Background(), "script-1", "all")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if id != "parent-123" {
		t.Errorf("taskID = %q", id)
	}
}

func TestGetRemoteScriptStatus_MapsStates(t *testing.T) {
	cases := []struct {
		raw  string
		want TaskState
	}{
		{"in_progress", TaskStateRunning},
		{"pending", TaskStatePending},
		{"completed", TaskStateCompleted},
		{"failed", TaskStateFailed},
		{"expired", TaskStateExpired},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":[{"id":"t1","status":"` + tc.raw + `","statusReason":"x"}]}`))
			}))
			defer srv.Close()

			c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
			defer c.Close()

			s, err := c.GetRemoteScriptStatus(context.Background(), "t1")
			if err != nil {
				t.Fatalf("GetStatus: %v", err)
			}
			if s.State != tc.want {
				t.Errorf("state = %v, want %v", s.State, tc.want)
			}
		})
	}
}

func TestGetRemoteScriptResults_StreamsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("parentTaskId") != "p1" {
			t.Errorf("parentTaskId query missing: %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"type":"library","name":"openssl","version":"3.0.14"}` + "\n"))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{APIToken: "t", ConsoleURL: srv.URL})
	defer c.Close()

	rc, err := c.GetRemoteScriptResults(context.Background(), "p1")
	if err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	defer rc.Close()
	body, _ := io.ReadAll(rc)
	if !strings.Contains(string(body), "openssl") {
		t.Errorf("body = %q", body)
	}
}
