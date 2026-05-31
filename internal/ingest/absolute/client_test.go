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

package absolute

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient_RequiresCredentials(t *testing.T) {
	if _, err := NewClient(Config{SecretKey: "s", ConsoleURL: "https://x"}); err == nil {
		t.Error("expected error for missing TokenID")
	}
	if _, err := NewClient(Config{TokenID: "t", ConsoleURL: "https://x"}); err == nil {
		t.Error("expected error for missing SecretKey")
	}
	if _, err := NewClient(Config{TokenID: "t", SecretKey: "s"}); err == nil {
		t.Error("expected error for missing ConsoleURL")
	}
}

func TestListInstalledApplications_SendsHMACAndReturnsRows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "ABS1-HMAC-SHA-256 ") {
			t.Errorf("Authorization scheme missing: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Abs-Date") == "" {
			t.Errorf("X-Abs-Date missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
{"deviceUid":"dev-1","deviceName":"host-1","osFamily":"Linux",
 "appName":"OpenSSL","appVendor":"OpenSSL Project","appVersion":"3.0.14",
 "installedAt":"2026-04-10T12:00:00Z"}]}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{TokenID: "t-id", SecretKey: "sec", ConsoleURL: srv.URL, HTTPTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	apps, err := c.ListInstalledApplications(context.Background(), time.Unix(0, 0), []string{"openssl"})
	if err != nil {
		t.Fatalf("ListInstalledApplications: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("apps = %d, want 1", len(apps))
	}
	if apps[0].DeviceID != "dev-1" {
		t.Errorf("DeviceID = %q", apps[0].DeviceID)
	}
	if apps[0].AppName != "OpenSSL" || apps[0].AppVersion != "3.0.14" {
		t.Errorf("app = %+v", apps[0])
	}
}

func TestListInstalledApplications_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{TokenID: "t", SecretKey: "s", ConsoleURL: srv.URL})
	defer c.Close()

	_, err := c.ListInstalledApplications(context.Background(), time.Now(), []string{"openssl"})
	rl, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("want *RateLimitError, got %T: %v", err, err)
	}
	if rl.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v", rl.RetryAfter)
	}
}

func TestListInstalledApplications_AuthError(t *testing.T) {
	for _, code := range []int{401, 403} {
		code := code
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte("denied"))
		}))

		c, _ := NewClient(Config{TokenID: "t", SecretKey: "s", ConsoleURL: srv.URL})
		_, err := c.ListInstalledApplications(context.Background(), time.Now(), []string{"openssl"})
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

func TestListInstalledApplications_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{TokenID: "t", SecretKey: "s", ConsoleURL: srv.URL})
	defer c.Close()

	_, err := c.ListInstalledApplications(context.Background(), time.Now(), []string{"openssl"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want 500 error, got %v", err)
	}
}

func TestExecuteReachScript_ReturnsExecutionID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "ABS1-HMAC-SHA-256 ") {
			t.Errorf("auth missing scheme")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"executionId":"exec-123"}}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{TokenID: "t", SecretKey: "s", ConsoleURL: srv.URL})
	defer c.Close()

	id, err := c.ExecuteReachScript(context.Background(), "script-1", "all")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if id != "exec-123" {
		t.Errorf("execution id = %q", id)
	}
}

func TestExecuteReachScript_RejectsNonAllTarget(t *testing.T) {
	c, _ := NewClient(Config{TokenID: "t", SecretKey: "s", ConsoleURL: "https://x"})
	defer c.Close()
	_, err := c.ExecuteReachScript(context.Background(), "s1", "group:prod")
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("want unsupported-target error, got %v", err)
	}
}

func TestGetReachExecutionStatus_MapsStates(t *testing.T) {
	cases := []struct {
		raw  string
		want ReachTaskState
	}{
		{"pending", ReachTaskStatePending},
		{"running", ReachTaskStateRunning},
		{"in_progress", ReachTaskStateRunning},
		{"completed", ReachTaskStateCompleted},
		{"failed", ReachTaskStateFailed},
		{"expired", ReachTaskStateExpired},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.raw, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":{"executionId":"e1","status":"` + tc.raw + `","statusReason":"x"}}`))
			}))
			defer srv.Close()

			c, _ := NewClient(Config{TokenID: "t", SecretKey: "s", ConsoleURL: srv.URL})
			defer c.Close()

			s, err := c.GetReachExecutionStatus(context.Background(), "e1")
			if err != nil {
				t.Fatalf("GetStatus: %v", err)
			}
			if s.State != tc.want {
				t.Errorf("state = %v, want %v", s.State, tc.want)
			}
		})
	}
}

func TestGetReachExecutionResults_StreamsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "exec-9") {
			t.Errorf("path missing executionId: %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"type":"library","name":"openssl","version":"3.0.14"}` + "\n"))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{TokenID: "t", SecretKey: "s", ConsoleURL: srv.URL})
	defer c.Close()

	rc, err := c.GetReachExecutionResults(context.Background(), "exec-9")
	if err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	defer rc.Close()
	body, _ := io.ReadAll(rc)
	if !strings.Contains(string(body), "openssl") {
		t.Errorf("body = %q", body)
	}
}
