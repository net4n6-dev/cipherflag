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
package netwrix

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNTLMClient_SearchActivity_RequestShape(t *testing.T) {
	var capturedPath string
	var capturedMethod string
	var capturedBody string

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(searchResponse{
			Records: []map[string]interface{}{
				{
					"EventTime":  "2026-04-11T12:00:00Z",
					"Action":     "Added",
					"ObjectType": "Certificate",
					"Where":      "corp-CA01-CA",
					"What":       "CN=web-01.corp.local",
					"Who":        "DOMAIN\\alice",
					"DataSource": "Active Directory",
					"Details": map[string]interface{}{
						"SerialNumber": "0a1b2c3d",
						"Issuer":       "CN=corp-CA01-CA",
					},
				},
			},
			HasMore: false,
		})
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		BaseURL:         srv.URL,
		Username:        "test",
		Password:        "test",
		InsecureSkipTLS: true,
		HTTPTimeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	since := time.Date(2026, 4, 11, 0, 0, 0, 0, time.UTC)
	records, err := client.SearchActivity(context.Background(), SearchFilter{
		Since:      since,
		DataSource: "Active Directory",
	})
	if err != nil {
		t.Fatalf("SearchActivity: %v", err)
	}

	if capturedMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", capturedMethod)
	}
	if !strings.HasSuffix(capturedPath, "/api/v1/activity/search") {
		t.Errorf("path = %q, want suffix /api/v1/activity/search", capturedPath)
	}
	if !strings.Contains(capturedBody, "Active Directory") {
		t.Errorf("body should mention DataSource: %s", capturedBody)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Raw["Where"] != "corp-CA01-CA" {
		t.Errorf("record[0].Where = %v", records[0].Raw["Where"])
	}
}

func TestNTLMClient_Pagination(t *testing.T) {
	page := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		var hasMore bool
		var rec map[string]interface{}
		if page == 1 {
			hasMore = true
			rec = map[string]interface{}{
				"EventTime":  "2026-04-11T12:00:00Z",
				"Action":     "Added",
				"ObjectType": "Certificate",
				"Where":      "ca",
				"Who":        "alice",
				"Details":    map[string]interface{}{"SerialNumber": "1", "Issuer": "CN=ca"},
			}
		} else {
			hasMore = false
			rec = map[string]interface{}{
				"EventTime":  "2026-04-11T12:01:00Z",
				"Action":     "Revoked",
				"ObjectType": "Certificate",
				"Where":      "ca",
				"Who":        "bob",
				"Details":    map[string]interface{}{"SerialNumber": "2", "Issuer": "CN=ca"},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(searchResponse{Records: []map[string]interface{}{rec}, HasMore: hasMore, NextPageToken: "page2"})
	}))
	defer srv.Close()

	client, _ := NewClient(Config{BaseURL: srv.URL, Username: "u", Password: "p", InsecureSkipTLS: true, HTTPTimeout: 5 * time.Second})
	defer client.Close()

	records, err := client.SearchActivity(context.Background(), SearchFilter{})
	if err != nil {
		t.Fatalf("SearchActivity: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (across 2 pages)", len(records))
	}
	if page != 2 {
		t.Errorf("server saw %d page calls, want 2", page)
	}
}

func TestNTLMClient_HTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, _ := NewClient(Config{BaseURL: srv.URL, Username: "u", Password: "p", InsecureSkipTLS: true, HTTPTimeout: 5 * time.Second})
	defer client.Close()

	_, err := client.SearchActivity(context.Background(), SearchFilter{})
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
}
