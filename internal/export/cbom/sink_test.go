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

package cbom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
)

func minimalBOM() *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	return bom
}

func TestHTTPSink_BearerAuth(t *testing.T) {
	t.Setenv("TEST_TOKEN", "secret-token")
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := &HTTPSink{
		cfg:    config.HTTPSinkConfig{URL: srv.URL, Auth: "bearer", AuthRef: "TEST_TOKEN"},
		common: config.SinkConfig{Timeout: 5 * time.Second, Retries: 0},
	}
	if err := sink.Send(context.Background(), &SinkPayload{BOM: minimalBOM()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want Bearer secret-token", gotAuth)
	}
}

func TestHTTPSink_HeaderAuth(t *testing.T) {
	t.Setenv("TEST_KEY", "my-api-key")
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := &HTTPSink{
		cfg:    config.HTTPSinkConfig{URL: srv.URL, Auth: "header", AuthRef: "TEST_KEY", AuthHeaderName: "X-API-Key"},
		common: config.SinkConfig{Timeout: 5 * time.Second, Retries: 0},
	}
	if err := sink.Send(context.Background(), &SinkPayload{BOM: minimalBOM()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotHeader != "my-api-key" {
		t.Errorf("X-API-Key = %q, want my-api-key", gotHeader)
	}
}

func TestHTTPSink_NoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected Authorization header with auth=none")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	sink := &HTTPSink{
		cfg:    config.HTTPSinkConfig{URL: srv.URL, Auth: "none"},
		common: config.SinkConfig{Timeout: 5 * time.Second},
	}
	if err := sink.Send(context.Background(), &SinkPayload{BOM: minimalBOM()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestHTTPSink_4xxNoRetry(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	sink := &HTTPSink{
		cfg:    config.HTTPSinkConfig{URL: srv.URL, Auth: "none"},
		common: config.SinkConfig{Timeout: 5 * time.Second, Retries: 3},
	}
	err := sink.Send(context.Background(), &SinkPayload{BOM: minimalBOM()})
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt for 4xx, got %d", attempts)
	}
}

func TestHTTPSink_5xxRetries(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	sink := &HTTPSink{
		cfg:    config.HTTPSinkConfig{URL: srv.URL, Auth: "none"},
		common: config.SinkConfig{Timeout: 5 * time.Second, Retries: 2},
	}
	err := sink.Send(context.Background(), &SinkPayload{BOM: minimalBOM()})
	if err == nil {
		t.Fatal("expected error after exhausted retries")
	}
	if attempts != 3 { // initial + 2 retries
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestHTTPSink_ContentType(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	sink := &HTTPSink{
		cfg:    config.HTTPSinkConfig{URL: srv.URL, Auth: "none"},
		common: config.SinkConfig{Timeout: 5 * time.Second},
	}
	_ = sink.Send(context.Background(), &SinkPayload{BOM: minimalBOM()})
	if !strings.HasPrefix(gotCT, "application/vnd.cyclonedx+json") {
		t.Errorf("Content-Type = %q, want application/vnd.cyclonedx+json prefix", gotCT)
	}
}

func TestFileSink_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	sink := &FileSink{
		cfg:       config.FileSinkConfig{PathTemplate: "{output_dir}/{scope}/{timestamp}.cdx.json"},
		common:    config.SinkConfig{},
		outputDir: dir,
		scopeName: "test-scope",
	}

	if err := sink.Send(context.Background(), &SinkPayload{BOM: minimalBOM()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Verify a .cdx.json file exists in dir/test-scope/
	scopeDir := filepath.Join(dir, "test-scope")
	entries, err := os.ReadDir(scopeDir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", scopeDir, err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".cdx.json") {
		t.Errorf("expected one .cdx.json file, got %v", entries)
	}
	// No .tmp file should remain
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("stale .tmp file found: %s", e.Name())
		}
	}
}

func TestFileSink_DirAutoCreation(t *testing.T) {
	dir := t.TempDir()
	sink := &FileSink{
		cfg:       config.FileSinkConfig{PathTemplate: "{output_dir}/{scope}/{timestamp}.cdx.json"},
		common:    config.SinkConfig{},
		outputDir: dir,
		scopeName: "new-scope",
	}
	// new-scope directory does not exist yet
	if err := sink.Send(context.Background(), &SinkPayload{BOM: minimalBOM()}); err != nil {
		t.Fatalf("Send should auto-create directory: %v", err)
	}
}

func TestFileSink_TemplateResolution(t *testing.T) {
	dir := t.TempDir()
	sink := &FileSink{
		cfg:       config.FileSinkConfig{PathTemplate: "{output_dir}/{scope}/{timestamp}.cdx.json"},
		common:    config.SinkConfig{},
		outputDir: dir,
		scopeName: "prod",
	}

	if err := sink.Send(context.Background(), &SinkPayload{BOM: minimalBOM()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "prod"))
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
	name := entries[0].Name()
	// Timestamp format: 20060102T150405Z
	if !strings.HasSuffix(name, ".cdx.json") || len(name) < 20 {
		t.Errorf("unexpected filename: %s", name)
	}
}
