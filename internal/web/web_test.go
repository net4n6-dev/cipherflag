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

package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func testFS() fs.FS {
	return fstest.MapFS{
		"index.html":            {Data: []byte("<!doctype html><title>CipherFlag</title>")},
		"favicon.ico":           {Data: []byte("ICODATA")},
		"_app/immutable/app.js": {Data: []byte("APPJS")},
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler_ServesIndexAtRoot(t *testing.T) {
	rec := get(t, handlerForFS(testFS()), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "CipherFlag") {
		t.Fatalf("body missing index content: %q", rec.Body.String())
	}
}

func TestHandler_SPAFallbackForUnknownPage(t *testing.T) {
	rec := get(t, handlerForFS(testFS()), "/certificates/abc123")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SPA fallback)", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
}

func TestHandler_ServesExistingAsset(t *testing.T) {
	rec := get(t, handlerForFS(testFS()), "/favicon.ico")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ICODATA" {
		t.Fatalf("asset body = %q, want ICODATA", rec.Body.String())
	}
}

func TestHandler_UnknownAPIPathReturnsJSON404(t *testing.T) {
	rec := get(t, handlerForFS(testFS()), "/api/v1/bogus")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json (NOT html)", ct)
	}
}

func TestHandler_EmbeddedHandlerConstructs(t *testing.T) {
	// Handler() must not panic — proves //go:embed all:dist resolved.
	if Handler() == nil {
		t.Fatal("Handler() returned nil")
	}
}

func TestHandler_BareAPIPathReturnsJSON404(t *testing.T) {
	rec := get(t, handlerForFS(testFS()), "/api")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
}

func TestHandler_DirectoryPathFallsBackToSPA(t *testing.T) {
	rec := get(t, handlerForFS(testFS()), "/_app/immutable")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SPA fallback, not a 301)", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html (SPA fallback)", ct)
	}
}
