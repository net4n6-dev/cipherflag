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

// Package web embeds the built SvelteKit single-page app and serves it
// with a path-aware fallback so the Go binary can serve both the UI and
// the API on one origin.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler serving the embedded SPA. Intended to
// be registered as the router's NotFound catch-all, after all API routes.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("web: embedded dist missing: " + err.Error())
	}
	return handlerForFS(sub)
}

// handlerForFS builds the serving handler over an arbitrary fs.FS so it
// can be unit-tested without the real embedded build.
//
// Behavior:
//   - /api/* reaching here is unmatched by the API router -> JSON 404
//     (never the HTML shell, which would break API clients).
//   - a real file in the FS (e.g. /_app/..., /favicon.ico) -> that file.
//   - anything else -> 200 + index.html (SPA shell) for client-side
//     routing and deep-link refresh.
func handlerForFS(sub fs.FS) http.Handler {
	fileServer := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
			return
		}

		if p := strings.TrimPrefix(r.URL.Path, "/"); p != "" {
			if f, err := sub.Open(p); err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		serveIndex(w, sub)
	})
}

// serveIndex writes index.html with a 200 even when the requested path
// did not exist (SPA fallback), so http.ServeFileFS with the original
// path is intentionally not used.
func serveIndex(w http.ResponseWriter, sub fs.FS) {
	data, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
