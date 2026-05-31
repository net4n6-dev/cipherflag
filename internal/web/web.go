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
	// Read the SPA shell once at construction; if it's missing the embed is
	// broken, which is a build-time invariant — fail fast like Handler().
	indexHTML, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("web: index.html missing from embedded FS: " + err.Error())
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API paths never receive the HTML shell. Match both the bare
		// "/api" and any "/api/..." subpath.
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
			return
		}

		// p == "" only for "/"; skip the probe and fall through to the SPA
		// shell. Serve a real file only when it exists AND is not a directory
		// (a directory would make FileServerFS emit a spurious redirect).
		if p := strings.TrimPrefix(r.URL.Path, "/"); p != "" {
			if f, err := sub.Open(p); err == nil {
				info, statErr := f.Stat()
				_ = f.Close()
				if statErr == nil && !info.IsDir() {
					fileServer.ServeHTTP(w, r)
					return
				}
			}
		}

		// SPA fallback: index.html with 200, even when the path didn't exist.
		// (w.Write implicitly sends 200, so no explicit WriteHeader.)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
}
