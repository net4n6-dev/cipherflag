# Frontend Embed Serving Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the single `cipherflag` container serve the SvelteKit UI and the API on one origin (`:8443`), fixing the "no frontend" gap after the EE→CE 2.x cutover.

**Architecture:** Build the frontend as a static SPA (`@sveltejs/adapter-static`), embed it into the Go binary via `//go:embed all:dist`, and serve it through a path-aware `http.Handler` registered as the chi `NotFound` catch-all. API routes (`/api/v1/*`, `/healthz`) keep precedence; unmatched `/api/*` returns JSON 404, everything else returns the SPA shell.

**Tech Stack:** Go 1.25 (`embed`, `http.FileServerFS`), chi v5.2.5, SvelteKit 2 / Svelte 5, `@sveltejs/adapter-static`, Docker multi-stage build.

**Spec:** `docs/superpowers/specs/2026-05-31-frontend-embed-serving-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/web/web.go` (new) | Embed `dist/` and expose `Handler()`; path-aware SPA + JSON-404 logic |
| `internal/web/web_test.go` (new) | Unit-test the handler's four behaviors against an in-memory FS |
| `internal/web/dist/index.html` (new) | Committed placeholder so `go build ./...` compiles from source |
| `internal/api/server.go` (modify) | Register `web.Handler()` as the chi `NotFound` catch-all |
| `frontend/svelte.config.js` (modify) | Swap adapter-node → adapter-static (SPA fallback mode) |
| `frontend/src/routes/+layout.ts` (new) | Disable SSR/prerender — pure client-side SPA |
| `frontend/package.json` (modify) | Add `@sveltejs/adapter-static`, remove `@sveltejs/adapter-node` |
| `.gitignore` (modify) | Ignore built `internal/web/dist/*` but keep the placeholder |
| `Dockerfile` (modify) | Reorder: frontend stage → go stage (copies build into embed dir) → runtime |

**Decomposition note:** The Go handler (Tasks 1–2) and the frontend build config (Task 3) are independent and could be done in either order. The Dockerfile (Task 5) depends on both. Task 6 is the end-to-end verification.

---

## Task 1: `internal/web` package — embed + path-aware handler

**Files:**
- Create: `internal/web/dist/index.html`
- Create: `internal/web/web.go`
- Test: `internal/web/web_test.go`

The handler logic is split so the embed (`Handler()`) and the testable core (`handlerForFS`) are separate. The test drives `handlerForFS` against an in-memory `fstest.MapFS`, so it does not depend on real embedded build output.

- [ ] **Step 1: Create the committed placeholder so the embed directive compiles**

Create `internal/web/dist/index.html`:

```html
<!doctype html>
<title>CipherFlag</title>
<body>frontend not built — run the frontend build (see Dockerfile)</body>
```

- [ ] **Step 2: Write the failing test**

Create `internal/web/web_test.go`:

```go
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
		"index.html":  {Data: []byte("<!doctype html><title>CipherFlag</title>")},
		"favicon.ico": {Data: []byte("ICODATA")},
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
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/web/ -v`
Expected: FAIL — compile error, `undefined: handlerForFS` and `undefined: Handler`.

- [ ] **Step 4: Write the implementation**

Create `internal/web/web.go`:

```go
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
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/web/ -v`
Expected: PASS — all five tests green.

- [ ] **Step 6: Vet and build**

Run: `go vet ./internal/web/ && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/web/web.go internal/web/web_test.go internal/web/dist/index.html
git commit -m "feat(web): embed SPA with path-aware fallback handler

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Wire the handler into the router

**Files:**
- Modify: `internal/api/server.go` (imports block at lines 17–34; before `return r` at line 287)

Behavioral correctness of the handler is covered by Task 1. `NewRouter` requires a live store and many handlers, so this task verifies via build/vet; end-to-end behavior is asserted in Task 6.

- [ ] **Step 1: Add the import**

In `internal/api/server.go`, add to the project-import group (after the existing `"github.com/net4n6-dev/cipherflag/internal/store"` line):

```go
	"github.com/net4n6-dev/cipherflag/internal/web"
```

- [ ] **Step 2: Register the catch-all**

In `internal/api/server.go`, immediately before the final `return r` (currently line 287, after `log.Info().Msg("CE API routes registered")`), insert:

```go
	// SPA catch-all. Registered last so all /api/v1 and /healthz routes
	// take precedence; unmatched /api/* still gets a JSON 404 from the
	// handler, everything else gets the embedded SPA shell.
	r.NotFound(web.Handler().ServeHTTP)
```

The end of the function should read:

```go
	log.Info().Msg("CE API routes registered")

	// SPA catch-all. Registered last so all /api/v1 and /healthz routes
	// take precedence; unmatched /api/* still gets a JSON 404 from the
	// handler, everything else gets the embedded SPA shell.
	r.NotFound(web.Handler().ServeHTTP)
	return r
}
```

- [ ] **Step 3: Build and vet**

Run: `go vet ./internal/api/ && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 4: Run the full Go test suite for regressions**

Run: `go test ./...`
Expected: PASS (or unchanged from the pre-change baseline; any pre-existing failures are not introduced by this one-line change).

- [ ] **Step 5: Commit**

```bash
git add internal/api/server.go
git commit -m "feat(api): serve embedded SPA via NotFound catch-all

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Frontend — adapter-static SPA build

**Files:**
- Modify: `frontend/svelte.config.js`
- Create: `frontend/src/routes/+layout.ts`
- Modify: `frontend/package.json` (+ `frontend/package-lock.json` via npm)

- [ ] **Step 1: Swap the adapter in `frontend/svelte.config.js`**

Replace the entire file contents with:

```js
import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	kit: {
		adapter: adapter({ fallback: 'index.html', strict: false })
	}
};

export default config;
```

- [ ] **Step 2: Disable SSR/prerender via a root layout module**

Create `frontend/src/routes/+layout.ts` (a **new** file; note an existing `frontend/src/routes/+layout.svelte` is already present — the `.ts` module and the `.svelte` component coexist, SvelteKit loads both for the root layout):

```ts
// Pure client-side SPA: all data is fetched at runtime via src/lib/api.ts
// (same-origin /api/v1). No server rendering or prerendering.
export const ssr = false;
export const prerender = false;
```

- [ ] **Step 3: Swap the adapter dependency via npm**

Use npm commands rather than hand-editing JSON — `@sveltejs/adapter-node` is currently a dependency (svelte.config.js imports it), and npm resolves the exact section/version and updates the lockfile in one step:

Run:
```bash
cd frontend
npm install -D @sveltejs/adapter-static
npm uninstall @sveltejs/adapter-node
```
Expected: `package.json` gains `@sveltejs/adapter-static` under devDependencies and loses `@sveltejs/adapter-node`; `package-lock.json` updates accordingly. (`@sveltejs/adapter-auto` is left as-is per the approved spec — unused but low-churn.)

If `node`/`npm` is unavailable locally, perform Steps 3–4 inside the Docker build (Task 5) instead — note that here and skip to Task 4; the Docker frontend stage runs `npm ci` + `npm run build` against the edited `package.json`.

- [ ] **Step 4: Build and verify static output**

Run:
```bash
cd frontend && npm run build
test -f build/index.html && echo "OK index.html present"
test ! -f build/handler.js && echo "OK no node bundle (handler.js absent)"
```
Expected: both `OK` lines print. `build/index.html` exists (SPA shell); the adapter-node `handler.js` is gone.

- [ ] **Step 5: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/svelte.config.js frontend/src/routes/+layout.ts frontend/package.json frontend/package-lock.json
git commit -m "feat(frontend): build as static SPA for single-origin serving

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `.gitignore` — ignore built dist, keep placeholder

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Append the embed-dir rules**

Add to the end of `.gitignore` (the file already ignores `frontend/build/` and `frontend/.svelte-kit/`):

```
# Embedded frontend build output (placeholder index.html is tracked)
internal/web/dist/*
!internal/web/dist/index.html
```

- [ ] **Step 2: Verify the placeholder stays tracked and built assets would be ignored**

Run:
```bash
git check-ignore -v internal/web/dist/_app/foo.js && echo "OK built asset ignored"
git ls-files --error-unmatch internal/web/dist/index.html && echo "OK placeholder tracked"
```
Expected: `internal/web/dist/_app/foo.js` matches the ignore rule (printed by `check-ignore`, then `OK built asset ignored`); the placeholder `index.html` is tracked (`OK placeholder tracked`).

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: ignore built web/dist, keep placeholder index.html

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Dockerfile — reorder stages so the embed sees the build

**Files:**
- Modify: `Dockerfile`

The frontend must build **before** `go build`, and its output must land in `internal/web/dist/` for `//go:embed all:dist`. Verified: `.dockerignore` excludes `frontend/build`, `frontend/.svelte-kit`, `frontend/node_modules`, `node_modules`, `.git`, and `docs/superpowers/` — but **not** `internal/web/dist`, so the committed placeholder copies into the go-builder via `COPY . .` and is then overlaid by the real build output.

- [ ] **Step 1: Replace `Dockerfile` contents**

Replace the entire file with:

```dockerfile
# Stage 1: Build frontend (static SPA)
FROM node:22-alpine AS frontend-builder
WORKDIR /build
# Copy install-time inputs BEFORE `npm ci`:
#   - package.json / package-lock.json: deterministic dep resolution
#   - .npmrc: minimal install config (engine-strict)
COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 2: Build Go binary (embeds the frontend)
FROM golang:1.25-alpine AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Place the static frontend build where //go:embed all:dist expects it.
# This overlays the committed placeholder internal/web/dist/index.html.
COPY --from=frontend-builder /build/build ./internal/web/dist
# LICENSE_PUBKEY_B64 — base64-encoded Ed25519 public key for AI-license
# verification. When non-empty, injected via -ldflags into
# internal/ai/license.PinnedPublicKeyB64. When empty (default), the
# binary keeps the placeholder sentinel and license.IsPlaceholder() is
# true at runtime — main.go logs a loud WARN at startup and any AI-
# licensed feature fails closed. This intentional split keeps local
# `docker build` (and PR CI) working without secrets, while the tagged-
# release workflow validates the secret is set and refuses to build
# without it (see .github/workflows/release.yml).
ARG LICENSE_PUBKEY_B64=
RUN LDFLAGS="-s -w" && \
    if [ -n "$LICENSE_PUBKEY_B64" ]; then \
      LDFLAGS="$LDFLAGS -X github.com/net4n6-dev/cipherflag/internal/ai/license.PinnedPublicKeyB64=$LICENSE_PUBKEY_B64"; \
    fi && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="$LDFLAGS" -o cipherflag ./cmd/cipherflag/

# Stage 3: Runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=go-builder /build/cipherflag .
COPY config/cipherflag.toml ./config/
COPY internal/store/migrations ./internal/store/migrations
EXPOSE 8443
ENTRYPOINT ["./cipherflag"]
CMD ["serve"]
```

Note the runtime stage no longer copies `frontend/build` — the UI is inside the binary.

- [ ] **Step 2: Build the image**

Run: `docker compose build cipherflag`
Expected: build succeeds through all three stages; no error about a missing `internal/web/dist` embed path.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "build: reorder Docker stages to embed static frontend in binary

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: End-to-end verification

**Files:** none (verification only)

- [ ] **Step 1: Recreate the stack with the new image**

Run:
```bash
cd /Users/Erik/projects/cipherflag
docker compose down
docker compose up -d --build
docker compose ps
```
Expected: `cipherflag-postgres-1` healthy, `cipherflag-cipherflag-1` up, ports `5433->5432` and `8443->8443`.

- [ ] **Step 2: Assert the SPA is served at root**

Run:
```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' http://localhost:8443/
```
Expected: `200 text/html; charset=utf-8`.

- [ ] **Step 3: Assert a deep link returns the SPA shell**

Run:
```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' http://localhost:8443/certificates/deadbeef
```
Expected: `200 text/html; charset=utf-8` (SPA fallback).

- [ ] **Step 4: Assert the API still works and is JSON**

Run:
```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' http://localhost:8443/api/v1/export/cbom
```
Expected: `200 application/json` (or the endpoint's real JSON content-type).

- [ ] **Step 5: Assert unknown API paths return JSON 404, NOT HTML**

Run:
```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' http://localhost:8443/api/v1/bogus
```
Expected: `404 application/json; charset=utf-8`.

- [ ] **Step 6: Assert a real asset is served**

Run:
```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' http://localhost:8443/favicon.ico
```
Expected: `200` with an image content-type (e.g. `image/x-icon` or `image/vnd.microsoft.icon`).

- [ ] **Step 7: Browser smoke**

Open `http://localhost:8443` in a browser. Confirm the dashboard renders (not the placeholder text) and the browser network tab shows `/api/v1/*` calls returning 200 on the same origin.

- [ ] **Step 8: Finalize the branch**

Use the `superpowers:finishing-a-development-branch` skill to decide merge/PR/cleanup for `feat/frontend-embed-serving`.

---

## Notes for the implementer

- **Go version:** `go.mod` declares `go 1.25.6` (local toolchain `go1.26.0`; Docker builder `golang:1.25-alpine`). `http.FileServerFS` (Go 1.22+) and `embed` (Go 1.16+) are both available.
- **API wiring is unchanged:** `frontend/src/lib/api.ts` uses `const BASE = '/api/v1'` (same-origin relative). Do not change fetch call sites.
- **Pre-existing working-tree changes:** `config/cipherflag.toml` and `docker-compose.yml` have uncommitted edits from earlier sessions (the port fixes: postgres `5433:5432`, cipherflag `8443:8443`, toml `postgres_url` → `postgres:5432`). `internal/config/config.go` may also show as modified (listen default reads `8444`). These are unrelated to this plan — do not stage them in these task commits. Commit them separately or carry them along, your call.
- **Branch:** work continues on `feat/frontend-embed-serving` (created during brainstorming; the spec commit `5ff83c0` is its first commit).
- **`@sveltejs/adapter-static` version:** the SvelteKit 2 / Svelte 5 compatible line (3.x). Let `npm install` resolve and record the exact version in the lockfile.
