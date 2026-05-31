# Design: Serve the SvelteKit UI from the Go binary (single `:8443` container)

**Date:** 2026-05-31
**Status:** Approved (pending written-spec review)
**Author:** Erik + Claude

---

## Problem

After the EE→CE 2.x cutover, the CipherFlag CE container starts the API
successfully but **serves no frontend**. `GET /` returns `404 page not
found` while `GET /api/v1/*` returns `200`.

Root cause — three independent gaps, all confirmed:

1. **No frontend-serving code exists in the Go binary.**
   `internal/api/server.go` registers `/healthz` and `/api/v1/*` only —
   no `http.FileServer`, no `//go:embed` of the frontend, no SPA
   catch-all. The chi router has no `NotFound` handler, so unmatched
   paths (including `/`) return chi's default `404 page not found`.

2. **The frontend is built with the wrong adapter for this deployment.**
   `frontend/svelte.config.js` uses `@sveltejs/adapter-node`, which
   emits a Node server bundle (`handler.js`, `index.js`, `server/`,
   `client/`) and deliberately produces **no `index.html`**. Confirmed:
   `find /app/frontend/build -name '*.html'` is empty.

3. **The runtime image cannot run that bundle anyway.** The Dockerfile's
   final stage is `alpine:3.20` with only the Go binary copied in;
   `command -v node` inside the container returns nothing. The
   adapter-node output at `/app/frontend/build` is dead weight — nothing
   serves it and nothing can.

In EE this was Layer 8's job (the production operator UX), which the
README lists as EE-only. CE shipped the API plus a frontend build with
no bridge between them. The `ff99e14` commit that set adapter-node was a
*build* fix (adapter-auto failed to build), not a serving decision; the
`vite.config.ts` dev proxy `/api → localhost:8443` confirms the frontend
was only ever developed against a separate dev server.

## Goals

- The single `cipherflag` container serves both the SPA and the API on
  one origin (`:8443`).
- Deep links and client-side routes (e.g.
  `/certificates/<fingerprint>`) resolve on refresh.
- Unknown API paths return JSON `404`, never the HTML shell.
- `go build ./...` continues to compile from a clean checkout (no
  frontend build required to compile the Go code).

## Non-goals

- Server-side rendering. The frontend is a pure client-side SPA (zero
  `+page.server.*` / `+server.*` / `+layout.server.*` files, zero form
  actions, zero server `load`). SSR is not needed and is explicitly
  disabled.
- Restoring EE Layer 8 operator UX. This serves the existing CE demo
  frontend, nothing more.
- Any change to how the frontend calls the API. `src/lib/api.ts`
  already uses `const BASE = '/api/v1'` (same-origin relative); 15
  relative `/api/v1` call sites, 0 absolute `:8443` references. Once the
  UI is same-origin with the API, fetches resolve unchanged.

## Confirmed facts (inputs to this design)

- Go module path: `github.com/net4n6-dev/cipherflag`
- Router: `github.com/go-chi/chi/v5 v5.2.5`; `NewRouter` returns the
  chi router at `internal/api/server.go:287`.
- Existing embed idiom in repo: `//go:embed migrations/*.sql` in
  `internal/store/postgres.go`.
- SvelteKit static output includes a `_app/` directory, so the embed
  directive must use the `all:` prefix (Go's `embed` skips files and
  directories whose names begin with `_` or `.` unless `all:` is used).
- Frontend routes: 11 `+page.svelte`, one dynamic route
  `certificates/[fingerprint]`.
- `docker-compose.yml` already publishes `8443:8443` (fixed in an
  earlier session) — no further compose change needed.

## Chosen approach

**Embed the static SPA into the Go binary (`//go:embed`)** and serve it
via a **path-aware catch-all** registered as the chi `NotFound` handler.

Rationale: a single self-contained binary matches the repo's existing
`//go:embed migrations/*.sql` idiom, removes the runtime path/volume
dependency that already caused config drift in this project, and is the
cleanest artifact to smoke-test. Considered and rejected: serving from
disk via `http.FileServer` over a copied `/app/frontend/build` — it
reintroduces a runtime path dependency and a COPY/volume to keep in
sync.

---

## Design

### 1. Frontend — swap adapter-node → adapter-static (SPA mode)

`frontend/svelte.config.js`:

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

- `fallback: 'index.html'` emits the SPA shell so the dynamic route
  `certificates/[fingerprint]` and deep-link refreshes resolve
  client-side.
- `strict: false` prevents the build erroring on the un-prerendered
  dynamic route.

`frontend/src/routes/+layout.ts` (new file):

```js
export const ssr = false;
export const prerender = false;
```

Forces pure client-side rendering; all data is fetched at runtime
through `src/lib/api.ts`.

`frontend/package.json`:

- Add `@sveltejs/adapter-static` to `devDependencies`.
- Remove `@sveltejs/adapter-node` (no longer used).
- `@sveltejs/adapter-auto` may remain or be removed; it is unused by the
  config either way. (Leave it to minimize churn.)

Build output remains `frontend/build/` (SvelteKit default), now
containing `index.html`, `_app/`, and static assets — no Node bundle.

**No changes to `src/lib/api.ts` or any fetch call site.**

### 2. New package `internal/web/`

Mirrors the existing `//go:embed` idiom.

`internal/web/web.go`:

```go
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the embedded SPA with a
// path-aware fallback:
//   - /api/* that reaches here is unmatched by the API router → JSON 404
//   - an embedded file that exists (e.g. /_app/…, /favicon.ico) → that file
//   - anything else → 200 + index.html (SPA shell), so client-side
//     routing and deep-link refresh work.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("web: embedded dist missing: " + err.Error())
	}
	fileServer := http.FileServerFS(sub)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API paths must never receive the HTML shell.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
			return
		}

		// Serve a real embedded file when one exists.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if f, err := sub.Open(p); err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		// SPA fallback.
		serveIndex(w, r, sub)
	})
}
```

`serveIndex` reads `index.html` from the sub-FS and writes it with
`Content-Type: text/html` and `200`. (Implementation detail left to the
plan; it must set status 200 even though the requested path did not
exist, which is why we cannot use `http.ServeFileFS` with the original
path.)

`internal/web/dist/index.html` (committed placeholder):

```html
<!doctype html>
<title>CipherFlag</title>
<body>frontend not built — run the frontend build (see Dockerfile)</body>
```

The placeholder keeps `go build ./...` compiling from a clean source
checkout when no frontend build has been produced. The real build
overwrites `internal/web/dist/` contents. `internal/web/dist/` is git-
tracked only for the placeholder; built assets are gitignored (see §6).

### 3. Router integration — `internal/api/server.go`

Add to imports:

```go
"github.com/net4n6-dev/cipherflag/internal/web"
```

Immediately before `return r` at the end of `NewRouter` (currently
line 287):

```go
// SPA catch-all. Registered last so all /api/v1 and /healthz routes
// take precedence; unmatched /api/* still gets a JSON 404 from the
// handler, everything else gets the embedded SPA shell.
r.NotFound(web.Handler().ServeHTTP)
```

chi routing precedence: explicitly registered routes win; only truly
unmatched paths fall to `NotFound`. So `/api/v1/export/cbom` still hits
its handler, `/api/v1/bogus` falls through to the JSON-404 branch, and
`/`, `/certificates/<fp>`, `/_app/...` get the SPA handler.

### 4. Dockerfile — reorder so the embed sees the build

Embed requires the frontend output present **before** `go build`. New
stage order:

1. **frontend-builder** (`node:22-alpine`): `npm ci` + `npm run build`
   → `frontend/build`.
2. **go-builder** (`golang:1.25-alpine`):
   `COPY --from=frontend-builder /build/build ./internal/web/dist`
   (placing the static output where `//go:embed all:dist` expects it),
   then `go build`. The binary now contains the UI.
3. **runtime** (`alpine:3.20`): copy only the Go binary. The previous
   `COPY --from=frontend-builder /build/build ./frontend/build` line is
   **removed** — the UI lives inside the binary now.

The `LICENSE_PUBKEY_B64` ldflags logic and migrations COPY are
unchanged. `EXPOSE 8443`, `ENTRYPOINT ["./cipherflag"]`,
`CMD ["serve"]` unchanged.

`docker-compose.yml`: no change (already `8443:8443`).

### 5. Testing & verification

**Go unit test** (`internal/web/web_test.go`): construct the handler
against a small test `fs.FS` (or exercise the real embedded FS) and
assert:

| Request | Expected |
|---|---|
| `GET /` | 200, `Content-Type: text/html` |
| `GET /certificates/abc123` | 200, HTML (SPA fallback) |
| `GET /favicon.ico` (exists) | 200, asset bytes |
| `GET /api/v1/bogus` | 404, `Content-Type: application/json` (**not** HTML) |

**Manual smoke** after `docker compose up -d --build`:

```bash
B=http://localhost:8443
curl -sS -i $B/                     | head -1   # HTTP/1.1 200 OK + text/html
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' $B/api/v1/export/cbom   # 200 application/json
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' $B/api/v1/bogus         # 404 application/json
```

Then open `http://localhost:8443` in a browser: confirm the dashboard
renders and populates from the API (network tab shows `/api/v1/*`
returning 200 on the same origin).

### 6. Repo hygiene

`.gitignore`: ignore the built static output but keep the placeholder:

```
internal/web/dist/*
!internal/web/dist/index.html
```

This guarantees a clean `go build ./...` from source (placeholder
present) while keeping generated assets out of git.

---

## Build/run order summary

- **Local `go build ./...`**: compiles against the committed placeholder
  `index.html`. Binary runs; UI shows the placeholder until a real
  frontend build is dropped into `internal/web/dist/`.
- **`docker compose up --build`**: frontend builds first, output is
  copied into `internal/web/dist/` before `go build`, binary embeds the
  real UI.
- **Local full UI from source** (optional dev path): `cd frontend &&
  npm run build && cp -r build/* ../internal/web/dist/ && go build
  ./cmd/cipherflag` — or just use the dev server (`npm run dev`, proxied
  to `:8443`).

## Risks / open considerations

- **`http.FileServerFS` / `http.ServeFileFS` require Go 1.16+ for embed
  and Go 1.22+ for `FileServerFS`.** The toolchain is Go 1.25, so both
  are available.
- **Caching headers**: `http.FileServerFS` sets `Last-Modified` from the
  embedded FS (zero-time for embedded files). Acceptable for the CE demo
  UI; immutable `_app/` assets are content-hashed by SvelteKit so stale
  caching is not a correctness risk. Not optimizing further (YAGNI).
- **Placeholder shipped in a release binary**: only happens if the
  Docker build's frontend stage is bypassed, which the staged build
  prevents. The unit test does not guard against an empty real build;
  the manual smoke step does.

## Files touched

| File | Change |
|---|---|
| `frontend/svelte.config.js` | adapter-node → adapter-static (SPA) |
| `frontend/src/routes/+layout.ts` | new — `ssr=false`, `prerender=false` |
| `frontend/package.json` | add adapter-static, drop adapter-node |
| `internal/web/web.go` | new — embed + path-aware handler |
| `internal/web/web_test.go` | new — handler unit tests |
| `internal/web/dist/index.html` | new — committed placeholder |
| `internal/api/server.go` | add `web` import + `r.NotFound(...)` |
| `Dockerfile` | reorder stages; drop runtime frontend COPY |
| `.gitignore` | ignore built dist, keep placeholder |
