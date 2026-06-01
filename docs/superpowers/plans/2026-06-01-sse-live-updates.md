# CipherFlag CE SSE Live-Update Layer Implementation Plan (Phase 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore CipherFlag CE's real-time event stream (Postgres LISTEN/NOTIFY → Go hub → browser EventSource) so the TopBar connection dot goes live and the dashboard auto-refreshes when assets are discovered or re-scored.

**Architecture:** Port EE's `internal/sse` package verbatim (hub + handler + listener), add a Postgres trigger migration that `pg_notify`s on the asset tables CE already writes (so no app publish-calls are needed), wire the `/events/stream` route + hub/listener startup, and port a self-contained frontend EventSource client that drives the TopBar dot and the dashboard's debounced refresh.

**Tech Stack:** Go 1.25 (chi, pgx/v5, zerolog — all already in go.mod), Postgres LISTEN/NOTIFY, SvelteKit 2 / Svelte 5 runes (`$state`/`$effect`), native `EventSource`.

**Spec:** `docs/superpowers/specs/2026-06-01-sse-live-updates-design.md`
**Branch:** `feat/ce-sse-live-updates` (already created off `main`; spec already committed at HEAD).

---

## Pre-flight (read once)

- **Repos:** CE = `/Users/Erik/projects/cipherflag` (branch `feat/ce-sse-live-updates`). EE source-of-truth (read-only) = `/Users/Erik/projects/cipherflag-EE`.
- **The publish seam already exists.** CE's `UpsertCertificate` INSERTs `certificates`; the scoring dispatcher's `SaveAssetHealthReport` INSERT…ON CONFLICT DO UPDATEs `asset_health_reports`. The triggers fire on those existing writes — NO Go publish-calls are added to app code.
- **Deps present:** `github.com/jackc/pgx/v5 v5.8.0` and `github.com/rs/zerolog v1.34.0` are already in CE go.mod. No new Go deps. No new npm deps (plain EventSource).
- **Auth works verbatim for EventSource** — CE auth is cookie-based (`cipherflag_token`, `Path:/`, `SameSite=Strict`), `fetchJSON` uses bare same-origin fetch, so a same-origin `EventSource('/api/v1/events/stream')` auto-sends the cookie. Register the route inside the authed group (no token-in-query, no public route).
- **Column names verified** (no port-blocking gaps): certificates has `fingerprint_sha256` + `source_discovery`; ssh_keys/crypto_libraries have `id` + `host_id` + `source`; asset_health_reports has `asset_type`+`asset_id`+`grade`+`score`+`pqc_status`. The cert trigger MUST use `NEW.source_discovery` (CE's column), NOT `NEW.source`.
- **Frontend import path:** CE has a FLAT `frontend/src/lib/api.ts` and NO `$lib/api/` directory. To avoid ambiguity, the ported events client goes at **`frontend/src/lib/events.svelte.ts`** (a flat sibling), with the 6 event interfaces **inlined at the top** (EE's `import … from './types'` is removed). Consumers import `from '$lib/events.svelte'`.
- **Migration mechanism:** `//go:embed migrations/*.sql`, `sort.Strings` (filename-sorted), tracked by filename, idempotent. New file: `v2.2.0_sse_event_triggers.sql` (sorts after `v2.0_baseline.sql` + `v2.1.0_venafi_push.sql`).
- **adapter-static / Go embed:** `go build ./...` must stay green; `cd frontend && npm run build` must keep emitting `build/index.html`.
- **Flaky bash:** if a command returns empty, re-run or redirect to a file and read it. Quote the real `git log -1 --format='%h %s'` for SHAs.
- **Do NOT** `git add -A` — untracked `docs/`, `.claude/`, `research/` dirs must not be committed. Stage explicit paths.
- **Out of scope:** the 3D constellation SSE `$effect` consumer (Phase 3); scan/briefing/external-source triggers + consumers.

---

## File manifest

| Path | Action | Responsibility |
|---|---|---|
| `internal/sse/hub.go` | create (port + header) | in-memory broadcaster |
| `internal/sse/handler.go` | create (port + header) | text/event-stream handler |
| `internal/sse/listener.go` | create (port + header) | pg LISTEN → hub.Publish |
| `internal/sse/hub_test.go` | create (port + header) | hub unit tests |
| `internal/store/migrations/v2.2.0_sse_event_triggers.sql` | create | cf_notify_event + 4 asset triggers |
| `internal/api/server.go` | modify | NewRouter sseHub param; register /events/stream; comment |
| `cmd/cipherflag/main.go` | modify | sse import; hub/listener startup; thread sseHub into NewRouter |
| `frontend/src/lib/events.svelte.ts` | create (port, types inlined) | EventSource client + sseState + on* registrars |
| `frontend/src/routes/+layout.svelte` | modify | connect()/disconnect(); sseConnected={sseState.connected} |
| `frontend/src/routes/+page.svelte` | modify | extract loadData(); $effect debounced refresh |

Tasks ordered so the project builds + tests green after each.

---

## Task 1: Port the `internal/sse` Go package

**Files:**
- Create: `internal/sse/hub.go`, `internal/sse/handler.go`, `internal/sse/listener.go`, `internal/sse/hub_test.go`

Each file = CE Apache header (the 13-line `// Copyright 2026 net4n6-dev` block used across CE) + EE's verbatim content. Import paths already match (`github.com/net4n6-dev/cipherflag/...`); these files have no internal-package imports anyway.

- [ ] **Step 1: Create `internal/sse/hub.go`**

CE Apache header, then:
```go
package sse

import (
	"encoding/json"
	"sync"
	"time"
)

// Event is the envelope for all SSE events.
type Event struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
}

// Client represents a connected SSE consumer.
type Client struct {
	Events chan Event
}

// Hub manages SSE client connections and fans out events.
type Hub struct {
	clients    map[*Client]struct{}
	mu         sync.RWMutex
	broadcast  chan Event
	register   chan *Client
	unregister chan *Client
}

const clientBufferSize = 64

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]struct{}),
		broadcast:  make(chan Event, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

func (h *Hub) Register() *Client {
	c := &Client{Events: make(chan Event, clientBufferSize)}
	h.register <- c
	return c
}

func (h *Hub) Unregister(c *Client) {
	h.unregister <- c
}

func (h *Hub) Publish(evt Event) {
	h.broadcast <- evt
}

// Run is the main event loop. Start in a goroutine: go hub.Run()
func (h *Hub) Run() {
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = struct{}{}
			h.mu.Unlock()

		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.Events)
			}
			h.mu.Unlock()

		case evt := <-h.broadcast:
			h.mu.RLock()
			for c := range h.clients {
				select {
				case c.Events <- evt:
				default:
					// Slow client — drop event
				}
			}
			h.mu.RUnlock()

		case <-heartbeat.C:
			hb := Event{
				Type:      "heartbeat",
				Timestamp: time.Now(),
			}
			h.mu.RLock()
			for c := range h.clients {
				select {
				case c.Events <- hb:
				default:
				}
			}
			h.mu.RUnlock()
		}
	}
}
```

- [ ] **Step 2: Create `internal/sse/handler.go`**

CE Apache header, then:
```go
package sse

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

// NewHandler returns an HTTP handler that streams SSE events from the hub.
func NewHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			log.Error().Str("path", r.URL.Path).Msg("sse: hub is nil")
			http.Error(w, "sse hub unavailable", http.StatusInternalServerError)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			log.Error().
				Str("path", r.URL.Path).
				Str("writer_type", fmt.Sprintf("%T", w)).
				Msg("sse: response writer does not implement Flusher")
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		flusher.Flush()

		client := hub.Register()
		defer hub.Unregister(client)

		ctx := r.Context()
		for {
			select {
			case evt, ok := <-client.Events:
				if !ok {
					return
				}
				data, err := json.Marshal(evt.Data)
				if err != nil || evt.Data == nil {
					data = []byte("{}")
				}
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, string(data))
				flusher.Flush()
			case <-ctx.Done():
				return
			}
		}
	}
}
```

- [ ] **Step 3: Create `internal/sse/listener.go`**

CE Apache header, then:
```go
package sse

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

// StartListener connects to PostgreSQL, LISTENs on cipherflag_events,
// and publishes received notifications to the hub. Blocks until ctx is cancelled.
// Reconnects with exponential backoff on connection loss.
func StartListener(ctx context.Context, connString string, hub *Hub, logger zerolog.Logger) {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		err := listenLoop(ctx, connString, hub, logger)
		if ctx.Err() != nil {
			return // context cancelled, shut down
		}
		logger.Warn().Err(err).Dur("backoff", backoff).Msg("SSE listener disconnected, reconnecting")
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func listenLoop(ctx context.Context, connString string, hub *Hub, logger zerolog.Logger) error {
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, "LISTEN cipherflag_events")
	if err != nil {
		return err
	}
	logger.Info().Msg("SSE listener connected, listening on cipherflag_events")

	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}

		var evt Event
		if err := json.Unmarshal([]byte(notification.Payload), &evt); err != nil {
			logger.Warn().Err(err).Str("payload", notification.Payload).Msg("invalid SSE event payload")
			continue
		}
		hub.Publish(evt)
	}
}
```

- [ ] **Step 4: Create `internal/sse/hub_test.go`**

CE Apache header, then:
```go
package sse

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHub_PublishToRegisteredClient(t *testing.T) {
	h := NewHub()
	go h.Run()

	c := h.Register()
	defer h.Unregister(c)

	evt := Event{
		Type:      "asset.discovered",
		Data:      json.RawMessage(`{"asset_type":"certificate"}`),
		Timestamp: time.Now(),
	}
	h.Publish(evt)

	select {
	case got := <-c.Events:
		if got.Type != "asset.discovered" {
			t.Errorf("expected type asset.discovered, got %s", got.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestHub_UnregisteredClientDoesNotReceive(t *testing.T) {
	h := NewHub()
	go h.Run()

	c := h.Register()
	h.Unregister(c)

	// Give hub time to process unregister
	time.Sleep(50 * time.Millisecond)

	evt := Event{
		Type:      "test",
		Data:      json.RawMessage(`{}`),
		Timestamp: time.Now(),
	}
	h.Publish(evt)

	select {
	case evt, ok := <-c.Events:
		if ok {
			t.Fatalf("unregistered client should not receive events, got %+v", evt)
		}
		// Channel was closed cleanly — expected
	case <-time.After(100 * time.Millisecond):
		// expected — no event received
	}
}

func TestHub_SlowClientDropsEvents(t *testing.T) {
	h := NewHub()
	go h.Run()

	c := h.Register()
	defer h.Unregister(c)

	// Fill the buffer (capacity 64)
	for i := 0; i < 100; i++ {
		h.Publish(Event{
			Type:      "flood",
			Data:      json.RawMessage(`{}`),
			Timestamp: time.Now(),
		})
	}

	// Give the hub goroutine time to process
	time.Sleep(100 * time.Millisecond)

	// Drain what we can — should be <= 64
	count := 0
	for {
		select {
		case <-c.Events:
			count++
		default:
			goto done
		}
	}
done:
	if count > 64 {
		t.Errorf("expected at most 64 buffered events, got %d", count)
	}
}
```

- [ ] **Step 5: Build + test + fmt**

Run: `cd /Users/Erik/projects/cipherflag && go build ./internal/sse/ 2>&1 | tail -10 && echo SSE-BUILD-OK`
Expected: SSE-BUILD-OK. (`min` is a Go 1.21+ builtin — CE is on 1.25, so `min(backoff*2, maxBackoff)` compiles.)
Run: `go test ./internal/sse/ 2>&1 | tail -10`
Expected: 3 tests PASS.
Run: `gofmt -l internal/sse/*.go`
Expected: empty. If any listed, `gofmt -w internal/sse/<file>.go`.

- [ ] **Step 6: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add internal/sse/hub.go internal/sse/handler.go internal/sse/listener.go internal/sse/hub_test.go
git commit -m "feat(sse): port SSE hub + handler + listener package

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 2: Add the pg_notify trigger migration

**Files:**
- Create: `internal/store/migrations/v2.2.0_sse_event_triggers.sql`

Asset events only (4 triggers). Idempotent (`CREATE OR REPLACE`). The cert trigger reads `NEW.source_discovery` (CE's column); ssh/library read `NEW.source`; asset_health_reports maps `NEW.score` → payload key `risk_score`. Channel `cipherflag_events`, function param type `JSON`.

- [ ] **Step 1: Create the migration file**

Create `internal/store/migrations/v2.2.0_sse_event_triggers.sql`:
```sql
-- v2.2.0_sse_event_triggers.sql
-- Restore the SSE event stream's publish side: pg_notify triggers on the asset
-- tables. The Go listener (internal/sse) LISTENs on 'cipherflag_events' and fans
-- notifications to connected EventSource clients. Asset events only
-- (certificates/ssh_keys/crypto_libraries -> asset.discovered, asset_health_reports
-- -> asset.scored); scan/briefing/external-source triggers are intentionally omitted.

-- cf_notify_event takes JSON (trigger call sites pass json_build_object(...) which
-- is json, not jsonb — no implicit cast exists).
DROP FUNCTION IF EXISTS cf_notify_event(TEXT, JSONB);
CREATE OR REPLACE FUNCTION cf_notify_event(event_type TEXT, payload JSON) RETURNS void AS $$
BEGIN
  PERFORM pg_notify('cipherflag_events', json_build_object(
    'type', event_type,
    'data', payload,
    'timestamp', NOW()
  )::text);
END $$ LANGUAGE plpgsql;

-- Certificate insert -> asset.discovered (CE column is source_discovery, not source)
CREATE OR REPLACE FUNCTION notify_cert_discovered() RETURNS trigger AS $$
BEGIN
  PERFORM cf_notify_event('asset.discovered', json_build_object(
    'asset_type', 'certificate',
    'asset_id', NEW.fingerprint_sha256,
    'source', NEW.source_discovery
  ));
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER cert_discovered_trigger
  AFTER INSERT ON certificates
  FOR EACH ROW EXECUTE FUNCTION notify_cert_discovered();

-- SSH key insert -> asset.discovered
CREATE OR REPLACE FUNCTION notify_ssh_key_discovered() RETURNS trigger AS $$
BEGIN
  PERFORM cf_notify_event('asset.discovered', json_build_object(
    'asset_type', 'ssh_key',
    'asset_id', NEW.id,
    'host_id', NEW.host_id,
    'source', NEW.source
  ));
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER ssh_key_discovered_trigger
  AFTER INSERT ON ssh_keys
  FOR EACH ROW EXECUTE FUNCTION notify_ssh_key_discovered();

-- Crypto library insert -> asset.discovered
CREATE OR REPLACE FUNCTION notify_library_discovered() RETURNS trigger AS $$
BEGIN
  PERFORM cf_notify_event('asset.discovered', json_build_object(
    'asset_type', 'crypto_library',
    'asset_id', NEW.id,
    'host_id', NEW.host_id,
    'source', NEW.source
  ));
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER library_discovered_trigger
  AFTER INSERT ON crypto_libraries
  FOR EACH ROW EXECUTE FUNCTION notify_library_discovered();

-- Asset health report upsert -> asset.scored
-- asset_health_reports uses 'score' (not 'risk_score'); payload key kept as
-- 'risk_score' for API stability but mapped from the actual 'score' column.
CREATE OR REPLACE FUNCTION notify_asset_scored() RETURNS trigger AS $$
BEGIN
  PERFORM cf_notify_event('asset.scored', json_build_object(
    'asset_type', NEW.asset_type,
    'asset_id', NEW.asset_id,
    'grade', NEW.grade,
    'risk_score', NEW.score,
    'pqc_status', NEW.pqc_status
  ));
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER asset_scored_trigger
  AFTER INSERT OR UPDATE ON asset_health_reports
  FOR EACH ROW EXECUTE FUNCTION notify_asset_scored();
```

- [ ] **Step 2: Verify the file embeds + the project builds**

Run: `cd /Users/Erik/projects/cipherflag && go build ./... 2>&1 | tail -10 && echo GO-BUILD-OK`
Expected: GO-BUILD-OK (the migration is `//go:embed`'d by the store package; a syntactically-present `.sql` file just embeds — SQL is validated at runtime/Task 7).
Run: `ls internal/store/migrations/ | sort`
Expected: `v2.0_baseline.sql`, `v2.1.0_venafi_push.sql`, `v2.2.0_sse_event_triggers.sql` — confirm the new file sorts LAST (so it applies after the baseline + venafi, never before the tables exist).

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add internal/store/migrations/v2.2.0_sse_event_triggers.sql
git commit -m "feat(store): add pg_notify triggers for SSE asset events

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 3: Wire the backend (route + hub/listener startup)

**Files:**
- Modify: `internal/api/server.go`
- Modify: `cmd/cipherflag/main.go`

Both files change together (adding a param to `NewRouter` forces updating its caller in main.go), so they're one task to keep the build green.

- [ ] **Step 1: server.go — add the sse import**

In `internal/api/server.go`, in the internal-package import group (after `.../internal/ingest/osquery`, before `.../internal/store`), add:
```go
	"github.com/net4n6-dev/cipherflag/internal/sse"
```

- [ ] **Step 2: server.go — add the sseHub param to NewRouter**

Change the `NewRouter` signature (currently ends `scorer scoring.Scorer,`) to append `sseHub *sse.Hub`:
```go
func NewRouter(
	st store.CryptoStore,
	cfg *config.Config,
	cfgPath string,
	frontendURL string,
	jwtSecret []byte,
	cache observcache.ObservationCache,
	scorer scoring.Scorer,
	sseHub *sse.Hub,
) http.Handler {
```

- [ ] **Step 3: server.go — register the route inside the authed group**

Inside the authed `r.Group(func(r chi.Router) { ... })` (the one that begins with `r.Use(middleware.Auth(st, jwtSecret))`), add this line near the other top-level `r.Get` routes (e.g. right after the `/pki/tree` + `/graph/*` block, at the 3-tab indent):
```go
			// SSE live-update event stream
			r.Get("/events/stream", sse.NewHandler(sseHub))
```

- [ ] **Step 4: server.go — update the stripped-wiring doc comment**

Find the NewRouter doc comment and remove `SSE event stream` from the stripped list. Change:
```go
// network targets, teams, external sources, rank review, PQC migration
// planner, evidence export, agency OMB, SSE event stream) has been
// stripped. The Layer 0/1/2/4/5/6.1a-c surface remains, including the
// PKI cert-graph landscape views (/graph/*).
```
to:
```go
// network targets, teams, external sources, rank review, PQC migration
// planner, evidence export, agency OMB) has been stripped. The Layer
// 0/1/2/4/5/6.1a-c surface remains, including the PKI cert-graph
// landscape views (/graph/*) and the SSE live-update stream (/events/stream).
```

- [ ] **Step 5: main.go — add the sse import**

In `cmd/cipherflag/main.go`, in the internal-package import group (after `scanscheduler "github.com/net4n6-dev/cipherflag/internal/scanner/scheduler"`, before `.../internal/store`), add:
```go
	"github.com/net4n6-dev/cipherflag/internal/sse"
```

- [ ] **Step 6: main.go — start the hub + listener and thread it into NewRouter**

In `runServe`, immediately BEFORE the `router := api.NewRouter(...)` line (currently around `jwtSecret := auth.GenerateSecret(...)` then the NewRouter call), add the hub/listener startup (mirrors EE; uses CE's `ctx` + `cfg.Storage.PostgresURL`; `defer sseCancel()` fires on graceful return after `srv.Shutdown`, matching CE's other background workers):
```go
	// SSE hub + PostgreSQL LISTEN goroutine (live-update event stream).
	sseHub := sse.NewHub()
	go sseHub.Run()
	sseCtx, sseCancel := context.WithCancel(ctx)
	defer sseCancel()
	go sse.StartListener(sseCtx, cfg.Storage.PostgresURL, sseHub, log.Logger)
	log.Info().Msg("SSE hub started")
```
Then change the NewRouter call to pass `sseHub` as the final argument:
```go
	router := api.NewRouter(st, cfg, configPath, cfg.Server.FrontendURL, jwtSecret, sharedCache, scorer, sseHub)
```
(`log.Logger` is the package-level zerolog logger already used throughout main.go; `context` is already imported.)

- [ ] **Step 7: Build + vet + fmt**

Run: `cd /Users/Erik/projects/cipherflag && go build ./... 2>&1 | tail -15 && echo GO-BUILD-OK`
Expected: GO-BUILD-OK. If `NewRouter` arg-count mismatch errors, the main.go call (Step 6) and the signature (Step 2) disagree — recheck both have 8 args in the same order.
Run: `go vet ./internal/api/ ./cmd/cipherflag/ ./internal/sse/ 2>&1 | tail -10`
Expected: no issues.
Run: `gofmt -l internal/api/server.go cmd/cipherflag/main.go`
Expected: empty (else `gofmt -w`).
Run: `go test ./internal/api/... ./internal/sse/ 2>&1 | tail -10`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add internal/api/server.go cmd/cipherflag/main.go
git commit -m "feat(api): wire SSE /events/stream route + hub/listener startup

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 4: Port the frontend events client

**Files:**
- Create: `frontend/src/lib/events.svelte.ts`

Self-contained: the 6 event interfaces are inlined at the top (EE's `import … from './types'` is dropped), so this is one flat file resolvable as `$lib/events.svelte` with no `$lib/api/` directory.

- [ ] **Step 1: Create the file**

Create `frontend/src/lib/events.svelte.ts` with EXACTLY this content (6 interfaces inlined, then EE's client verbatim minus the `./types` import):
```ts
// SSE live-update client. Connects to /api/v1/events/stream (same-origin, cookie
// auth) and dispatches typed events to registered callbacks. Singleton module
// state; Svelte 5 runes.

// ── Event payload types (mirror the backend pg_notify payloads) ──────────────

export interface AssetDiscoveredEvent {
	asset_type: string;
	asset_id: string;
	host_id?: string;
	source: string;
}

export interface AssetScoredEvent {
	asset_type: string;
	asset_id: string;
	grade: string;
	risk_score: number;
	pqc_status: string;
}

export interface ScanProgressEvent {
	scan_id: string;
	status: string;
}

export interface ScanCompletedEvent {
	scan_id: string;
	status: string;
	findings_count: number;
	duration_ms?: number;
}

export interface BriefingUpdatedEvent {
	item_count: number;
	max_severity: string;
}

export interface ExternalSourceScanCompletedEvent {
	source_id: string;
	kind: string;
	status: 'ok' | 'partial' | 'error';
	last_scan_at: string; // ISO8601
}

// ── Reactive state ──────────────────────────────────────────────────────────

export const sseState: { connected: boolean; reconnecting: boolean } = $state({
	connected: false,
	reconnecting: false,
});

// ── Callback registrations ──────────────────────────────────────────────────

type Callback<T> = (data: T) => void;
type Unsubscribe = () => void;

const assetDiscoveredCbs = new Set<Callback<AssetDiscoveredEvent>>();
const assetScoredCbs = new Set<Callback<AssetScoredEvent>>();
const scanProgressCbs = new Set<Callback<ScanProgressEvent>>();
const scanCompletedCbs = new Set<Callback<ScanCompletedEvent>>();
const briefingUpdatedCbs = new Set<Callback<BriefingUpdatedEvent>>();
const externalSourceScanCompletedCbs = new Set<Callback<ExternalSourceScanCompletedEvent>>();

export function onAssetDiscovered(cb: Callback<AssetDiscoveredEvent>): Unsubscribe {
	assetDiscoveredCbs.add(cb);
	return () => { assetDiscoveredCbs.delete(cb); };
}

export function onAssetScored(cb: Callback<AssetScoredEvent>): Unsubscribe {
	assetScoredCbs.add(cb);
	return () => { assetScoredCbs.delete(cb); };
}

export function onScanProgress(cb: Callback<ScanProgressEvent>): Unsubscribe {
	scanProgressCbs.add(cb);
	return () => { scanProgressCbs.delete(cb); };
}

export function onScanCompleted(cb: Callback<ScanCompletedEvent>): Unsubscribe {
	scanCompletedCbs.add(cb);
	return () => { scanCompletedCbs.delete(cb); };
}

export function onBriefingUpdated(cb: Callback<BriefingUpdatedEvent>): Unsubscribe {
	briefingUpdatedCbs.add(cb);
	return () => { briefingUpdatedCbs.delete(cb); };
}

export function onExternalSourceScanCompleted(cb: Callback<ExternalSourceScanCompletedEvent>): Unsubscribe {
	externalSourceScanCompletedCbs.add(cb);
	return () => { externalSourceScanCompletedCbs.delete(cb); };
}

// ── Connection management ───────────────────────────────────────────────────

let eventSource: EventSource | null = null;
let reconnectAttempts = 0;
let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
let heartbeatTimer: ReturnType<typeof setTimeout> | undefined;
let visibilityTimer: ReturnType<typeof setTimeout> | undefined;

const MAX_BACKOFF_MS = 30_000;
const HEARTBEAT_TIMEOUT_MS = 60_000;
const VISIBILITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

function resetHeartbeat(): void {
	clearTimeout(heartbeatTimer);
	heartbeatTimer = setTimeout(() => {
		// No event for 60s — force reconnect
		closeEventSource();
		scheduleReconnect();
	}, HEARTBEAT_TIMEOUT_MS);
}

function dispatchToCallbacks(type: string, data: unknown): void {
	switch (type) {
		case 'asset.discovered':
			assetDiscoveredCbs.forEach((cb) => cb(data as AssetDiscoveredEvent));
			break;
		case 'asset.scored':
			assetScoredCbs.forEach((cb) => cb(data as AssetScoredEvent));
			break;
		case 'scan.progress':
			scanProgressCbs.forEach((cb) => cb(data as ScanProgressEvent));
			break;
		case 'scan.completed':
			scanCompletedCbs.forEach((cb) => cb(data as ScanCompletedEvent));
			break;
		case 'briefing.updated':
			briefingUpdatedCbs.forEach((cb) => cb(data as BriefingUpdatedEvent));
			break;
		case 'external_source.scan.completed':
			externalSourceScanCompletedCbs.forEach((cb) => cb(data as ExternalSourceScanCompletedEvent));
			break;
	}
}

function createEventSource(): void {
	if (eventSource) return;

	eventSource = new EventSource('/api/v1/events/stream');

	eventSource.onopen = () => {
		sseState.connected = true;
		sseState.reconnecting = false;
		reconnectAttempts = 0;
		resetHeartbeat();
	};

	eventSource.onerror = () => {
		sseState.connected = false;
		closeEventSource();
		scheduleReconnect();
	};

	// Register typed event listeners
	const eventTypes = [
		'asset.discovered',
		'asset.scored',
		'scan.progress',
		'scan.completed',
		'briefing.updated',
		'external_source.scan.completed',
		'heartbeat',
	];

	for (const type of eventTypes) {
		eventSource.addEventListener(type, (e: MessageEvent) => {
			resetHeartbeat();
			if (type === 'heartbeat') return;
			try {
				const data = JSON.parse(e.data);
				dispatchToCallbacks(type, data);
			} catch {
				// Ignore malformed events
			}
		});
	}
}

function closeEventSource(): void {
	clearTimeout(heartbeatTimer);
	if (eventSource) {
		eventSource.close();
		eventSource = null;
	}
	sseState.connected = false;
}

function scheduleReconnect(): void {
	if (reconnectTimer) return;

	sseState.reconnecting = true;
	const backoff = Math.min(
		1000 * Math.pow(2, reconnectAttempts),
		MAX_BACKOFF_MS,
	);
	reconnectAttempts++;

	reconnectTimer = setTimeout(() => {
		reconnectTimer = undefined;
		createEventSource();
	}, backoff);
}

// ── Tab visibility handling ─────────────────────────────────────────────────

function handleVisibilityChange(): void {
	if (typeof document === 'undefined') return;

	if (document.hidden) {
		// Start 5-minute timer to disconnect
		visibilityTimer = setTimeout(() => {
			closeEventSource();
		}, VISIBILITY_TIMEOUT_MS);
	} else {
		// Tab focused — cancel timer and reconnect if needed
		clearTimeout(visibilityTimer);
		if (!eventSource && !reconnectTimer) {
			createEventSource();
		}
	}
}

// ── Public API ──────────────────────────────────────────────────────────────

export function connect(): void {
	if (typeof window === 'undefined') return;
	createEventSource();
	document.addEventListener('visibilitychange', handleVisibilityChange);
}

export function disconnect(): void {
	clearTimeout(reconnectTimer);
	clearTimeout(visibilityTimer);
	reconnectTimer = undefined;
	closeEventSource();
	if (typeof document !== 'undefined') {
		document.removeEventListener('visibilitychange', handleVisibilityChange);
	}
	sseState.reconnecting = false;
}
```

- [ ] **Step 2: Type-check + build**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -8`
Expected: 0 errors in events.svelte.ts. (It's a `.svelte.ts` rune module — `$state` is valid there. Pre-existing warnings elsewhere OK.)
Run: `npm run build 2>&1 | tail -5 && test -f build/index.html && echo BUILD-OK`
Expected: BUILD-OK.

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/events.svelte.ts
git commit -m "feat(ui): add SSE EventSource client (sseState + asset event registrars)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 5: Wire the TopBar live dot

**Files:**
- Modify: `frontend/src/routes/+layout.svelte`

Make the TopBar connection dot reflect the real `sseState.connected`: connect after auth, disconnect on logout, flip the static prop.

- [ ] **Step 1: Add the import**

In `frontend/src/routes/+layout.svelte`, after the existing `import { initTheme } from '$lib/stores/theme.svelte';` line, add:
```svelte
	import { connect as sseConnect, disconnect as sseDisconnect, sseState } from '$lib/events.svelte';
```
(Alias `connect`/`disconnect` to `sseConnect`/`sseDisconnect` to avoid any name ambiguity.)

- [ ] **Step 2: Call connect() on the authenticated onMount path**

In the `onMount` async block, find the authenticated success path where `currentUser = user;` is set and `authChecked = true;` runs at the end. Immediately AFTER the existing line `authChecked = true;` (the one at the very end of onMount, reached only on the authenticated path), add:
```svelte
		sseConnect();
```
So the tail of onMount reads:
```svelte
			currentUser = user;
		} else {
			// Not authenticated — check if users exist
			const status = await checkAuthStatus();
			if (!status.has_users) {
				goto('/setup-admin');
				return;
			}
			goto('/login');
			return;
		}
		authChecked = true;
		sseConnect();
	});
```
(Do NOT call connect on the `/login`//setup-admin early-return path — that one returns before reaching here, which is correct: no stream until authenticated.)

- [ ] **Step 3: Disconnect on logout**

In `handleLogout`, add `sseDisconnect();` before the `await doLogout();` call:
```svelte
	async function handleLogout() {
		sseDisconnect();
		await doLogout();
		currentUser = null;
		goto('/login');
	}
```

- [ ] **Step 4: Flip the sseConnected prop**

Change the `<AppShell>` prop from `sseConnected={false}` to:
```svelte
			sseConnected={sseState.connected}
```

- [ ] **Step 5: Type-check + build**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -8`
Expected: 0 errors in +layout.svelte.
Run: `npm run build 2>&1 | tail -5 && test -f build/index.html && echo BUILD-OK`
Expected: BUILD-OK.

- [ ] **Step 6: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/routes/+layout.svelte
git commit -m "feat(ui): connect SSE on auth + drive TopBar live dot from sseState

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 6: Wire the dashboard debounced auto-refresh

**Files:**
- Modify: `frontend/src/routes/+page.svelte`

Extract the inline `onMount` data load into a callable `loadData()`, then subscribe to `asset.scored`/`asset.discovered` with a 2s debounce.

- [ ] **Step 1: Add the import**

In `frontend/src/routes/+page.svelte`, after the existing `import RadialTree from '$lib/components/dashboard/RadialTree.svelte';` line, add:
```svelte
	import { onAssetScored, onAssetDiscovered } from '$lib/events.svelte';
```

- [ ] **Step 2: Extract `loadData()` and call it from onMount**

Replace the existing `onMount(async () => { try { ... } catch { ... } loading = false; });` block with an extracted `loadData()` plus an onMount that calls it. The current onMount body (the `Promise.all` of 5 calls + assignments + catch + `loading = false`) moves verbatim into `loadData`:
```svelte
	async function loadData() {
		try {
			const [s, iss, pkiData, compliance, crypto] = await Promise.all([
				api.getSummary(),
				api.getIssuers(),
				api.getPKITree(),
				api.getComplianceReport(),
				api.getCryptoPosture(),
			]);
			stats = s;
			issuers = (iss as any).issuers ?? [];
			pki = pkiData;
			complianceScore = compliance.compliance_score;
			complianceByCategory = compliance.by_category ?? {};
			priorities = compliance.remediation_priorities ?? [];
			cryptoAlgos = crypto.key_algorithms ?? [];
			sigAlgos = crypto.signature_algorithms ?? [];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load dashboard';
		}
		loading = false;
	}

	onMount(() => {
		loadData();
	});
```

- [ ] **Step 3: Add the debounced SSE refresh `$effect`**

Immediately after the `onMount(() => { loadData(); });` block, add:
```svelte
	// Live refresh: re-pull dashboard data when assets are scored or discovered.
	// Debounced so a burst of ingest events triggers at most one reload per 2s.
	let refreshTimer: ReturnType<typeof setTimeout> | undefined;
	function scheduleRefresh() {
		clearTimeout(refreshTimer);
		refreshTimer = setTimeout(() => { loadData(); }, 2000);
	}

	$effect(() => {
		const offScored = onAssetScored(scheduleRefresh);
		const offDiscovered = onAssetDiscovered(scheduleRefresh);
		return () => {
			offScored();
			offDiscovered();
			clearTimeout(refreshTimer);
		};
	});
```
(Both event types trigger the same full `loadData()` — simpler than EE's per-panel reloads and correct, since CE's dashboard panels all derive from the 5 calls. The `briefing.updated` subscription is intentionally omitted — no CE briefing.)

- [ ] **Step 4: Type-check + build + run the frontend suite**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -8`
Expected: 0 errors in +page.svelte.
Run: `npm run build 2>&1 | tail -5 && test -f build/index.html && echo BUILD-OK`
Expected: BUILD-OK.
Run: `npx vitest run 2>&1 | tail -8`
Expected: all existing tests still pass (this phase adds no frontend unit tests; confirm no regression).

- [ ] **Step 5: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/routes/+page.svelte
git commit -m "feat(ui): live dashboard refresh on asset.scored/discovered (debounced)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 7: Rebuild container + end-to-end verification

**Files:** none (verification only — no commit unless a defect fix is warranted)

- [ ] **Step 1: Rebuild frontend + image + recreate stack**

Run:
```bash
cd /Users/Erik/projects/cipherflag/frontend && npm run build 2>&1 | tail -3 && test -f build/index.html && echo FE-BUILD-OK
cd /Users/Erik/projects/cipherflag
docker compose build cipherflag 2>&1 | tail -6
docker compose up -d 2>&1 | tail -5
docker compose ps --format '{{.Service}}={{.State}}'
```
Expected: FE-BUILD-OK; image builds; both services running. The cipherflag log should show `SSE hub started` and `SSE listener connected, listening on cipherflag_events`. Check: `docker compose logs cipherflag 2>&1 | grep -i sse | tail -5`. (Docker build takes minutes — generous timeout; re-check `docker compose ps` rather than concluding failure from empty output.)

- [ ] **Step 2: Confirm the migration applied + triggers exist**

Run (psql into the postgres container; adjust the service/db/user names to match docker-compose):
```bash
docker compose exec -T postgres psql -U cipherflag -d cipherflag -c "\df cf_notify_event" 2>&1 | tail -5
docker compose exec -T postgres psql -U cipherflag -d cipherflag -c "SELECT tgname FROM pg_trigger WHERE tgname LIKE '%_discovered_trigger' OR tgname = 'asset_scored_trigger' ORDER BY tgname;" 2>&1 | tail -10
docker compose exec -T postgres psql -U cipherflag -d cipherflag -c "SELECT version FROM schema_migrations ORDER BY version;" 2>&1 | tail -10
```
Expected: `cf_notify_event` function exists; the 4 triggers (`cert_discovered_trigger`, `ssh_key_discovered_trigger`, `library_discovered_trigger`, `asset_scored_trigger`) are present; `v2.2.0_sse_event_triggers.sql` appears in schema_migrations. (If the psql user/db differ, read them from `docker-compose.yml` / the cipherflag env and adjust.)

- [ ] **Step 3: Confirm the stream holds open + heartbeats (auth cookie)**

First obtain an auth cookie (log in via the API, or extract the `cipherflag_token` from a browser session). Then:
```bash
curl -sS -N --max-time 35 -H "Cookie: cipherflag_token=<token>" http://localhost:8443/api/v1/events/stream | head -c 400
```
Expected: the connection holds open (doesn't return immediately); within ~30s a `event: heartbeat` frame appears. A 200 + held connection proves route + auth + handler + hub. (If you can't easily get a cookie, the headless-browser step 5 covers auth-mocked verification of the dot instead; document which path you used.)

- [ ] **Step 4: Trigger a real event end-to-end**

With the stream from Step 3 still open in one terminal, in another insert/ingest a certificate (e.g. via the upload API, or `docker compose exec postgres psql … -c "INSERT INTO certificates (fingerprint_sha256, ...) VALUES (...)"` with the minimal NOT NULL columns). Confirm an `event: asset.discovered` frame with `data: {"asset_type":"certificate","asset_id":"...","source":"..."}` arrives on the open stream. This proves trigger → pg_notify → listener → hub → handler end-to-end. (If a manual INSERT is fiddly due to NOT NULL columns, an upload through the running UI/API is the cleaner trigger.)

- [ ] **Step 5: Screenshot the TopBar dot live + dashboard (headless)**

Use the auth-mocked headless-Chrome / Playwright approach from prior phases. Mock `GET /api/v1/auth/me` → admin user + `GET /api/v1/auth/status` → `{has_users:true}` (context-level, before navigation, 200 + application/json). Let the EventSource hit the real backend (with the auth-mock the connection may or may not authenticate depending on the harness's cookie handling — if the mock prevents a real cookie, the dot may stay grey in headless; in that case ALSO verify the dot logic by confirming `sseState.connected` flips when the real backend stream connects, e.g. via the Step 3 curl proving the backend works + reading the +layout wiring). Navigate to `http://localhost:8443/`, wait, screenshot `/tmp/sse_dashboard.png`; READ it. Confirm: the dashboard renders inside the operator shell; the TopBar SSE dot is present (green = connected if the headless session authenticated, grey = disconnected otherwise — note which, and that the backend stream itself is proven by Steps 3-4).

- [ ] **Step 6: (Optional, if a dev DB is reachable) run the un-orphaned integration test**

Run: `cd /Users/Erik/projects/cipherflag && go test -tags=integration ./internal/store/ -run Trigger 2>&1 | tail -15` against a DB that has the migration applied (the docker postgres, with the right connection env). Expected: `certificates_trigger_test.go`'s `TestUpsertCertificate_NotifyPayloadHasSource` PASSES (it was orphaned; the v2.2.0 migration satisfies it). If the sandbox can't reach the DB, document that this is verified via the container's applied triggers (Step 2) + the live event (Step 4) instead.

- [ ] **Step 7: Report (no commit)**

Report: FE+docker build; `docker compose ps`; the SSE startup log lines; the migration/trigger psql output; the curl stream result (held open + heartbeat); the live `asset.discovered` frame (or how triggered); the dashboard screenshot judgment (dot state, shell renders, no console errors); and the integration-test result (or why deferred). Overall PASS/FAIL for "SSE stream is live end-to-end and the TopBar dot reflects it". Leave the container running for smoke-test.

---

## Notes for the implementer

- **The Go sse package + events client are verbatim ports** — the ONLY changes are CE Apache headers (Go) and inlining the 6 event interfaces + dropping the `./types` import (frontend). Do not refactor.
- **No app publish-calls.** The triggers do all publishing; CE's existing writes fire them. Do not add `hub.Publish` calls anywhere in ingest/scoring.
- **server.go + main.go change together** (the NewRouter param). Keep both in Task 3's single commit so the build never breaks between them.
- **Cert trigger uses `NEW.source_discovery`** (CE's column), not `NEW.source` — this is the one column difference that matters; ssh/library use `NEW.source`.
- **Build gates:** Go tasks end green on `go build ./...` + `go test`; frontend tasks on `svelte-check` 0 errors + `npm run build` emitting `build/index.html`.
- **No push, no merge** without explicit user approval (per `docs/CLAUDE.md`). Branch is local.
- **Flaky bash:** redirect to a file and Read it if output is empty; quote real `git log -1` output for SHAs.
```
