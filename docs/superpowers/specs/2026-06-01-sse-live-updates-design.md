# CipherFlag CE SSE Live-Update Layer — Design Spec (Phase 2)

**Date:** 2026-06-01
**Status:** Approved (brainstorming complete, awaiting spec review → writing-plans)
**Branch:** `feat/ce-sse-live-updates` (off `main`)

## Goal

Restore CipherFlag CE's real-time event stream — Postgres `LISTEN/NOTIFY` → in-memory Go hub → browser `EventSource` — so the operator-shell TopBar connection dot goes live and the dashboard auto-refreshes when assets are discovered or re-scored. This is Phase 2 of the 3-phase PKI/real-time effort (Phase 1 = PKI graph backend, merged; Phase 3 = 3D constellation, deferred).

## Background / current state (verified by code inspection 2026-06-01)

CE's SSE layer was stripped during the open-core port (`internal/api/server.go` doc comment lists "SSE event stream" among stripped EE-only wiring). The stream is a **generic Postgres LISTEN/NOTIFY fan-out** with no EE-proprietary logic — safe to de-moat.

Verified facts:
- **Absent in CE:** no `internal/sse/` package, no `/events/stream` route, no `text/event-stream`/`http.Flusher` handler, no `pg_notify` trigger in CE migrations, no frontend `events.svelte`/`EventSource` client.
- **The seam is intact (no app publish-calls needed):** CE's `UpsertCertificate` (`internal/store/postgres.go:129`) INSERTs into `certificates`; the scoring dispatcher (`internal/analysis/scoring/dispatcher.go`) calls `SaveAssetHealthReport` (INSERT…ON CONFLICT DO UPDATE on `asset_health_reports`). Both write the exact tables the triggers fire on — so **adding triggers alone publishes events**.
- **Tables present in CE** (`internal/store/migrations/v2.0_baseline.sql`): `certificates` (:42, col `source_discovery` :71), `ssh_keys` (:228, col `source` :239), `crypto_libraries` (:271, col `source` :278), `asset_health_reports` (:361, cols `asset_type, asset_id, grade, score, pqc_status` :361-372).
- **Deps already in CE go.mod:** `github.com/jackc/pgx/v5 v5.8.0` (the listener's only dep) and `github.com/rs/zerolog v1.34.0`. The hub/handler are pure stdlib.
- **Auth works verbatim for EventSource (the key feasibility check):** CE's auth middleware (`internal/api/middleware/auth.go`) authenticates browsers via an `HttpOnly` cookie `cipherflag_token` (`internal/auth/jwt.go:29`, `Path:/`, `SameSite=Strict`); `GetTokenFromCookie(r)` at `auth.go:125`. CE's `fetchJSON` (`frontend/src/lib/api.ts:3-9`) is a bare same-origin `fetch` with NO Authorization header and NO token storage anywhere. So a same-origin `EventSource('/api/v1/events/stream')` auto-sends the cookie and authenticates — exactly as EE does (byte-identical middleware; EE's EventSource passes no token/header). The Bearer path (`auth.go:99`) is agent-tokens-only. **No SSE-specific auth work needed.**
- **Orphaned regression test:** CE already carries `internal/store/certificates_trigger_test.go` (`//go:build integration`) that LISTENs on `cipherflag_events` and asserts the cert NOTIFY payload contains `asset.discovered`, the key `source`, and the raw source value (`active_scan`). It currently has no trigger to satisfy; this phase's migration un-orphans it.
- **TopBar dot already exists:** `frontend/src/lib/components/layout/TopBar.svelte` takes `sseConnected: boolean` (:7,:10) and renders `cf-sse-indicator` (:52-55); AppShell threads it; `frontend/src/routes/+layout.svelte:103` currently passes static `sseConnected={false}`.
- **Migration mechanism:** `//go:embed migrations/*.sql`, `sort.Strings(names)` (filename-sorted), tracked by filename in `schema_migrations`, idempotent skip-if-applied. Current files: `v2.0_baseline.sql`, `v2.1.0_venafi_push.sql`. Next filename: **`v2.2.0_sse_event_triggers.sql`** (sorts after both).

### Decisions locked during brainstorming

- **Phase 2 scope:** backend SSE + frontend client + **both** Phase-2 consumers — the TopBar live dot AND the dashboard debounced auto-refresh. (The 3D constellation's SSE `$effect` consumer is Phase 3.)
- **Trigger set:** **asset events only** — 4 triggers (certificates/ssh_keys/crypto_libraries → `asset.discovered`, asset_health_reports → `asset.scored`). Do NOT create scan_jobs/briefing_cache/external_sources triggers (no CE consumers; briefing_cache/external_sources tables don't exist in CE).
- **Stream auth:** **match EE verbatim** — register `/events/stream` inside CE's authed group; rely on the same-origin `cipherflag_token` cookie (verified to work for EventSource). No token-in-query-param, no public route.
- **Port fidelity:** copy the Go sse package and the frontend events client verbatim from EE (adapting only import paths). The 4 unwired event registrars (scan/briefing/external-source) stay in the client but are never fired and have no CE subscribers — harmless, kept for fidelity.
- **No moat crossed:** generic LISTEN/NOTIFY, no `internal/ai`/host-deps/velociraptor/vendor-SDK coupling. The EE-specific surface (external_sources/briefing/AWS-CT discovery events) is excluded simply by not porting those triggers/consumers.

## Architecture

Layers ordered so the project builds + tests green after each:

### Layer 1 — Backend SSE package (verbatim from EE)

Copy `internal/sse/{hub.go, handler.go, listener.go, hub_test.go}` from `/Users/Erik/projects/cipherflag-EE/internal/sse/` to CE (add CE Apache header to each; EE's copies match the module path `github.com/net4n6-dev/cipherflag/...` already). Contents:
- **`hub.go`** — `package sse`. `Event{Type string `json:"type"`; Data json.RawMessage `json:"data"`; Timestamp time.Time `json:"timestamp"`}`, `Client{Events chan Event}`, `Hub`. Funcs `NewHub()`, `(*Hub) Register() *Client`, `Unregister(*Client)`, `Publish(Event)`, `Run()`. Buffers: broadcast 256, per-client 64. 30s server heartbeat. Slow-client policy: non-blocking send, drop on full buffer.
- **`handler.go`** — `NewHandler(hub *Hub) http.HandlerFunc`. Headers `text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`, `X-Accel-Buffering: no`. Wire: `event: <type>\ndata: <json>\n\n` + flush. Nil-data → `{}`; nil-hub / non-Flusher → 500.
- **`listener.go`** — `StartListener(ctx, connString string, hub *Hub, logger zerolog.Logger)`. `pgx.Connect` + `LISTEN cipherflag_events` → `WaitForNotification` → `json.Unmarshal(payload, &Event)` → `hub.Publish`. Exp-backoff reconnect (1s → ×2 → cap 30s); exits on ctx cancel.
- **`hub_test.go`** — 3 unit tests (publish fan-out, unregister closes channel, slow-client drop ≤64). DB-free; runs in the normal suite.

### Layer 2 — Trigger migration (asset events only)

Create `internal/store/migrations/v2.2.0_sse_event_triggers.sql` with the `cf_notify_event` helper (takes `JSON`) + 4 triggers. Final correct form (composited from EE's 019/020/023, only CE's 4 tables):
- `cf_notify_event(event_type TEXT, payload JSON)` → `pg_notify('cipherflag_events', json_build_object('type',event_type,'data',payload,'timestamp',NOW())::text)`.
- `cert_discovered_trigger` AFTER INSERT ON `certificates` → `asset.discovered`, payload `{asset_type:'certificate', asset_id:NEW.fingerprint_sha256, source:NEW.source_discovery}`.
- `ssh_key_discovered_trigger` AFTER INSERT ON `ssh_keys` → `asset.discovered`, payload `{asset_type:'ssh_key', asset_id:NEW.id, host_id:NEW.host_id, source:NEW.source}`.
- `library_discovered_trigger` AFTER INSERT ON `crypto_libraries` → `asset.discovered`, payload `{asset_type:'crypto_library', asset_id:NEW.id, host_id:NEW.host_id, source:NEW.source}`.
- `asset_scored_trigger` AFTER INSERT OR UPDATE ON `asset_health_reports` → `asset.scored`, payload `{asset_type:NEW.asset_type, asset_id:NEW.asset_id, grade:NEW.grade, risk_score:NEW.score, pqc_status:NEW.pqc_status}`.
Use `CREATE OR REPLACE FUNCTION` and `CREATE OR REPLACE TRIGGER` so the migration is idempotent on already-migrated DBs. The cert payload MUST use JSON key `source` carrying the raw `source_discovery` enum value (so the orphaned integration test's `"source"` + `"active_scan"` substring assertions pass).

### Layer 3 — Backend wiring (route + startup)

- `internal/api/server.go`: add `sseHub *sse.Hub` param to `NewRouter`; register `r.Get("/events/stream", sse.NewHandler(sseHub))` inside the authed `r.Group` under `/api/v1` (mirroring EE server.go:456). Update the stripped-wiring doc comment to drop "SSE event stream" from the stripped list.
- `cmd/cipherflag/main.go`: `sseHub := sse.NewHub(); go sseHub.Run()`; start the listener under a cancelable context: `sseCtx, sseCancel := context.WithCancel(ctx); defer sseCancel(); go sse.StartListener(sseCtx, cfg.Storage.PostgresURL, sseHub, log.Logger)`; thread `sseHub` into the `api.NewRouter(...)` call. (CE main.go already imports `context`, has `ctx`, and uses `cfg.Storage.PostgresURL`.)

### Layer 4 — Frontend events client + consumers

- Port EE `frontend/src/lib/api/events.svelte.ts` → CE `frontend/src/lib/api/events.svelte.ts` (a new `$lib/api/` subdir alongside the flat `api.ts`). Svelte 5 runes. Exports `sseState = $state({connected, reconnecting})`, `connect()`, `disconnect()`, and the `on*` registrars (each returns an unsubscribe). URL `/api/v1/events/stream`. Client backoff 1s→cap 30s; 60s heartbeat watchdog; 5-min tab-hidden disconnect.
- **Import-path adaptation:** EE's client does `import type {…} from './types'`. CE has no `$lib/api/types`. Ship a small `frontend/src/lib/api/events-types.ts` (or `$lib/api/types.ts`) carrying just the 6 event interfaces (`AssetDiscoveredEvent{asset_type,asset_id,host_id?,source}`, `AssetScoredEvent{asset_type,asset_id,grade,risk_score:number,pqc_status}`, plus the 4 unused: ScanProgress/ScanCompleted/BriefingUpdated/ExternalSourceScanCompleted) and point the client's import at it. Do NOT entangle with the flat `api.ts`.
- **TopBar dot (consumer 1):** in `frontend/src/routes/+layout.svelte`: import `{connect, disconnect, sseState}`; call `connect()` right after `authChecked = true` in onMount; call `disconnect()` in `handleLogout`; change `sseConnected={false}` → `sseConnected={sseState.connected}`.
- **Dashboard auto-refresh (consumer 2):** in `frontend/src/routes/+page.svelte`: refactor the inline `onMount` `Promise.all` (getSummary/getIssuers/getPKITree/getComplianceReport/getCryptoPosture) into a callable `loadData()` (preserving existing loading/error handling); add an `$effect` subscribing via `onAssetScored`/`onAssetDiscovered` with 2000ms debounce — `asset.scored` → reload summary + compliance; `asset.discovered` → reload summary + pki + issuers; return the unsubscribers as cleanup. Do NOT subscribe to `briefing.updated` (no CE equivalent).

## Data flow

```
asset.discovered:
  UpsertCertificate / ingester INSERT (certificates|ssh_keys|crypto_libraries)
    → AFTER INSERT trigger → cf_notify_event('asset.discovered', {asset_type, asset_id, source[, host_id]})
    → pg_notify('cipherflag_events', {type, data, timestamp})
    → StartListener unmarshal → hub.Publish → handler "event: asset.discovered\ndata: {...}\n\n"
    → events.svelte client → onAssetDiscovered callbacks → dashboard debounced reload

asset.scored:
  scoring dispatcher → SaveAssetHealthReport (INSERT…ON CONFLICT DO UPDATE on asset_health_reports)
    → AFTER INSERT OR UPDATE trigger → cf_notify_event('asset.scored', {asset_type, asset_id, grade, risk_score, pqc_status})
    → … → onAssetScored callbacks → dashboard debounced reload
```
Connection state (`sseState.connected`) drives the TopBar dot independent of any payload.

## Error handling & resilience (all in the verbatim-ported code)

1. **Listener (DB drop):** exp-backoff reconnect (1s→cap 30s), clean exit on ctx cancel. Events emitted while disconnected are lost — acceptable (live nicety, not an event log; data is re-fetched fresh on reconnect).
2. **Hub (slow client):** non-blocking per-client send, drop on full 64-buffer; one slow browser can't stall the hub or others.
3. **Frontend client:** EventSource native reconnect + own backoff + 60s heartbeat watchdog (force-reconnect on silence, pairs with server 30s heartbeat); 5-min tab-hidden disconnect; `sseState` drives the dot honestly.
4. **Auth expiry mid-stream:** reconnect 401s, dot stays grey, reconnects after re-auth — graceful, honest.
5. **Dashboard refresh failure:** the extracted `loadData()` keeps the existing try/catch; a failed refresh leaves last-good data on screen.
6. **No-data:** stream is simply quiet; dot still shows connected (connection healthy). No special empty-state.

## Testing strategy

**Backend unit (no DB, normal suite):** port `hub_test.go` (publish fan-out, unregister, slow-client drop). `go build ./...` + `go vet` green; sse package + tests pass.

**Backend trigger integration (`//go:build integration`, Postgres):** the migration un-orphans `internal/store/certificates_trigger_test.go` — once `v2.2.0` lands, it passes (LISTEN `cipherflag_events`, assert cert NOTIFY payload has `asset.discovered` + `source` + raw value). Verify via `go test -tags=integration ./internal/store/ -run Trigger` against the dev DB (or in-container; document which). Confirm the migration applies cleanly + container starts (filename-sorted, idempotent).

**Frontend:** `svelte-check` 0 errors + `npm run build` emits `build/index.html` are the hard gates. Optionally a light vitest on the extracted `loadData()` callability — but no brittle EventSource-mock test.

**Integration / visual gate (end-to-end):**
- `docker compose build && up`; `curl -N` the stream with an auth cookie → confirm it holds open + 30s heartbeat (route + hub + handler + auth).
- Trigger a real event (ingest/insert a cert) → confirm an `asset.discovered` frame arrives on the open stream (trigger → listener → hub → wire).
- Headless-Chrome (auth-mocked) → TopBar dot goes green; after a simulated scored/discovered, dashboard refreshes. Read the screenshot to confirm dot state + no console errors.

**Out of scope for tests:** hub load/soak; the 4 unwired event types (no CE consumer).

## File manifest

| Path | Action | Responsibility |
|---|---|---|
| `internal/sse/hub.go` | create (port from EE) | in-memory broadcaster |
| `internal/sse/handler.go` | create (port from EE) | text/event-stream HTTP handler |
| `internal/sse/listener.go` | create (port from EE) | pg LISTEN → hub.Publish |
| `internal/sse/hub_test.go` | create (port from EE) | hub unit tests |
| `internal/store/migrations/v2.2.0_sse_event_triggers.sql` | create | cf_notify_event + 4 asset triggers |
| `internal/api/server.go` | modify | NewRouter sseHub param; register /events/stream; comment |
| `cmd/cipherflag/main.go` | modify | NewHub/Run/StartListener; thread sseHub into NewRouter |
| `frontend/src/lib/api/events.svelte.ts` | create (port from EE) | EventSource client + sseState + on* registrars |
| `frontend/src/lib/api/events-types.ts` | create | the 6 event TS interfaces |
| `frontend/src/routes/+layout.svelte` | modify | connect()/disconnect(); sseConnected={sseState.connected} |
| `frontend/src/routes/+page.svelte` | modify | extract loadData(); $effect debounced refresh on scored/discovered |

## Non-goals / out of scope

- **3D constellation SSE consumer** (the `$effect` injecting/re-grading 3D nodes) — Phase 3.
- **scan_jobs / briefing_cache / external_sources triggers + consumers** — no CE tables/consumers; excluded.
- The 4 unused event registrars are ported (fidelity) but not wired to any CE consumer and never fire.
- No changes to ingest/scoring code (the publish seam already exists via DB writes).
- No new npm deps (events client is plain EventSource + Svelte runes).

## References

- `project_ce_v2_strategy` (memory) — open-core de-moat strategy.
- EE source of truth: `/Users/Erik/projects/cipherflag-EE` (`internal/sse/`, migrations 019/020/023, `frontend/src/lib/api/events.svelte.ts`, `server.go:456`, `cmd/cipherflag/main.go:632-639,693`).
- Prior phases: PKI graph backend (Phase 1, merged); operator shell + analytics cutover (the TopBar dot + dashboard this builds on).
