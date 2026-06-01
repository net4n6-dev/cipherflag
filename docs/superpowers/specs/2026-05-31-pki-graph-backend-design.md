# CipherFlag CE PKI Graph Backend — Design Spec (Phase 1)

**Date:** 2026-05-31
**Status:** Approved (brainstorming complete, awaiting spec review → writing-plans)
**Branch:** `feat/ce-pki-graph-backend` (off `main`)

## Goal

Un-break CipherFlag CE's existing 2D PKI Explorer — and reach full EE parity on the graph API — by restoring the graph backend that was stripped during the open-core port. CE already ships the PKI Explorer frontend, the `api.ts` client methods, the store methods, and all model types; only the `graph.go` handler + `internal/analysis/chain.go` are missing and **no `/graph/*` routes are registered**, so the page 404s on load. This phase ports 2 Go files and registers 5 routes.

## Background / current state (verified by code inspection 2026-05-31)

CE's PKI Explorer is **shipped but broken**: the frontend `/pki/+page.svelte` + `frontend/src/lib/components/graph/*` + the `api.ts` methods (`getAggregatedLandscape`, `getCAChildren`, `getBlastRadius`) all exist and call `/graph/*` endpoints, but those endpoints return 404 (the `/pki` "Failed to load landscape" 404 seen in earlier smoke tests). The store methods exist; the handler + analysis helper were stripped during the CE port (`internal/api/server.go:39-43` documents the SSE+graph wiring removal).

This is the same de-moat pattern as the analytics cutover: store/model present, handler/routes absent.

Verified facts:
- **Store methods — all PRESENT** in CE: `GetAllCertificatesForGraph` (interface `store.go:195`, impl `postgres.go:493`), `GetAggregatedLandscape` (`:196`/`:523`), `GetCAChildren` (`:197`/`:605`), `GetBlastRadius` (`:198`/`:720`); plus `GetCertificate` (`:160`) and `GetAllHealthReports` (`:177`) needed by `ChainGraph`/`loadReportsMap`.
- **Model types — all PRESENT** in CE `internal/model/chain.go` (byte-identical to EE modulo the Apache header): `GraphResponse`, `GraphNode`, `GraphNodeData` (incl. `PulseRate`/`SizeWeight`/`NodeType`/`Parent`/`Issuer`), `GraphEdge`, `GraphEdgeData`, `ChainNode`, `ChainTree`, `AggregatedGraphNode`, `AggregatedGraphEdge`, `AggregatedLandscapeResponse`, `CAChildrenResponse`, `BlastRadiusSummary`, `BlastRadiusResponse`. `Grade`/`GradeAPlus`/`GradeC`/`GradeD`/`GradeF`/`HealthReport` in `model/health.go`. **No model gap.**
- **Helpers — PRESENT** in CE `internal/api/handler/certificates.go`: `loadReportsMap(s store.CertStore, r *http.Request) map[string]*model.HealthReport` (`:205`), `writeJSON` (`:195`), `writeError` (`:201`).
- **MISSING in CE:** `internal/api/handler/graph.go` (absent) and `internal/analysis/chain.go` (absent — CE `internal/analysis/` has only `scorer.go` + subdirs `compliance/`, `pqc/`, `scoring/`). No helper-name collisions: `classifyNode`/`gradeToRisk`/`sanitizeID`/`calcPulseRate`/`calcSizeWeight`/`edgeWeight` are not already defined in CE's `analysis` package.
- **Routes:** CE registers `/pki/tree` only (`server.go:167`); `grep -c 'r.Get("/graph'` = 0. EE registers all 5 `/graph/*` (`server.go:154-158`).

### Decisions locked during brainstorming

- **Phase 1 scope:** graph-backend de-moat ONLY. The 3D constellation and the SSE live-update layer are separate later cycles (this is the first of a decomposed 3-phase effort: graph backend → SSE → constellation).
- **Routes:** register ALL 5 (full EE parity), which requires porting `internal/analysis/chain.go` (used by the `Landscape` + `ChainGraph` routes; the other 3 routes need no analysis helper).
- **Handler source:** port from EE (`/Users/Erik/projects/cipherflag-EE`) — the current source of truth; byte-identical to the v1.0 tag modulo module path, and the import path `github.com/net4n6-dev/cipherflag/...` already matches CE, so the files port verbatim with no rewrite.
- **No moat crossed:** all graph data is pure cert-hierarchy aggregation over `certificates` + `health_reports`. The "blast radius" here is the recursive CA-descendant CERT graph (a `WITH RECURSIVE` CTE on `issuer_cn → subject_cn`), NOT the EE-only host blast-radius (a separate feature needing host-dependency data CE doesn't collect). `graph.go`/`chain.go` import only `internal/analysis`, `internal/store`, `internal/model`, chi, and stdlib — no `internal/ai`, host-deps, velociraptor, or vendor SDK.

## Architecture

Three changes, ordered so the project builds + tests green after each:

### Change 1 — Port `internal/analysis/chain.go` (verbatim from EE)

Copy `/Users/Erik/projects/cipherflag-EE/internal/analysis/chain.go` to `/Users/Erik/projects/cipherflag/internal/analysis/chain.go`. Package `analysis`; imports `fmt`, `math`, `time`, `internal/model` only. Provides:
- `BuildGraphData(certs []model.Certificate, reports map[string]*model.HealthReport) *model.GraphResponse` — full-landscape Cytoscape nodes/edges (used by `Landscape`).
- `BuildChainTree(leaf *model.Certificate, allCerts []model.Certificate, reports map[string]*model.HealthReport) *model.ChainTree` — walks leaf→root by issuer CN (used by `ChainGraph`).
- `BuildChainGraphData(tree *model.ChainTree) *model.GraphResponse` — converts a `ChainTree` to Cytoscape elements (used by `ChainGraph`).
- 6 unexported helpers (`classifyNode`, `gradeToRisk`, `calcPulseRate`, `calcSizeWeight`, `edgeWeight`, `sanitizeID`).
The CE Apache license header must be added to match CE's file convention (every other CE Go file carries it).

### Change 2 — Port `internal/api/handler/graph.go` (verbatim from EE)

Copy `/Users/Erik/projects/cipherflag-EE/internal/api/handler/graph.go` to CE. Imports `net/http`, `strconv`, `chi/v5`, `internal/analysis`, `internal/store`. Defines:
- `type GraphHandler struct { store store.CertStore }` + `func NewGraphHandler(s store.CertStore) *GraphHandler`.
- 5 methods:
  - `Landscape` — `GetAllCertificatesForGraph` + `loadReportsMap(h.store, r)` + `analysis.BuildGraphData` → `*model.GraphResponse`.
  - `ChainGraph` — reads `chi.URLParam(r, "fingerprint")`; `GetCertificate` (404 if nil) + `GetAllCertificatesForGraph` + `loadReportsMap` + `analysis.BuildChainTree` → `analysis.BuildChainGraphData` → `*model.GraphResponse`.
  - `AggregatedLandscape` — `GetAggregatedLandscape` → `*model.AggregatedLandscapeResponse`.
  - `CAChildren` — `chi.URLParam("fingerprint")` + query `limit` (default 100, clamp 1–500) + `offset` (default 0, ≥0); `GetCAChildren(fp, limit, offset)` → `*model.CAChildrenResponse`.
  - `BlastRadius` — `chi.URLParam("fingerprint")`; `GetBlastRadius(fp, 500)` → `*model.BlastRadiusResponse`.
Add the CE Apache header. Uses CE's existing `loadReportsMap`/`writeJSON`/`writeError` (same package `handler`).

### Change 3 — Register routes + construct handler (`internal/api/server.go`)

- In the handler-construction block (lines 66-99, 1-tab indent), add: `graphH := handler.NewGraphHandler(st)`. CE's `st` is `store.CryptoStore`, which embeds `store.CertStore` (`store.go:457-458`), so it satisfies `NewGraphHandler` directly — no adapter.
- In the authenticated `r.Group` route block (3-tab indent, after the stats/PKI block ~line 167), add:
```go
			// Graph / PKI landscape (Cytoscape.js views)
			r.Get("/graph/landscape", graphH.Landscape)
			r.Get("/graph/chain/{fingerprint}", graphH.ChainGraph)
			r.Get("/graph/landscape/aggregated", graphH.AggregatedLandscape)
			r.Get("/graph/ca/{fingerprint}/children", graphH.CAChildren)
			r.Get("/graph/ca/{fingerprint}/blast-radius", graphH.BlastRadius)
```
- Update the `server.go:39-43` stripped-wiring comment to note the graph/PKI views are now restored in CE (SSE remains stripped — separate phase).

### Change 4 — Regression test (`internal/api/handler/graph_test.go`)

Mirror the `stats_test.go` embedded-interface pattern: `fakeGraphStore` embeds `store.CertStore` (nil) and overrides the 6 methods (`GetAllCertificatesForGraph`, `GetCertificate`, `GetAllHealthReports`, `GetAggregatedLandscape`, `GetCAChildren`, `GetBlastRadius`) returning zero-value structs (and a non-nil cert from `GetCertificate` so `ChainGraph` exercises the success path). `TestGraphHandler_RoutesRegistered` builds a chi router with all 5 routes and asserts each returns a non-404 status (200), proving the routes resolve to the handler (not "404 route not found").

## Data flow

```
PKI page (onMount / interaction) → api.getX() → fetchJSON('/graph/...')
  → chi route (server.go) → graphH.Method → store.GetX() [+ analysis.BuildX] → SQL over certificates + health_reports
  → JSON → ForceGraph renders nodes/edges
```

| Route | Method | Store + analysis | Used by CE `/pki` page |
|---|---|---|---|
| `/graph/landscape/aggregated` | `AggregatedLandscape` | `GetAggregatedLandscape` | yes (initial load) |
| `/graph/ca/{fp}/children` | `CAChildren` | `GetCAChildren(fp, limit, offset)` | yes (expand CA) |
| `/graph/ca/{fp}/blast-radius` | `BlastRadius` | `GetBlastRadius(fp, 500)` | yes (blast overlay) |
| `/graph/landscape` | `Landscape` | `GetAllCertificatesForGraph` + `loadReportsMap` + `BuildGraphData` | no (parity only) |
| `/graph/chain/{fp}` | `ChainGraph` | `GetCertificate` + `GetAllCertificatesForGraph` + `loadReportsMap` + `BuildChainTree`→`BuildChainGraphData` | no (parity only) |

The first 3 un-break the existing page (direct store→JSON, no analysis dependency). The last 2 are parity additions needing `chain.go`. The frontend is unchanged — once the routes exist, the page goes 404 → working with no frontend edits.

## Error handling

No new patterns — restores handlers using CE's established conventions:
1. **Handler:** store error → `writeError(w, 500, err.Error())`; success → `writeJSON(w, 200, resp)`. `ChainGraph` returns 404 when the fingerprint isn't found. `CAChildren` clamps `limit` (1–500) / `offset` (≥0) rather than erroring on bad input. (EE behaviors, ported as-is.)
2. **Frontend (unchanged):** the `/pki` page's existing try/catch "Failed to load landscape" stops firing for the 3 routes it uses (404 → 200).
3. **Empty data:** `GetAggregatedLandscape` returns empty node/edge arrays when there are no certs; the ForceGraph renders an empty canvas (existing behavior). No special empty-state needed.

The build's `go build ./...` + the route test are the proof that the ported files reference only real CE symbols.

## Testing strategy

**Backend (core gate):**
- `internal/api/handler/graph_test.go`: `fakeGraphStore` (embedded `store.CertStore` + 6 overrides) + `TestGraphHandler_RoutesRegistered` asserting all 5 routes return non-404 (200), with a non-nil cert from the fake so `ChainGraph` hits its success path.
- `go build ./...` + `go test ./internal/api/...` green (also compile-proves all ported deps resolve).

**Frontend:** no new tests — PKI page + graph components are unchanged and already shipped.

**Integration / visual gate:**
- `docker compose build && up`; `curl` each of the 5 `/graph/*` endpoints → none returns 404.
- Headless-Chrome (auth-mocked) load of `/pki` in dark + light; read the screenshots; confirm the force graph renders nodes/edges (not the error state); confirm no `/graph/*` 404s in console.

**Out of scope for tests:** the graph store methods' SQL internals (pre-existing) and the frontend graph components (pre-existing).

## File manifest

| Path | Action | Responsibility |
|---|---|---|
| `internal/analysis/chain.go` | create (port from EE) | BuildGraphData / BuildChainTree / BuildChainGraphData + helpers |
| `internal/api/handler/graph.go` | create (port from EE) | GraphHandler + 5 methods |
| `internal/api/handler/graph_test.go` | create | 5-route non-404 regression test |
| `internal/api/server.go` | modify | construct graphH; register 5 routes; update stripped-wiring comment |

## Non-goals / out of scope

- **3D PKI Constellation** (Threlte/Three.js + d3-force-3d + `/constellation` route + 7 components + npm deps) — Phase 3, separate cycle.
- **SSE live-update layer** (DB-trigger event stream + hub + frontend events client + live TopBar dot) — Phase 2, separate cycle. (Verified safe to de-moat; deferred by decomposition, not blocked.)
- **EE-only host graphs** (`/hosts/{id}/dependencies|blast-radius|subgraph`, leaf-asset blast-radius) — these need host-dependency data CE's ingest doesn't collect; remain EE-only, not part of any PKI phase.
- No frontend changes this phase (the PKI page + graph components already exist).
- No new store methods, SQL, or migrations.

## References

- `project_ce_frontend_ee_endpoint_leak` (memory) — the `/pki` graph/landscape/aggregated 404 this resolves.
- `project_ce_v2_strategy` (memory) — open-core de-moat strategy.
- EE source of truth: `/Users/Erik/projects/cipherflag-EE` (`internal/analysis/chain.go`, `internal/api/handler/graph.go`, `internal/api/server.go:154-158`).
- v1.0 tag: byte-identical PKI explorer + graph.go (the original open-source version).
