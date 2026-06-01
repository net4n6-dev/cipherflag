# CipherFlag CE Analytics Cutover — Design Spec

**Date:** 2026-05-31
**Status:** Approved (brainstorming complete, awaiting spec review → writing-plans)
**Branch (proposed):** `feat/ce-analytics-cutover` off `main`

## Goal

Bring CipherFlag CE's Analytics page to full EE parity — all 7 analytics tabs functional — by (a) de-mooting 4 already-implemented-but-unregistered backend routes and (b) porting the 2 missing frontend tabs. This also resolves 3 of the 4 pre-existing analytics 404s recorded in `project_ce_frontend_ee_endpoint_leak` (chain-flow, deployment, source-lineage; ownership is a 4th).

## Background / current state (verified by code inspection 2026-05-31)

The analytics feature is almost entirely present in CE already — it was vendored in but deliberately moated at the **route layer only**.

- **Backend handlers** — all 13 `StatsHandler` methods exist in CE (`internal/api/handler/stats.go`), including `ChainFlow:76`, `Ownership:85`, `Deployment:94`, `CryptoPosture:103`, `ExpiryForecast:112`, `SourceLineage:121`, `LibraryDistribution:130`, `SSHKeyAnalytics:139`.
- **Store layer** — `CryptoStore` interface declares all of them (`internal/store/store.go:187-192`, `:611-612`); `PostgresStore` implements them with SQL byte-identical to EE (`postgres.go:1375 GetChainFlow`, `:1479 GetOwnershipStats`, `:1527 GetDeploymentStats`, `:1581 GetCryptoPosture`, `:1652 GetExpiryForecast`, `:1752 GetSourceLineage`; `stats_extended.go:21 GetLibraryDistribution`, `:60 GetSSHKeyAnalytics`). CE compiles today, so this code is live.
- **Frontend** — CE already ships 5 analytics tabs wired into `frontend/src/routes/analytics/+page.svelte` (Chain Flow, Ownership, Crypto Posture, Expiry Forecast, Source Lineage) plus chart components `SankeyChart.svelte`, `OwnershipTreemap.svelte`, `DeploymentChart.svelte`, and `analytics-types.ts`.
- **The gaps:**
  1. 4 routes are NOT registered in `internal/api/server.go` (commented "CE subset" at `:153-154`): `/stats/chain-flow`, `/stats/ownership`, `/stats/deployment`, `/stats/source-lineage`. Their handlers + store + SQL already exist. (crypto-posture `:159` and expiry-forecast `:160` ARE routed, which is why those 2 tabs work today.)
  2. 2 EE tabs are missing from CE's frontend: `LibraryDistTab.svelte`, `SSHAnalyticsTab.svelte`. Their backend routes ARE already mounted in CE (`server.go:292-293`), but `frontend/src/lib/api.ts` lacks `getLibraryDistribution`/`getSSHKeyAnalytics` and the 2 tabs aren't in the page.
  3. EE's `LibraryDistTab` uses an echarts treemap (`$lib/components/charts/Treemap.svelte`); CE has no echarts. Must rebuild on d3.

### Decisions locked during brainstorming

- **Scope:** Full EE parity — register the 4 routes AND port both new tabs (Library Distribution + SSH Key Analytics).
- **Library Distribution chart:** Reuse CE's d3-hierarchy treemap pattern (no echarts dependency). New sibling component `LibraryDistTreemap.svelte`.
- **SSH tab data:** Ship with a graceful empty-state. (Correction to an earlier assumption: CE DOES populate `ssh_keys` and `crypto_libraries` via the shared `UnifiedIngester` → `UpsertSSHKey`/`UpsertCryptoLibrary`, fed by the CE-eligible osquery/Tanium/SentinelOne/Absolute/Defender connectors — but only when a host-resolving collector runs; passive-Zeek-only deployments leave them empty. `crypto_library_cves` is migration-seeded, so `has_cves` always works.)
- **API convention:** new tabs call CE's single `api` object (`api.getLibraryDistribution()` / `api.getSSHKeyAnalytics()`), NOT EE's separate `stats` namespace.
- **Page wrapper:** keep CE's native analytics page markup (NOT EE's `PageShell`, which CE deliberately did not port).
- **Tab order:** append in EE's order — `library-dist`, then `ssh-analytics` last.
- **No EE-only entanglement:** all analytics store methods are pure SQL aggregation; no `internal/ai`, image scanner, velociraptor, aws, or vendor-SDK dependency. Safe to de-moat per the project's connector rule.

## Architecture

Three layers, ordered so the app builds + tests green after each:

### Layer 1 — Backend de-moat (registration only, no new logic)

In `internal/api/server.go`, register the 4 missing routes next to the existing stats routes (around `:155-160`), pointing at the already-existing handler methods:

```go
r.Get("/stats/chain-flow", statsH.ChainFlow)
r.Get("/stats/ownership", statsH.Ownership)
r.Get("/stats/deployment", statsH.Deployment)
r.Get("/stats/source-lineage", statsH.SourceLineage)
```

Update the `:153-154` comment ("CE subset — no chain-flow / source-lineage graph views, no ownership/deployment Cytoscape data") to reflect that these stat endpoints are now available in CE (the *graph/Cytoscape* host-dependency views remain EE-only and out of scope — this cutover is the **stats** endpoints only, not `/graph/landscape/aggregated` or the hosts dependency/blast-radius routes).

**Testability refactor:** `StatsHandler` currently takes the full `store.CryptoStore` (`handler/stats.go:23-28`), and there is no narrow interface or `stats_test.go`. Introduce a narrow `statsStore` interface (mirroring the existing `lineageStore` pattern in `handler/lineage.go` / `lineage_test.go`) declaring exactly the methods `StatsHandler` calls, and change `NewStatsHandler` to accept it. `PostgresStore` already satisfies it (it implements `CryptoStore` ⊇ `statsStore`). This enables DB-free route tests with a `fakeStatsStore`.

### Layer 2 — API client (additive)

In `frontend/src/lib/api.ts`:
- Add types `LibraryDistItem`, `AgeBucket`, `ProtectionStats`, `SSHKeyAnalytics` (shapes mirrored from CE's Go structs in `internal/store/store.go:408/417/428/437` and EE's `api/types.ts`).
- Add methods to the `api` object:
  - `getLibraryDistribution: () => fetchJSON<{ items: LibraryDistItem[]; total: number }>('/stats/library-distribution')`
  - `getSSHKeyAnalytics: () => fetchJSON<SSHKeyAnalytics>('/stats/ssh-key-analytics')`

(Both routes are already mounted in CE backend at `server.go:292-293`; this is purely the missing client side.)

### Layer 3 — Frontend tabs + new chart component

1. **`frontend/src/lib/components/analytics/LibraryDistTreemap.svelte`** (NEW) — d3 treemap. Copies the d3 scaffolding from CE's existing `OwnershipTreemap.svelte` (d3 `hierarchy` → `treemap().tile(treemapSquarify)`, ResizeObserver, label-visibility threshold, SVG `<rect>` render), but:
   - Props: `{ items: LibraryDistItem[] }`.
   - Builds a single-level hierarchy: root → one leaf per item, `name = \`${library} ${version}\``, `value = host_count`.
   - Fill: `has_cves ? '#ef4444' : '#22c55e'`.
   - Tooltip: library, version, host count, CVE flag.
   - Uses only `--cf-*` CSS variables (themes automatically).

2. **`frontend/src/lib/components/analytics/LibraryDistTab.svelte`** (PORT from EE) — fetches `api.getLibraryDistribution()` in `onMount`; renders `LibraryDistTreemap` with the items; loading + error + empty-state (empty when `items.length === 0`).

3. **`frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte`** (PORT from EE) — copy EE's component (pure HTML/CSS bars, no chart lib); swap `import { stats } from '$lib/api'` → use CE's `api`, and the `SSHKeyAnalytics` type import to CE's types. Fetches `api.getSSHKeyAnalytics()`; renders KPI cards (weak/root/shared/unprotected), strength bar, and CSS bar-lists for `key_types`, `age_distribution`, `source_breakdown`; loading + error + empty-state (empty when `total_keys === 0`).

4. **`frontend/src/routes/analytics/+page.svelte`** (MODIFY) — add 2 imports, 2 `TABS` entries (`{ id: 'library-dist', label: 'Library Distribution' }`, `{ id: 'ssh-analytics', label: 'SSH Key Analytics' }`) appended after the existing 5, and 2 `{:else if}` branches in the tab switch.

## Data flow

```
Tab.svelte (onMount) → api.getX() → fetchJSON('/stats/X')
  → chi route (server.go) → statsH.X → store.GetX() → SQL over Postgres
  → JSON → tab renders (d3 / HTML-CSS charts)
```

- The 4 de-mooted tabs already have frontend + handler + store + SQL; route registration flips them 404 → 200.
- The 2 new tabs hit routes already mounted; the missing pieces are the api methods/types and the components.

## Error handling & empty-states

Three cases:
1. **Fetch error (non-2xx):** `fetchJSON` throws; each tab's `onMount` try/catch sets an `error` string → error message rendered (existing CE tab pattern). Route registration removes the 404-driven errors on the 4 de-mooted tabs.
2. **Empty inventory (200, no rows):** expected for SSH/Library tabs in passive-only CE. Render a graceful empty-state message instead of zeros/blank:
   - SSH tab → when `total_keys === 0`: "No SSH key data yet — configure a host-based source (osquery/EDR) to populate this view."
   - Library tab → when `items.length === 0`: "No crypto-library data yet — configure a host-based source (osquery/EDR) to populate this view."
3. **Partial data:** charts/bars scale to whatever rows exist; no special handling.

Loading: each new tab shows a brief "Loading…" during fetch (existing pattern). The 4 already-vendored tabs keep their existing error/loading handling unchanged (only verified post-registration, not restyled). Graceful empty-state work is scoped to the 2 new tabs.

## Testing strategy

**Backend:**
- Add the narrow `statsStore` interface + `fakeStatsStore`; new `internal/api/handler/stats_test.go` asserts each of the 4 de-mooted routes returns 200 (not 404) with the expected JSON shape, using the chi-router + httptest + fake-store pattern (mirror `lineage_test.go`).
- `go build ./...` and `go test ./internal/api/...` green.

**Frontend (vitest + @testing-library/svelte):**
- `LibraryDistTreemap.svelte`: renders the expected leaf `<rect>` count for sample items; applies red fill for `has_cves`, green otherwise.
- `LibraryDistTab.svelte` / `SSHAnalyticsTab.svelte`: with sample data → content renders; with empty data → empty-state message renders.
- `npx svelte-check` 0 errors; `npm run build` emits `build/index.html` (Go embed depends on it).

**Integration / visual gate:**
- `docker compose build && up`; headless-Chrome (auth-mocked, as in the operator-shell work) over `/analytics`, clicking all 7 tabs in dark + light; read screenshots; confirm each tab renders (data or graceful empty-state), no console 404s for chain-flow/ownership/deployment/source-lineage, treemap + charts correct in both themes.

**Out of scope for tests:** internals of the 4 already-vendored tabs (only route-registration tests + visual confirmation).

## File manifest

| Path | Action | Responsibility |
|---|---|---|
| `internal/api/server.go` | modify | register 4 stats routes; update CE-subset comment |
| `internal/api/handler/stats.go` | modify | introduce narrow `statsStore` interface; `NewStatsHandler` accepts it |
| `internal/api/handler/stats_test.go` | create | 200-not-404 route tests w/ `fakeStatsStore` |
| `frontend/src/lib/api.ts` | modify | add 2 methods + 4 types |
| `frontend/src/lib/components/analytics/LibraryDistTreemap.svelte` | create | d3 treemap for library dist |
| `frontend/src/lib/components/analytics/LibraryDistTab.svelte` | create (port) | library-dist tab |
| `frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte` | create (port) | ssh-analytics tab |
| `frontend/src/lib/components/analytics/LibraryDistTreemap.svelte.test.ts` | create | treemap unit test |
| `frontend/src/lib/components/analytics/LibraryDistTab.svelte.test.ts` | create | lib tab unit test |
| `frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte.test.ts` | create | ssh tab unit test |
| `frontend/src/routes/analytics/+page.svelte` | modify | wire 2 new tabs |

## Non-goals / out of scope

- `/graph/landscape/aggregated` (PKI graph) and the hosts dependency/blast-radius/subgraph routes remain EE-only — NOT part of this cutover (this is the analytics **stats** endpoints only). The `/pki` aggregated-landscape 404 and `/upload` pcap/jobs 404 from `project_ce_frontend_ee_endpoint_leak` are NOT addressed here.
- No new ingest/collector work — the data plumbing already exists; tabs show real data where host-based collectors run, graceful empty-states otherwise.
- No restyling of the 4 already-vendored tabs.
- No echarts dependency.

## References

- `project_ce_frontend_ee_endpoint_leak` (memory) — the 404s this partially resolves.
- `project_ce_v2_strategy` (memory) — open-core de-moat strategy.
- EE source of truth: `/Users/Erik/projects/cipherflag-EE`.
