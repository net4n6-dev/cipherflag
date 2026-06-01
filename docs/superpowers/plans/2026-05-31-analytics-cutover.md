# CipherFlag CE Analytics Cutover — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring CipherFlag CE's Analytics page to full EE parity — all 7 tabs functional — by registering 4 already-implemented backend stats routes and porting the 2 missing frontend tabs (Library Distribution, SSH Key Analytics).

**Architecture:** The analytics backend (handlers, store methods, SQL) already exists in CE; only 4 routes are unregistered. This plan (1) registers those 4 routes + a regression test, (2) adds 2 api-client methods + 4 TS types, (3) ports the SSH tab verbatim with an import swap, (4) builds a CE-native d3 treemap and ports the Library tab onto it, (5) wires both tabs into the page, (6) verifies all 7 tabs in dark+light. No new handler/store/SQL/migration code; no echarts dependency.

**Tech Stack:** Go 1.26 (chi router), SvelteKit 2 / Svelte 5 (runes), d3-hierarchy, vitest + @testing-library/svelte, adapter-static SPA embedded in the Go binary.

**Spec:** `docs/superpowers/specs/2026-05-31-analytics-cutover-design.md`
**Branch:** `feat/ce-analytics-cutover` (already created off `main`; spec already committed at HEAD).

---

## Pre-flight (read once)

- **Repos:** CE = `/Users/Erik/projects/cipherflag` (this repo, branch `feat/ce-analytics-cutover`). EE source-of-truth (read-only) = `/Users/Erik/projects/cipherflag-EE`.
- **Backend is already built.** All 13 `StatsHandler` methods, the `CryptoStore`/`CertStore` interface declarations, the `PostgresStore` SQL implementations, and the `LibraryDistItem`/`SSHKeyAnalytics` Go structs already exist in CE and compile. This plan does NOT re-implement them — it registers 4 routes and ports frontend.
- **api object name:** CE uses a single flat `frontend/src/lib/api.ts` exporting `export const api = {...}` and `fetchJSON`. EE's tabs import `{ stats }` from a modular `$lib/api/` — when porting, rewrite `stats.` → `api.`.
- **Indentation:** CE analytics components (`OwnershipTreemap.svelte`, `SourceLineageTab.svelte`, `+page.svelte`) use **tabs**. EE components use 2 spaces. The 2 ported tabs come from EE (2-space) — keep them internally consistent (2-space is fine for those files since they're verbatim ports); new CE-authored files (`LibraryDistTreemap.svelte`) use tabs to match CE siblings. Do not mix within a file.
- **adapter-static:** after any frontend change, `cd frontend && npm run build` must still emit `frontend/build/index.html` (the Go `//go:embed` depends on it).
- **Flaky bash:** this environment's bash output is intermittently empty — if a command returns nothing, re-run it or redirect to a file and read it. Never conclude from one blank result. When reporting a commit SHA, quote the real output of `git log -1 --format='%h %s'`.
- **Do NOT** `git add -A` / `git add .` — there are untracked `docs/`, `.claude/`, `research/` dirs that must not be committed. Stage explicit paths only.
- **Out of scope:** `/graph/landscape/aggregated`, hosts dependency/blast-radius routes, `/pcap/jobs` — those stay EE-only and are NOT part of this cutover.

---

## File manifest

| Path | Action | Responsibility |
|---|---|---|
| `internal/api/server.go` | modify | register 4 stats routes; update CE-subset comment |
| `internal/api/handler/stats_test.go` | create | regression test: 4 routes → 200 (embedded-interface fake) |
| `frontend/src/lib/api.ts` | modify | add 4 types + 2 methods |
| `frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte` | create (port) | SSH analytics tab |
| `frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte.test.ts` | create | SSH tab unit test |
| `frontend/src/lib/components/analytics/LibraryDistTreemap.svelte` | create | d3 treemap for library dist |
| `frontend/src/lib/components/analytics/LibraryDistTreemap.svelte.test.ts` | create | treemap unit test |
| `frontend/src/lib/components/analytics/LibraryDistTab.svelte` | create (port) | library-dist tab |
| `frontend/src/lib/components/analytics/LibraryDistTab.svelte.test.ts` | create | lib tab unit test |
| `frontend/src/routes/analytics/+page.svelte` | modify | wire 2 new tabs |

Tasks are ordered so the project builds + tests green after each.

---

## Task 1: Register 4 backend stats routes + regression test

**Files:**
- Modify: `internal/api/server.go` (the stats route block, ~lines 153-163)
- Create: `internal/api/handler/stats_test.go`

**Note on the test approach (deviation from spec, documented):** the spec suggested a narrow `statsStore` interface + production refactor of `NewStatsHandler`. Instead we use the Go embedded-interface fake idiom: a `fakeStatsStore` that embeds `store.CryptoStore` (nil) and overrides only the 4 methods under test. This satisfies `NewStatsHandler(store.CryptoStore)` with **zero production change** and no need to implement the other ~30 interface methods. Same outcome: DB-free route tests proving 200-not-404. This test builds its own chi router (mirroring `lineage_test.go`), so it locks the route→handler contract; the *server.go* registration itself is verified by `go build` + the Task 7 integration gate (no console 404s).

- [ ] **Step 1: Write the regression test**

Create `internal/api/handler/stats_test.go`:
```go
// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// fakeStatsStore embeds the full CryptoStore interface (nil) so it satisfies
// NewStatsHandler's parameter type without implementing every method. We only
// override the four de-mooted analytics methods exercised by these tests;
// any other method call would panic (and none of the tested routes make one).
type fakeStatsStore struct {
	store.CryptoStore
	chainFlow     *model.ChainFlowResponse
	ownership     *model.OwnershipResponse
	deployment    *model.DeploymentResponse
	sourceLineage *model.SourceLineageResponse
}

func (f *fakeStatsStore) GetChainFlow(ctx context.Context) (*model.ChainFlowResponse, error) {
	return f.chainFlow, nil
}
func (f *fakeStatsStore) GetOwnershipStats(ctx context.Context) (*model.OwnershipResponse, error) {
	return f.ownership, nil
}
func (f *fakeStatsStore) GetDeploymentStats(ctx context.Context) (*model.DeploymentResponse, error) {
	return f.deployment, nil
}
func (f *fakeStatsStore) GetSourceLineage(ctx context.Context) (*model.SourceLineageResponse, error) {
	return f.sourceLineage, nil
}

func newStatsRouter(t *testing.T, s store.CryptoStore) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	h := NewStatsHandler(s)
	r.Get("/stats/chain-flow", h.ChainFlow)
	r.Get("/stats/ownership", h.Ownership)
	r.Get("/stats/deployment", h.Deployment)
	r.Get("/stats/source-lineage", h.SourceLineage)
	return r
}

func TestStatsHandler_DeMootedRoutesReturn200(t *testing.T) {
	s := &fakeStatsStore{
		chainFlow:     &model.ChainFlowResponse{},
		ownership:     &model.OwnershipResponse{},
		deployment:    &model.DeploymentResponse{},
		sourceLineage: &model.SourceLineageResponse{},
	}
	r := newStatsRouter(t, s)

	for _, path := range []string{
		"/stats/chain-flow",
		"/stats/ownership",
		"/stats/deployment",
		"/stats/source-lineage",
	} {
		req := httptest.NewRequest("GET", path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: want 200, got %d: %s", path, rr.Code, rr.Body.String())
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it passes (handlers already exist)**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/api/handler/ -run TestStatsHandler_DeMootedRoutesReturn200 -v 2>&1 | tail -15`
Expected: PASS. (The handlers + store methods already exist, so this passes immediately — it is a regression guard locking the route→handler contract. If it FAILS to compile, check that `model.ChainFlowResponse`/`OwnershipResponse`/`DeploymentResponse`/`SourceLineageResponse` and `store.CryptoStore` resolve — they are defined in `internal/model/analytics.go` and `internal/store/store.go`.)

- [ ] **Step 3: Register the 4 routes in server.go**

In `internal/api/server.go`, find this block (around lines 153-160):
```go
			// Stats (CE subset — no chain-flow / source-lineage graph views,
			// no ownership/deployment Cytoscape data)
			r.Get("/stats/summary", statsH.Summary)
			r.Get("/stats/ciphers", statsH.Ciphers)
			r.Get("/stats/issuers", statsH.Issuers)
			r.Get("/stats/expiry-timeline", statsH.ExpiryTimeline)
			r.Get("/stats/crypto-posture", statsH.CryptoPosture)
			r.Get("/stats/expiry-forecast", statsH.ExpiryForecast)
```
Replace it with (updated comment + 4 new routes appended):
```go
			// Stats (full analytics suite — CE parity with EE; the host
			// dependency/blast-radius Cytoscape graph views remain EE-only)
			r.Get("/stats/summary", statsH.Summary)
			r.Get("/stats/ciphers", statsH.Ciphers)
			r.Get("/stats/issuers", statsH.Issuers)
			r.Get("/stats/expiry-timeline", statsH.ExpiryTimeline)
			r.Get("/stats/crypto-posture", statsH.CryptoPosture)
			r.Get("/stats/expiry-forecast", statsH.ExpiryForecast)
			r.Get("/stats/chain-flow", statsH.ChainFlow)
			r.Get("/stats/ownership", statsH.Ownership)
			r.Get("/stats/deployment", statsH.Deployment)
			r.Get("/stats/source-lineage", statsH.SourceLineage)
```
(Leave the existing `/stats/library-distribution` and `/stats/ssh-key-analytics` routes elsewhere in the file untouched — they are already registered.)

- [ ] **Step 4: Build + verify routes registered**

Run: `cd /Users/Erik/projects/cipherflag && go build ./... 2>&1 | tail -15 && echo GO-BUILD-OK`
Expected: GO-BUILD-OK (no errors).
Run: `grep -nE 'stats/(chain-flow|ownership|deployment|source-lineage)' internal/api/server.go`
Expected: 4 lines printed (the new registrations).
Run: `go test ./internal/api/... 2>&1 | tail -15`
Expected: all pass (incl. the new test).

- [ ] **Step 5: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add internal/api/server.go internal/api/handler/stats_test.go
git commit -m "feat(api): register chain-flow/ownership/deployment/source-lineage stats routes

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 2: Add api-client types + methods

**Files:**
- Modify: `frontend/src/lib/api.ts`

CE's `api.ts` already has `getChainFlow`/`getOwnership`/`getDeployment`/`getSourceLineage` (the de-mooted-route methods) and their response types. It is MISSING the 2 extended methods and 4 types (confirmed absent). Add them.

- [ ] **Step 1: Add the 4 types**

In `frontend/src/lib/api.ts`, after the `SourceLineageResponse` interface (around line 356), add:
```ts
export interface LibraryDistItem {
	library: string;
	version: string;
	host_count: number;
	has_cves: boolean;
}

export interface AgeBucket {
	bucket: string;
	count: number;
}

export interface ProtectionStats {
	protected: number;
	unprotected: number;
}

export interface SSHKeyAnalytics {
	key_types: Record<string, number>;
	age_distribution: AgeBucket[];
	protection: ProtectionStats;
	root_authorized_count: number;
	strength_distribution: Record<string, number>;
	shared_keys_count: number;
	shared_keys_instances: number;
	source_breakdown: Record<string, number>;
	total_keys: number;
}
```

- [ ] **Step 2: Add the 2 methods**

In the `export const api = {` object, find the existing analytics methods ending with:
```ts
	getSourceLineage: () => fetchJSON<SourceLineageResponse>('/stats/source-lineage'),
```
Immediately after that line, add:
```ts
	getLibraryDistribution: () => fetchJSON<{ items: LibraryDistItem[]; total: number }>('/stats/library-distribution'),
	getSSHKeyAnalytics: () => fetchJSON<SSHKeyAnalytics>('/stats/ssh-key-analytics'),
```

- [ ] **Step 3: Type-check**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -6`
Expected: 0 errors (a handful of pre-existing warnings in unrelated files are fine).

- [ ] **Step 4: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/api.ts
git commit -m "feat(ui): add library-distribution + ssh-key-analytics api methods and types

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 3: Port the SSH Key Analytics tab

**Files:**
- Create: `frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte` (port from EE)
- Create: `frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte.test.ts`

The EE component is pure HTML/CSS (no chart lib). Port verbatim, then apply 4 small edits (api import, fetch call, empty-state branch, empty-state style).

- [ ] **Step 1: Copy the EE component verbatim**

Run:
```bash
cp /Users/Erik/projects/cipherflag-EE/frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte \
   /Users/Erik/projects/cipherflag/frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte
```

- [ ] **Step 2: Edit imports (lines 2-4) — swap `stats` → `api`**

In the new CE file, change:
```svelte
  import { onMount } from 'svelte';
  import { stats } from '$lib/api';
  import type { SSHKeyAnalytics } from '$lib/api';
```
to:
```svelte
  import { onMount } from 'svelte';
  import { api } from '$lib/api';
  import type { SSHKeyAnalytics } from '$lib/api';
```

- [ ] **Step 3: Edit the fetch call (in onMount)**

Change:
```svelte
      data = await stats.getSSHKeyAnalytics();
```
to:
```svelte
      data = await api.getSSHKeyAnalytics();
```

- [ ] **Step 4: Add the empty-state branch**

Find this markup (around lines 118-120):
```svelte
  {:else if error}
    <div class="tab-error">{error}</div>
  {:else if data}
```
Replace with:
```svelte
  {:else if error}
    <div class="tab-error">{error}</div>
  {:else if data && totalKeys === 0}
    <div class="tab-empty">No SSH key data yet — configure a host-based source (osquery or EDR) to populate this view.</div>
  {:else if data}
```
(`totalKeys` is the `$derived` already defined in the script at ~line 60.)

- [ ] **Step 5: Add the `.tab-empty` style**

Find this rule in the `<style>` block (around line 253):
```svelte
  .tab-error { color: var(--cf-severity-critical); }
```
Immediately after it, add:
```svelte
  .tab-empty { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; text-align: center; padding: 0 2rem; }
```

- [ ] **Step 6: Write the unit test**

Create `frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import { vi } from 'vitest';

const { getSSH } = vi.hoisted(() => ({ getSSH: vi.fn() }));
vi.mock('$lib/api', () => ({ api: { getSSHKeyAnalytics: getSSH } }));

import SSHAnalyticsTab from './SSHAnalyticsTab.svelte';

const sample = {
	key_types: { rsa: 3, ed25519: 2 },
	age_distribution: [{ bucket: '0-30d', count: 2 }],
	protection: { protected: 4, unprotected: 1 },
	root_authorized_count: 1,
	strength_distribution: { weak: 1, strong: 4 },
	shared_keys_count: 0,
	shared_keys_instances: 0,
	source_breakdown: { osquery: 5 },
	total_keys: 5,
};

describe('SSHAnalyticsTab', () => {
	it('renders analytics when data is present', async () => {
		getSSH.mockResolvedValue(sample);
		const { findByText } = render(SSHAnalyticsTab);
		expect(await findByText('SSH Key Analytics')).toBeTruthy();
		expect(await findByText('5 total keys')).toBeTruthy();
	});

	it('shows the empty-state when there are no keys', async () => {
		getSSH.mockResolvedValue({
			key_types: {},
			age_distribution: [],
			protection: { protected: 0, unprotected: 0 },
			root_authorized_count: 0,
			strength_distribution: {},
			shared_keys_count: 0,
			shared_keys_instances: 0,
			source_breakdown: {},
			total_keys: 0,
		});
		const { findByText } = render(SSHAnalyticsTab);
		expect(await findByText(/configure a host-based source/i)).toBeTruthy();
	});
});
```

- [ ] **Step 7: Run the test**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx vitest run src/lib/components/analytics/SSHAnalyticsTab.svelte.test.ts 2>&1 | tail -15`
Expected: 2 passing.

- [ ] **Step 8: Type-check**

Run: `npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -6`
Expected: 0 errors in SSHAnalyticsTab.svelte / its test.

- [ ] **Step 9: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte frontend/src/lib/components/analytics/SSHAnalyticsTab.svelte.test.ts
git commit -m "feat(ui): port SSH key analytics tab with graceful empty-state

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 4: Build the d3 Library Distribution treemap

**Files:**
- Create: `frontend/src/lib/components/analytics/LibraryDistTreemap.svelte`
- Create: `frontend/src/lib/components/analytics/LibraryDistTreemap.svelte.test.ts`

This is a CE-native d3 treemap (no echarts), modeled on the existing `OwnershipTreemap.svelte` scaffolding but single-level and sized by host count.

- [ ] **Step 1: Create the component**

Create `frontend/src/lib/components/analytics/LibraryDistTreemap.svelte` (tabs indentation, matching CE siblings):
```svelte
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { hierarchy, treemap, treemapSquarify } from 'd3-hierarchy';
	import type { LibraryDistItem } from '$lib/api';

	interface Props {
		items: LibraryDistItem[];
	}

	let { items }: Props = $props();

	let containerEl: HTMLDivElement;
	let width = $state(800);
	let height = $state(400);
	let resizeObserver: ResizeObserver;

	interface TreeRect {
		x: number; y: number; w: number; h: number;
		library: string; version: string;
		hostCount: number; hasCves: boolean; showLabel: boolean;
	}

	let rects: TreeRect[] = $state([]);
	let hoveredRect: TreeRect | null = $state(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);

	const CVE_COLOR = '#ef4444';
	const SAFE_COLOR = '#22c55e';

	function computeLayout() {
		if (items.length === 0) { rects = []; return; }

		const children = items.map((item) => ({
			name: `${item.library} ${item.version}`,
			value: item.host_count,
			library: item.library,
			version: item.version,
			hostCount: item.host_count,
			hasCves: item.has_cves,
		}));

		const root = hierarchy({ name: 'root', children })
			.sum(d => (d as any).value ?? 0)
			.sort((a, b) => (b.value ?? 0) - (a.value ?? 0));

		treemap<any>()
			.size([width, height])
			.paddingOuter(4)
			.paddingInner(2)
			.tile(treemapSquarify)
			(root);

		const totalArea = width * height;
		rects = (root.leaves() as any[]).map(leaf => {
			const d = leaf.data;
			const w = (leaf.x1 ?? 0) - (leaf.x0 ?? 0);
			const h = (leaf.y1 ?? 0) - (leaf.y0 ?? 0);
			return {
				x: leaf.x0 ?? 0, y: leaf.y0 ?? 0, w, h,
				library: d.library ?? '',
				version: d.version ?? '',
				hostCount: d.hostCount ?? 0,
				hasCves: d.hasCves ?? false,
				showLabel: totalArea > 0 && (w * h) / totalArea > 0.02 && w > 50 && h > 24,
			};
		});
	}

	onMount(() => {
		const rect = containerEl.getBoundingClientRect();
		width = rect.width || width;
		resizeObserver = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) { width = entry.contentRect.width; computeLayout(); }
		});
		resizeObserver.observe(containerEl);
		computeLayout();
	});

	onDestroy(() => { if (resizeObserver) resizeObserver.disconnect(); });

	$effect(() => { if (items && width > 0) computeLayout(); });
</script>

<div class="treemap-container" bind:this={containerEl}>
	<svg {width} {height}>
		{#each rects as r, i (i)}
			<g
				transform="translate({r.x},{r.y})"
				onpointerenter={(e) => { hoveredRect = r; tooltipX = e.clientX; tooltipY = e.clientY; }}
				onpointerleave={() => hoveredRect = null}
				role="img"
				aria-label={`${r.library} ${r.version}`}
			>
				<rect width={r.w} height={r.h} fill={r.hasCves ? CVE_COLOR : SAFE_COLOR} fill-opacity={0.25}
					stroke={r.hasCves ? CVE_COLOR : SAFE_COLOR} stroke-opacity={0.6} stroke-width={1} rx={3} />
				{#if r.showLabel}
					<text x={4} y={14} fill="#e2e8f0" font-size="10" font-weight="600">
						{r.library.length > r.w / 6 ? r.library.slice(0, Math.floor(r.w / 6)) + '...' : r.library}
					</text>
					{#if r.h > 30}
						<text x={4} y={26} fill="#94a3b8" font-size="9">{r.version}</text>
					{/if}
					<text x={4} y={r.h - 6} fill="#64748b" font-size="9">{r.hostCount.toLocaleString()}</text>
				{/if}
			</g>
		{/each}
	</svg>

	{#if hoveredRect}
		<div class="treemap-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
			<div class="tt-lib">{hoveredRect.library}</div>
			<div class="tt-ver">v{hoveredRect.version}</div>
			<div class="tt-stats">
				<span>{hoveredRect.hostCount.toLocaleString()} host{hoveredRect.hostCount === 1 ? '' : 's'}</span>
				{#if hoveredRect.hasCves}<span class="tt-cve">has CVEs</span>{/if}
			</div>
		</div>
	{/if}
</div>

<style>
	.treemap-container { position: relative; width: 100%; }
	svg { display: block; }
	g { cursor: default; }
	g rect { transition: fill-opacity 0.15s; }
	g:hover rect { fill-opacity: 0.4; }
	text { pointer-events: none; user-select: none; }
	.treemap-tooltip { position: fixed; background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 0.5rem 0.75rem; z-index: 50; pointer-events: none; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4); }
	.tt-lib { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; }
	.tt-ver { font-size: 0.7rem; color: #64748b; margin-bottom: 0.25rem; }
	.tt-stats { display: flex; gap: 0.75rem; font-size: 0.75rem; color: #94a3b8; }
	.tt-cve { color: #ef4444; font-weight: 600; }
</style>
```

- [ ] **Step 2: Write the unit test**

Create `frontend/src/lib/components/analytics/LibraryDistTreemap.svelte.test.ts`:
```ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import LibraryDistTreemap from './LibraryDistTreemap.svelte';

beforeEach(() => {
	// jsdom has no ResizeObserver; the component constructs one in onMount.
	vi.stubGlobal('ResizeObserver', class {
		observe() {}
		unobserve() {}
		disconnect() {}
	});
});

const items = [
	{ library: 'openssl', version: '1.1.1', host_count: 10, has_cves: true },
	{ library: 'openssl', version: '3.0.0', host_count: 5, has_cves: false },
	{ library: 'libgcrypt', version: '1.9.4', host_count: 2, has_cves: false },
];

describe('LibraryDistTreemap', () => {
	it('renders one rect per library item', () => {
		const { container } = render(LibraryDistTreemap, { props: { items } });
		expect(container.querySelectorAll('rect').length).toBe(3);
	});

	it('fills CVE libraries red and others green', () => {
		const { container } = render(LibraryDistTreemap, { props: { items } });
		const fills = Array.from(container.querySelectorAll('rect')).map((r) => r.getAttribute('fill'));
		expect(fills).toContain('#ef4444');
		expect(fills).toContain('#22c55e');
	});

	it('renders no rects for empty items', () => {
		const { container } = render(LibraryDistTreemap, { props: { items: [] } });
		expect(container.querySelectorAll('rect').length).toBe(0);
	});
});
```

- [ ] **Step 3: Run the test**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx vitest run src/lib/components/analytics/LibraryDistTreemap.svelte.test.ts 2>&1 | tail -15`
Expected: 3 passing. (In jsdom `getBoundingClientRect().width` is 0, so `width = rect.width || width` keeps the 800 default and the layout produces 3 leaf rects.)

- [ ] **Step 4: Type-check**

Run: `npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -6`
Expected: 0 errors in LibraryDistTreemap.svelte / its test.

- [ ] **Step 5: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/components/analytics/LibraryDistTreemap.svelte frontend/src/lib/components/analytics/LibraryDistTreemap.svelte.test.ts
git commit -m "feat(ui): add d3 library-distribution treemap (CVE-colored, host-count sized)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 5: Port the Library Distribution tab

**Files:**
- Create: `frontend/src/lib/components/analytics/LibraryDistTab.svelte`
- Create: `frontend/src/lib/components/analytics/LibraryDistTab.svelte.test.ts`

This is a CE rewrite of EE's `LibraryDistTab` — same data fetch + states, but renders the new d3 `LibraryDistTreemap` instead of the echarts one, and uses CE's `api` object.

- [ ] **Step 1: Create the component**

Create `frontend/src/lib/components/analytics/LibraryDistTab.svelte`:
```svelte
<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import type { LibraryDistItem } from '$lib/api';
	import LibraryDistTreemap from './LibraryDistTreemap.svelte';

	let items = $state<LibraryDistItem[]>([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	onMount(async () => {
		try {
			const resp = await api.getLibraryDistribution();
			items = resp?.items ?? [];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load library data';
		}
		loading = false;
	});
</script>

<div class="library-dist-tab">
	{#if loading}
		<div class="tab-loading">Loading library distribution...</div>
	{:else if error}
		<div class="tab-error">{error}</div>
	{:else if items.length === 0}
		<div class="tab-empty">No crypto-library data yet — configure a host-based source (osquery or EDR) to populate this view.</div>
	{:else}
		<div class="tab-header">
			<h2>Library Distribution</h2>
			<span class="tab-meta">{items.length} libraries · sized by host count · red = has CVEs</span>
		</div>
		<div class="chart-wrap">
			<LibraryDistTreemap {items} />
		</div>
	{/if}
</div>

<style>
	.library-dist-tab { padding: 1.5rem; height: 100%; overflow-y: auto; }
	.tab-header { display: flex; align-items: baseline; gap: 1rem; margin-bottom: 1rem; }
	.tab-header h2 { margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--cf-text-primary); }
	.tab-meta { font-size: 0.8rem; color: var(--cf-text-muted); }
	.chart-wrap { height: calc(100% - 60px); min-height: 400px; }
	.tab-loading, .tab-error, .tab-empty { display: flex; align-items: center; justify-content: center; height: 50vh; color: var(--cf-text-muted); font-size: 0.9rem; text-align: center; padding: 0 2rem; }
	.tab-error { color: var(--cf-severity-critical); }
</style>
```

- [ ] **Step 2: Write the unit test**

Create `frontend/src/lib/components/analytics/LibraryDistTab.svelte.test.ts`:
```ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte';

const { getLib } = vi.hoisted(() => ({ getLib: vi.fn() }));
vi.mock('$lib/api', () => ({ api: { getLibraryDistribution: getLib } }));

import LibraryDistTab from './LibraryDistTab.svelte';

beforeEach(() => {
	vi.stubGlobal('ResizeObserver', class {
		observe() {}
		unobserve() {}
		disconnect() {}
	});
});

describe('LibraryDistTab', () => {
	it('renders the treemap when data is present', async () => {
		getLib.mockResolvedValue({
			items: [{ library: 'openssl', version: '3.0.0', host_count: 4, has_cves: false }],
			total: 1,
		});
		const { findByText, container } = render(LibraryDistTab);
		expect(await findByText('Library Distribution')).toBeTruthy();
		expect(container.querySelectorAll('rect').length).toBeGreaterThan(0);
	});

	it('shows the empty-state when there are no libraries', async () => {
		getLib.mockResolvedValue({ items: [], total: 0 });
		const { findByText } = render(LibraryDistTab);
		expect(await findByText(/configure a host-based source/i)).toBeTruthy();
	});
});
```

- [ ] **Step 3: Run the test**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx vitest run src/lib/components/analytics/LibraryDistTab.svelte.test.ts 2>&1 | tail -15`
Expected: 2 passing.

- [ ] **Step 4: Type-check**

Run: `npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -6`
Expected: 0 errors in LibraryDistTab.svelte / its test.

- [ ] **Step 5: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/components/analytics/LibraryDistTab.svelte frontend/src/lib/components/analytics/LibraryDistTab.svelte.test.ts
git commit -m "feat(ui): port library-distribution tab onto d3 treemap with empty-state

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 6: Wire both tabs into the analytics page

**Files:**
- Modify: `frontend/src/routes/analytics/+page.svelte`

- [ ] **Step 1: Add the 2 imports**

In `frontend/src/routes/analytics/+page.svelte`, find:
```svelte
	import SourceLineageTab from '$lib/components/analytics/SourceLineageTab.svelte';
```
Add immediately after it:
```svelte
	import LibraryDistTab from '$lib/components/analytics/LibraryDistTab.svelte';
	import SSHAnalyticsTab from '$lib/components/analytics/SSHAnalyticsTab.svelte';
```

- [ ] **Step 2: Add the 2 tab entries**

Find the `TABS` array entry:
```svelte
		{ id: 'source-lineage', label: 'Source Lineage' },
	] as const;
```
Change it to:
```svelte
		{ id: 'source-lineage', label: 'Source Lineage' },
		{ id: 'library-dist', label: 'Library Distribution' },
		{ id: 'ssh-analytics', label: 'SSH Key Analytics' },
	] as const;
```

- [ ] **Step 3: Add the 2 render branches**

Find the end of the tab switch:
```svelte
		{:else if activeTab === 'source-lineage'}
			<SourceLineageTab />
		{/if}
```
Change it to:
```svelte
		{:else if activeTab === 'source-lineage'}
			<SourceLineageTab />
		{:else if activeTab === 'library-dist'}
			<LibraryDistTab />
		{:else if activeTab === 'ssh-analytics'}
			<SSHAnalyticsTab />
		{/if}
```

- [ ] **Step 4: Type-check + build**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -8`
Expected: 0 errors.
Run: `npm run build 2>&1 | tail -5 && test -f build/index.html && echo BUILD-OK`
Expected: BUILD-OK.

- [ ] **Step 5: Run the full frontend test suite**

Run: `npx vitest run 2>&1 | tail -10`
Expected: all pass (the 3 theme/Sidebar suites from earlier + the 3 new analytics suites).

- [ ] **Step 6: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/routes/analytics/+page.svelte
git commit -m "feat(ui): wire library-distribution + ssh-analytics tabs into analytics page

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 7: Rebuild container + verify all 7 tabs in dark + light

**Files:** none (verification only — no commit unless a defect fix is needed)

- [ ] **Step 1: Rebuild the image + recreate the stack**

Run:
```bash
cd /Users/Erik/projects/cipherflag/frontend && npm run build 2>&1 | tail -3 && test -f build/index.html && echo FE-OK
cd /Users/Erik/projects/cipherflag && docker compose build cipherflag 2>&1 | tail -5
docker compose up -d 2>&1 | tail -5
docker compose ps --format '{{.Service}}={{.State}}'
```
Expected: FE-OK; image builds; both services running. (Docker build can take minutes — use a generous timeout and re-check `docker compose ps` rather than concluding failure from an empty result.)

- [ ] **Step 2: Confirm the 4 de-mooted routes no longer 404**

Run:
```bash
for p in chain-flow ownership deployment source-lineage; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' "http://localhost:8443/api/v1/stats/$p")
  echo "stats/$p -> $code"
done
```
Expected: each prints `200` (they require no auth at the API layer the same way the other stats routes don't — if any returns 401, that's an auth-middleware concern, not a 404; the de-moat goal is "not 404"). If any prints `404`, the route registration from Task 1 didn't make it into the running image — rebuild.

- [ ] **Step 3: Screenshot all 7 tabs in dark + light (auth-mocked, headless)**

Use the same auth-mocked headless-Chrome / Playwright approach used for the operator-shell verification:
- Intercept `GET /api/v1/auth/me` → `{ "user": { "id":"preview-admin","email":"p@e.com","display_name":"Preview Admin","role":"admin" } }` and `GET /api/v1/auth/status` → `{ "has_users": true }`, registered on the browser CONTEXT before navigation, each fulfilled 200 + `application/json`.
- For each tab id (`chain-flow`, `ownership`, `crypto-posture`, `expiry-forecast`, `source-lineage`, `library-dist`, `ssh-analytics`), navigate to `http://localhost:8443/analytics?tab=<id>`, wait for `networkidle`, screenshot to `/tmp/an_<id>_dark.png`.
- Then set `localStorage.setItem('cf-theme','light')`, reload, and capture `/tmp/an_<id>_light.png` for each.
- READ each screenshot and confirm: the tab renders its chart/content OR a graceful empty-state (NOT a raw error / 404 message); dark = navy palette, light = readable light palette (no dark-on-dark / white-on-white); the treemap (library-dist) and Sankey (chain-flow) render.
- Also capture the browser console for each tab and confirm NO `404` for `/stats/chain-flow`, `/stats/ownership`, `/stats/deployment`, `/stats/source-lineage`, `/stats/library-distribution`, `/stats/ssh-key-analytics`.

- [ ] **Step 4: Record results (no commit)**

Report per-tab: renders (data or empty-state)? dark OK? light OK? any console 404? Note that library-dist + ssh-analytics likely show the graceful empty-state in this dev DB (no host-based collector data) — that is the expected, correct behavior, not a failure. If a real visual defect is found (e.g. unreadable light-mode text in a ported tab), fix it minimally (tokenize the offending hardcoded color) and commit that fix separately; otherwise no commit.

---

## Notes for the implementer

- **Backend is registration-only.** Do NOT re-implement handlers/store/SQL — they exist. If `go build` fails after Task 1, the cause is a typo in the route lines, not missing handlers.
- **The 2 ported tabs are EE 2-space; the new treemap is CE tabs.** Keep each file internally consistent; don't reformat the verbatim ports.
- **Empty-states are expected to show** for library-dist/ssh-analytics in a dev DB without host-collector data — that's correct, not a bug.
- **adapter-static:** every frontend task ends green on `npm run build` with `build/index.html` present.
- **No push, no merge** without explicit user approval (per `docs/CLAUDE.md`). Branch is local.
- **Flaky bash:** redirect to a file and Read it if output is empty; never conclude from one blank result.
```
