# CipherFlag CE 3D PKI Constellation — Design Spec (Phase 3)

**Date:** 2026-06-01
**Status:** Approved (brainstorming complete, awaiting spec review → writing-plans)
**Branch:** `feat/ce-pki-constellation` (off `main`)

## Goal

Add EE's 3D "PKI Constellation" to CipherFlag CE as the PKI Explorer — a Three.js/Threlte force-directed 3D graph of the CA landscape, with a 2D SVG fallback for no-WebGL clients and live SSE node animation. Replace the existing 2D `/pki` route with a redirect to a new `/constellation` route, mirroring EE. This is Phase 3 (final) of the PKI/real-time effort (Phase 1 = PKI graph backend; Phase 2 = SSE live-updates — both merged).

## Background / current state (verified by code inspection 2026-06-01)

Both prerequisites are already in CE (the reason the effort was phased):
- **Graph backend (Phase 1):** the 3 endpoints the constellation calls are registered — `internal/api/server.go:176` `/graph/landscape/aggregated`, `:177` `/graph/ca/{fingerprint}/children`, `:178` `/graph/ca/{fingerprint}/blast-radius`. The client methods exist — `frontend/src/lib/api.ts:664` `getAggregatedLandscape`, `:665` `getCAChildren`, `:667` `getBlastRadius`. Supporting types (`AggregatedGraphNode/Edge`, `AggregatedLandscapeResponse`, `CAChildrenResponse`, `BlastRadiusResponse`) are present and byte-identical to EE.
- **SSE (Phase 2):** `frontend/src/lib/events.svelte.ts` exports `onAssetDiscovered` (`:65`) and `onAssetScored` (`:70`) with the same `(cb) => Unsubscribe` signature and identical payload types (`AssetDiscoveredEvent`/`AssetScoredEvent`) that the constellation's `$effect` reads (`asset_id`, `asset_type`, `grade`, `risk_score`).

CE has NO `frontend/src/lib/components/constellation/` dir and NO three/threlte/d3-force-3d usage anywhere. CE's current `/pki` is the working 2D ForceGraph explorer (restored Phase 1). EE's `/pki` is a redirect to `/constellation`.

This is **pure frontend** — no backend, data-model, or store work. Moat-clean: the 7 constellation components import only `@threlte/core`, `@threlte/extras`, `three` (+ `three/examples/jsm/controls/OrbitControls.js`), `d3-force-3d`, sibling constellation files, and `$lib/api` types — zero EE-only modules.

### Decisions locked during brainstorming

- **Route (Option A — mirror EE):** add `/constellation` (the 3D page); change `/pki/+page.svelte` to a redirect → `/constellation`; rename the Sidebar nav item "PKI Explorer" → "PKI Constellation" (keep `Orbit` icon, href → `/constellation`); update the breadcrumb map. One explorer, matches EE for upgrade/downgrade consistency.
- **Dependencies:** add the 4 net-new npm deps verbatim at EE's versions: `@threlte/core ^8.5.9`, `@threlte/extras ^9.14.6`, `three ^0.184.0`, `d3-force-3d ^3.0.6` (dependencies) + `@types/three ^0.184.0` (devDependencies). They are dynamically imported, so they land in a lazy chunk loaded only on `/constellation`, not the main bundle.
- **2D fallback:** keep EE's inline 2D SVG fallback verbatim — renders the same node/edge data as `<circle>`/`<line>` when `await import('@threlte/core')` throws (no-WebGL / chunk-load failure). Graceful degradation.
- **Verbatim port:** the 7 components + page are copied from EE; the only content edits are (a) the page's SSE import path `$lib/api/events.svelte` → `$lib/events.svelte` (CE's flat layout), and (b) a trivial CE rule for the `cf-dark-zone` wrapper class (or drop it). The `$lib/api` type imports resolve as-is against CE's flat `api.ts`.

## Architecture

Layers ordered so the project builds after each:

### Layer 1 — Dependencies

Add to `frontend/package.json`: dependencies `@threlte/core ^8.5.9`, `@threlte/extras ^9.14.6`, `three ^0.184.0`, `d3-force-3d ^3.0.6`; devDependencies `@types/three ^0.184.0`. Run `npm install` to update the lockfile. (CE already has the standard d3 family but none of these.) Adapter-static (`fallback:'index.html', strict:false`) handles the lazy dynamic-import chunk.

### Layer 2 — Constellation components (verbatim port from EE)

Create `frontend/src/lib/components/constellation/` with 7 files, copied verbatim from `/Users/Erik/projects/cipherflag-EE/frontend/src/lib/components/constellation/` (add CE Apache header where EE files carry one; preserve the EE indentation within each file):
- `constellation-types.ts` — `Node3D`, `Edge3D`, `ConstellationMode`, `GRADE_COLORS`, `gradeColor()`, `nodeRadius3D()`, `nodeShape()`. Pure TS, no imports.
- `constellation-physics.ts` — `createSimulation3D()` (d3-force-3d: forceManyBody/forceLink/forceCenter/forceCollide, pre-settles 250 ticks), `apiNodeToNode3D()`, `apiEdgeToEdge3D()`. Dynamic-imports `d3-force-3d`; imports types `AggregatedGraphNode/AggregatedGraphEdge` from `$lib/api` (resolves as-is in CE).
- `ConstellationScene.svelte` — `@threlte/core` `Canvas` wrapper + background-click. Props: nodes, edges, hovered/selected IDs, dimmedNodes, onHover, onNodeClick, onBackgroundClick, onReady.
- `ConstellationSceneBody.svelte` — `@threlte/core` `T`, `@threlte/extras` `OrbitControls`/`interactivity`; camera, lights, fog; module export `ConstellationSceneApi` (zoomIn/zoomOut/fitView; fitView computes scene bounds).
- `ConstellationNodes.svelte` — per-frame mesh position sync via `useTask`; maintains a meshRefs map.
- `ConstellationNode.svelte` — one mesh; shape by node type (sphere/octahedron/box/wireframe-sphere via `nodeShape()`), emissive on hover/select.
- `ConstellationEdges.svelte` — single `LineSegments` with vertex colors, grows BufferGeometry, updates per frame via `useTask`.

(CE-fed `AggregatedGraphNode.type` is only `root|intermediate|leaf`; the `ssh_key|library|host` shape branches in `nodeShape()` are harmless dead code in CE — no dependency.)

### Layer 3 — The constellation page (verbatim port + 1 import rewrite)

Create `frontend/src/routes/constellation/+page.svelte`, copied verbatim from EE's `frontend/src/routes/constellation/+page.svelte`, with ONE edit: change the import
`import { onAssetDiscovered, onAssetScored } from '$lib/api/events.svelte';` → `from '$lib/events.svelte';`
(`import { api, type BlastRadiusResponse } from '$lib/api';` resolves as-is.) The page provides: state (mode explore/search/blast-radius, nodes/edges, expandedCAs, selectedGrades, showExpiredOnly, threlteAvailable, sceneApi), the `dimmedNodes` derived set, `onMount` (Threlte-availability check + `getAggregatedLandscape`), the SSE `$effect` (cert-only inject/re-grade), handlers (node/background click, search, grade/expired filters, Escape, `handleExpandCA`→getCAChildren, `handleBlastRadius`→getBlastRadius, navigate-to-cert), the `{#if !threlteAvailable}` 2D SVG fallback else `<ConstellationScene>`, and the overlay UI (toolbar + grade pills + counts, zoom controls via sceneApi, legend, hover tooltip, detail panel). If the page wraps in `cf-dark-zone` (undefined in CE), add a minimal CSS rule for it in the page's `<style>` or drop the class.

### Layer 4 — Route + nav swap

- Replace `frontend/src/routes/pki/+page.svelte` with EE's redirect page (verbatim): `onMount(() => goto('/constellation', { replaceState: true }))`, a "Redirecting…" title + centered message, `.redirect-page` style using `var(--cf-text-muted)`. (This removes the 2D explorer as a standalone route; no 2D component code is deleted — the `graph/` set stays for other uses.)
- `frontend/src/lib/components/layout/Sidebar.svelte`: change the nav entry `{ label: 'PKI Explorer', href: '/pki', icon: Orbit }` → `{ label: 'PKI Constellation', href: '/constellation', icon: Orbit }`.
- `frontend/src/routes/+layout.svelte`: in `BREADCRUMB_LABELS`, add `constellation: 'PKI Constellation'` (keep the existing `pki` entry harmless, or update it — the `/pki` redirect means users won't dwell there).

## Data flow

```
Initial:  onMount → (await import('@threlte/core') → threlteAvailable) → api.getAggregatedLandscape()
          → apiNodeToNode3D/apiEdgeToEdge3D → createSimulation3D (d3-force-3d, 250 pre-ticks)
          → ConstellationScene renders; useTask syncs x/y/z onto meshes + edge geometry each frame
Interact: expandCA → api.getCAChildren(fp) (append + warm sim); blast-radius → api.getBlastRadius(fp)
          (dim outside descendant set); filters/search → dimmedNodes derived
Live:     $effect → onAssetDiscovered (cert-only: build gray '?' Node3D, append, sim.alpha(0.3).restart())
                  → onAssetScored   (cert-only: find by asset_id, mutate grade/color/pulseRate, reassign)
Fallback: !threlteAvailable → inline SVG <circle>/<line> from the same nodes/edges (x/y, ignore z)
```

## Error handling & graceful degradation (all in the verbatim-ported page)

1. **Threlte/WebGL unavailable → 2D SVG fallback** (the headline case). `await import('@threlte/core')` in try/catch → `threlteAvailable=false` → inline 2D graph. Covers no-WebGL clients, failed lazy-chunk download, Threlte runtime throw.
2. **Data-fetch failure:** `onMount` fetch wrapped → empty graph (not a crash) on `getAggregatedLandscape` failure; `getCAChildren`/`getBlastRadius` failures on interaction are caught and leave the current graph unchanged. (Confirm the ported page doesn't white-screen.)
3. **Empty data:** empty arrays → empty scene/SVG; scene still initializes (camera/controls/lights). No special empty-state.
4. **SSE not connected:** `$effect` never fires; graph is a usable static snapshot; TopBar dot (Phase 2) signals disconnect honestly.
5. **Malformed/unknown events:** `$effect` filters `asset_type==='certificate'`; events client swallows malformed JSON (Phase 2); a scored event for an unknown asset_id no-ops.

## Testing strategy

**Type-check + build (primary machine gates):**
- `npx svelte-check` 0 errors — compiles the 7 components + page against CE types; proves the threlte/three/d3-force-3d imports resolve and the `$lib/events.svelte` rewrite + `$lib/api` type imports type-check.
- `npm run build` emits `build/index.html` AND a lazy constellation chunk — confirm the 3D deps bundle into a separate dynamically-imported chunk, not the main entry; confirm the main bundle didn't balloon.
- `go build ./...` stays green (backend untouched).

**Frontend unit (vitest) — selective:**
- Test the pure logic (no WebGL): `constellation-types.ts` (`gradeColor`/`nodeRadius3D`/`nodeShape`) and `constellation-physics.ts` mappers (`apiNodeToNode3D`/`apiEdgeToEdge3D`) — assert a sample `AggregatedGraphNode` maps to the right `Node3D` fields.
- Do NOT unit-test the Svelte 3D components (require a WebGL context jsdom lacks; verbatim EE port) — note this explicitly rather than fake coverage. Do NOT assert `createSimulation3D` positions (non-deterministic).

**Integration / visual gate (real browser — the real proof):**
- `docker compose build && up` (rebuild with new deps).
- Headless **Chrome** (real WebGL) auth-mocked `/constellation`: read the screenshot → confirm the 3D canvas renders nodes (spheres/octahedra in the navy scene) + toolbar/legend, in dark + light. Force the fallback (block the chunk / disable WebGL) → confirm the 2D SVG renders. Confirm `/pki` redirects to `/constellation`. Confirm no console errors.
- Live check: trigger an `asset.discovered` → confirm a node animates in (closes the loop with Phase 2 SSE).

**Out of scope for tests:** exact 3D positions/camera math; OrbitControls interaction (manual/visual only).

## File manifest

| Path | Action | Responsibility |
|---|---|---|
| `frontend/package.json` (+ lockfile) | modify | add 4 deps + @types/three |
| `frontend/src/lib/components/constellation/constellation-types.ts` | create (port) | Node3D/Edge3D types + color/size/shape helpers |
| `frontend/src/lib/components/constellation/constellation-physics.ts` | create (port) | 3D force sim + API→3D mappers |
| `frontend/src/lib/components/constellation/ConstellationScene.svelte` | create (port) | Canvas wrapper + bg-click |
| `frontend/src/lib/components/constellation/ConstellationSceneBody.svelte` | create (port) | camera/controls/lights/zoom+fit API |
| `frontend/src/lib/components/constellation/ConstellationNodes.svelte` | create (port) | per-frame mesh position sync |
| `frontend/src/lib/components/constellation/ConstellationNode.svelte` | create (port) | single node mesh |
| `frontend/src/lib/components/constellation/ConstellationEdges.svelte` | create (port) | edge LineSegments |
| `frontend/src/routes/constellation/+page.svelte` | create (port + 1 import rewrite) | the 3D explorer page |
| `frontend/src/lib/components/constellation/*.svelte.test.ts` (1-2) | create | unit tests for types + physics mappers |
| `frontend/src/routes/pki/+page.svelte` | replace (with redirect) | redirect → /constellation |
| `frontend/src/lib/components/layout/Sidebar.svelte` | modify | nav item → PKI Constellation / /constellation |
| `frontend/src/routes/+layout.svelte` | modify | breadcrumb label for constellation |

## Non-goals / out of scope

- No backend / data-model / store work — CE already has the endpoints + SSE + types.
- No changes to the existing 2D `graph/` components (the constellation is self-contained; its fallback is its own inline SVG). The 2D `/pki` route is removed (redirect) but no 2D component code is deleted.
- No `?select=` deep-link handling on the constellation (EE's page doesn't read it; the Chain-Flow `/pki?select=` link will redirect to `/constellation` and the param silently no-ops — acceptable; a follow-up could add it).
- No new backend endpoints; the `ssh_key|library|host` node-shape branches stay as harmless dead code (CE feeds only cert-graph nodes).

## References

- `project_ce_v2_strategy` (memory) — open-core de-moat strategy.
- EE source of truth: `/Users/Erik/projects/cipherflag-EE` (`frontend/src/lib/components/constellation/*`, `frontend/src/routes/constellation/+page.svelte`, `frontend/src/routes/pki/+page.svelte`, `frontend/package.json`).
- Phase 1 (PKI graph backend) + Phase 2 (SSE live-updates) — the prerequisites this consumes.
