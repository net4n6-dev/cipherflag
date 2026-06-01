# CipherFlag CE 3D PKI Constellation Implementation Plan (Phase 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add EE's 3D "PKI Constellation" to CipherFlag CE as the PKI Explorer — a Three.js/Threlte force-directed 3D CA graph with a 2D SVG fallback and live SSE node animation — replacing the 2D `/pki` with a redirect to a new `/constellation`.

**Architecture:** Pure frontend port. Both prerequisites are already in CE (Phase 1 `/graph/*` endpoints + types; Phase 2 SSE callbacks). Add 4 npm deps (dynamically imported → lazy chunk), copy 7 constellation components + 1 page verbatim from EE (one SSE import-path rewrite), add unit tests for the pure-logic modules, then swap the route + nav (redirect `/pki` → `/constellation`).

**Tech Stack:** SvelteKit 2 / Svelte 5 runes, Three.js (`three`), Threlte (`@threlte/core`, `@threlte/extras`), `d3-force-3d`, adapter-static SPA embedded in the Go binary.

**Spec:** `docs/superpowers/specs/2026-06-01-pki-constellation-design.md`
**Branch:** `feat/ce-pki-constellation` (already created off `main`; spec already committed at HEAD).

---

## Pre-flight (read once)

- **Repos:** CE = `/Users/Erik/projects/cipherflag` (branch `feat/ce-pki-constellation`). EE source-of-truth (read-only) = `/Users/Erik/projects/cipherflag-EE`.
- **Pure frontend.** No Go/backend/migration changes. CE already has: the 3 `/graph/*` routes (server.go), the 3 api methods + the `AggregatedGraphNode/Edge`, `AggregatedLandscapeResponse`, `CAChildrenResponse`, `BlastRadiusResponse` types (api.ts:177-220), and the SSE `onAssetDiscovered`/`onAssetScored` callbacks (events.svelte.ts). Do NOT re-add any of these.
- **Verbatim port via copy.** The 7 components + page are copied from EE then minimally edited. EE's constellation files carry NO license header (frontend convention) — copy as-is, prepend nothing. The ONLY content edits are: (a) the page's SSE import `$lib/api/events.svelte` → `$lib/events.svelte`; (b) a trivial CSS rule for the `cf-dark-zone` wrapper class (undefined in CE). Everything else is byte-for-byte from EE.
- **Import paths:** EE and CE share the module alias `$lib`. `import { api, type BlastRadiusResponse } from '$lib/api'` and `constellation-physics.ts`'s `import type { AggregatedGraphNode, AggregatedGraphEdge } from '$lib/api'` resolve as-is against CE's flat `api.ts`. The ONLY path that differs is the SSE one (CE has flat `$lib/events.svelte`, not `$lib/api/events.svelte`).
- **Lazy chunk:** three/threlte/d3-force-3d are dynamically imported (`await import(...)`), so Vite emits them in a separate chunk loaded only on `/constellation`. adapter-static (`fallback:'index.html', strict:false`) serves it fine.
- **Build gates:** every frontend task ends green on `npx svelte-check` (0 errors) + `npm run build` emitting `frontend/build/index.html`. `go build ./...` must stay green (unaffected, but confirm at the end).
- **Flaky bash:** if a command returns empty, re-run or redirect to a file and read it. Quote real `git log -1 --format='%h %s'` output for SHAs.
- **Do NOT** `git add -A` — untracked `docs/`, `.claude/`, `research/`, `.superpowers/` dirs must not be committed. Stage explicit paths.
- **Out of scope:** backend/data-model/store work; the existing 2D `graph/` components (untouched — kept for other uses); `?select=` deep-link handling on the constellation.

---

## File manifest

| Path | Action | Responsibility |
|---|---|---|
| `frontend/package.json` (+ `package-lock.json`) | modify | add @threlte/core, @threlte/extras, three, d3-force-3d, @types/three |
| `frontend/src/lib/components/constellation/constellation-types.ts` | create (cp) | Node3D/Edge3D + gradeColor/nodeRadius3D/nodeShape |
| `frontend/src/lib/components/constellation/constellation-physics.ts` | create (cp) | createSimulation3D + apiNode→Node3D / apiEdge→Edge3D |
| `frontend/src/lib/components/constellation/ConstellationScene.svelte` | create (cp) | Canvas wrapper |
| `frontend/src/lib/components/constellation/ConstellationSceneBody.svelte` | create (cp) | camera/controls/lights/zoom+fit API |
| `frontend/src/lib/components/constellation/ConstellationNodes.svelte` | create (cp) | per-frame mesh sync |
| `frontend/src/lib/components/constellation/ConstellationNode.svelte` | create (cp) | single node mesh |
| `frontend/src/lib/components/constellation/ConstellationEdges.svelte` | create (cp) | edge LineSegments |
| `frontend/src/routes/constellation/+page.svelte` | create (cp + 1 import rewrite + cf-dark-zone rule) | the 3D explorer page |
| `frontend/src/lib/components/constellation/constellation.test.ts` | create | unit tests: types + physics mappers |
| `frontend/src/routes/pki/+page.svelte` | replace | redirect → /constellation |
| `frontend/src/lib/components/layout/Sidebar.svelte` | modify | nav: PKI Constellation → /constellation |
| `frontend/src/routes/+layout.svelte` | modify | breadcrumb: add constellation label |

Tasks ordered so the project builds after each.

---

## Task 1: Add the 3D npm dependencies

**Files:**
- Modify: `frontend/package.json`, `frontend/package-lock.json`

- [ ] **Step 1: Install the deps (exact EE versions)**

Run:
```bash
cd /Users/Erik/projects/cipherflag/frontend
npm install @threlte/core@^8.5.9 @threlte/extras@^9.14.6 three@^0.184.0 d3-force-3d@^3.0.6
npm install --save-dev @types/three@^0.184.0
```
Expected: `package.json` gains `@threlte/core`, `@threlte/extras`, `three`, `d3-force-3d` under `dependencies` and `@types/three` under `devDependencies`; lockfile updates. (Network install — this is the one task that fetches packages.)

- [ ] **Step 2: Verify the deps resolve + the app still builds**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npm ls @threlte/core @threlte/extras three d3-force-3d @types/three 2>&1 | tail -8`
Expected: all five listed at the installed versions (no "missing"/"UNMET").
Run: `npm run build 2>&1 | tail -5 && test -f build/index.html && echo BUILD-OK`
Expected: BUILD-OK. (Nothing imports the new deps yet — this just confirms the install didn't break the existing build.)

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/package.json frontend/package-lock.json
git commit -m "build(ui): add three.js + threlte + d3-force-3d for 3D constellation

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 2: Port the constellation components (7 files, verbatim)

**Files:**
- Create: the 7 files under `frontend/src/lib/components/constellation/` (copied from EE)

These are copied verbatim from EE — no logic edits. They have no license header (frontend convention; copy as-is). After copying, type-check confirms the threlte/three/d3-force-3d/`$lib/api` imports all resolve.

- [ ] **Step 1: Copy all 7 component files verbatim from EE**

Run:
```bash
SRC=/Users/Erik/projects/cipherflag-EE/frontend/src/lib/components/constellation
DST=/Users/Erik/projects/cipherflag/frontend/src/lib/components/constellation
mkdir -p "$DST"
cp "$SRC/constellation-types.ts" "$DST/"
cp "$SRC/constellation-physics.ts" "$DST/"
cp "$SRC/ConstellationScene.svelte" "$DST/"
cp "$SRC/ConstellationSceneBody.svelte" "$DST/"
cp "$SRC/ConstellationNodes.svelte" "$DST/"
cp "$SRC/ConstellationNode.svelte" "$DST/"
cp "$SRC/ConstellationEdges.svelte" "$DST/"
ls -1 "$DST"
```
Expected: 7 files in CE's constellation dir.

- [ ] **Step 2: Confirm no stray import needs rewriting in the components**

Run: `grep -rnE "from '\\\$lib" /Users/Erik/projects/cipherflag/frontend/src/lib/components/constellation/`
Expected: ONLY `constellation-physics.ts` importing types from `$lib/api` (`AggregatedGraphNode`, `AggregatedGraphEdge`) — which resolves as-is against CE's flat `api.ts`. If any component imports `$lib/api/events.svelte` or another `$lib/api/<subpath>` that doesn't exist in CE, STOP and report (the spec says only the PAGE has the SSE import; components should not). No edit expected here.

- [ ] **Step 3: Type-check the components**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -20`
Expected: 0 errors in the constellation components. The threlte/three/d3-force-3d imports must resolve (Task 1 installed them); the `$lib/api` type import must resolve. Pre-existing warnings in OTHER files are fine. If `three/examples/jsm/controls/OrbitControls.js` is flagged as a missing type, that's a known three.js subpath — confirm `@types/three` is installed (Task 1); it ships those types. If a real error appears, report it (do NOT alter the ported logic to paper over a dep issue — fix the dep/import).

- [ ] **Step 4: Build**

Run: `npm run build 2>&1 | tail -5 && test -f build/index.html && echo BUILD-OK`
Expected: BUILD-OK. (Components aren't imported by any route yet — Task 4 wires the page — so this confirms they compile in isolation.)

- [ ] **Step 5: Commit (stage ONLY the 7 component files — never git add -A)**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/components/constellation/constellation-types.ts \
        frontend/src/lib/components/constellation/constellation-physics.ts \
        frontend/src/lib/components/constellation/ConstellationScene.svelte \
        frontend/src/lib/components/constellation/ConstellationSceneBody.svelte \
        frontend/src/lib/components/constellation/ConstellationNodes.svelte \
        frontend/src/lib/components/constellation/ConstellationNode.svelte \
        frontend/src/lib/components/constellation/ConstellationEdges.svelte
git commit -m "feat(ui): port 3D constellation components (threlte scene + physics)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 3: Unit tests for the pure-logic modules

**Files:**
- Create: `frontend/src/lib/components/constellation/constellation.test.ts`

Only the pure (no-WebGL) logic is unit-tested: the type helpers and the API→3D mappers. The Svelte 3D components require a real WebGL context (jsdom lacks it) and are a verbatim EE port — they are verified in the Task 6 visual gate, not faked here.

- [ ] **Step 1: Read the real signatures before writing the test**

READ `frontend/src/lib/components/constellation/constellation-types.ts` and `constellation-physics.ts` to confirm the EXACT exported names + signatures: `gradeColor(grade: string)`, `nodeRadius3D(...)`, `nodeShape(type: string)`, `apiNodeToNode3D(apiNode)`, `apiEdgeToEdge3D(apiEdge)`. The test below assumes these names; if any differs (e.g. `nodeRadius3D` takes a node vs a number, or a mapper is named differently), ADJUST the test to match the real exports. Note any adjustment in your report.

- [ ] **Step 2: Write the test**

Create `frontend/src/lib/components/constellation/constellation.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { gradeColor, nodeShape } from './constellation-types';
import { apiNodeToNode3D } from './constellation-physics';

describe('constellation-types', () => {
	it('gradeColor returns distinct colors for grades', () => {
		const f = gradeColor('F');
		const a = gradeColor('A+');
		expect(typeof f).toBe('string');
		expect(f.startsWith('#') || f.startsWith('rgb')).toBe(true);
		expect(f).not.toBe(a); // worst vs best must differ
	});

	it('gradeColor handles unknown grade without throwing', () => {
		expect(() => gradeColor('?')).not.toThrow();
	});

	it('nodeShape maps the CE node types', () => {
		// CE feeds only root|intermediate|leaf; assert each yields a string shape id
		for (const t of ['root', 'intermediate', 'leaf']) {
			expect(typeof nodeShape(t)).toBe('string');
		}
	});
});

describe('constellation-physics mappers', () => {
	it('apiNodeToNode3D maps id + grade from an AggregatedGraphNode', () => {
		const apiNode = {
			id: 'fp-abc',
			label: 'Root CA',
			type: 'root',
			grade: 'A+',
			cert_count: 42,
			avg_score: 95,
		} as any;
		const n = apiNodeToNode3D(apiNode);
		expect(n.id).toBe('fp-abc');
		expect(n.grade).toBe('A+');
		// color should be derived from the grade
		expect(typeof n.color).toBe('string');
	});
});
```
NOTE: this test imports ONLY the pure modules (no `.svelte` components → no WebGL). The sample `apiNode` shape mirrors CE's `AggregatedGraphNode` (api.ts:177). If `apiNodeToNode3D` reads fields not in the sample (e.g. it requires `x`/`y`/`z` or a different field), read the function and extend the sample so the mapping is exercised — but keep the assertions on stable outputs (id, grade, a color string). If `nodeShape`/`gradeColor` have different exact signatures, adjust per Step 1.

- [ ] **Step 3: Run the test**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx vitest run src/lib/components/constellation/constellation.test.ts 2>&1 | tail -20`
Expected: tests pass. If a mapper assertion fails because the real output differs from the assumption, FIX THE TEST to assert the real (correct) behavior — do NOT change the ported physics/types code (it's verbatim EE; the test must match it, not vice versa). Report any such adjustment.

- [ ] **Step 4: Type-check**

Run: `npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -6`
Expected: 0 errors in the test file.

- [ ] **Step 5: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/components/constellation/constellation.test.ts
git commit -m "test(ui): unit tests for constellation type helpers + 3D mappers

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 4: Port the constellation page

**Files:**
- Create: `frontend/src/routes/constellation/+page.svelte` (copied from EE + 1 import rewrite + cf-dark-zone rule)

- [ ] **Step 1: Copy the page verbatim from EE**

Run:
```bash
mkdir -p /Users/Erik/projects/cipherflag/frontend/src/routes/constellation
cp /Users/Erik/projects/cipherflag-EE/frontend/src/routes/constellation/+page.svelte \
   /Users/Erik/projects/cipherflag/frontend/src/routes/constellation/+page.svelte
```

- [ ] **Step 2: Rewrite the SSE import path (the one required content edit)**

In `frontend/src/routes/constellation/+page.svelte`, change:
```svelte
  import { onAssetDiscovered, onAssetScored } from '$lib/api/events.svelte';
```
to:
```svelte
  import { onAssetDiscovered, onAssetScored } from '$lib/events.svelte';
```
(CE's events client is the flat `$lib/events.svelte`, not EE's `$lib/api/events.svelte`. Leave `import { api, type BlastRadiusResponse } from '$lib/api'` unchanged — it resolves.)

- [ ] **Step 3: Add a CSS rule for the `cf-dark-zone` wrapper class**

The page's root element is `<div class="constellation-page cf-dark-zone">`. `cf-dark-zone` is undefined in CE. In the page's `<style>` block, add a minimal rule so the class is defined (it's a full-bleed dark canvas backdrop):
```css
	.cf-dark-zone {
		background: var(--cf-bg-base);
	}
```
(`--cf-bg-base` is defined in CE's app.css. If the `.constellation-page` rule already sets the background, this is belt-and-suspenders; add it regardless so the class isn't an undefined no-op. Do NOT remove the class from the markup.)

- [ ] **Step 4: Verify no other unresolved import / undefined symbol**

Run: `grep -nE "from '\\\$lib" frontend/src/routes/constellation/+page.svelte`
Expected: `$lib/api` (api + BlastRadiusResponse — resolves), `$lib/events.svelte` (the rewritten one — resolves), the constellation component/type/physics imports (from `$lib/components/constellation/...` — Task 2 created them). NO remaining `$lib/api/events.svelte` or other `$lib/api/<subpath>`.

- [ ] **Step 5: Type-check + build**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -20`
Expected: 0 errors in the page. (The page imports the Task-2 components + the api/events — all resolve.) If svelte-check flags an event-callback type, recall the events client's `onAssetScored`/`onAssetDiscovered` take `(data) => void`; the page's handlers match EE's. Report any real error rather than papering over.
Run: `npm run build 2>&1 | tail -6 && test -f build/index.html && echo BUILD-OK`
Expected: BUILD-OK. Also confirm Vite emitted a lazy chunk containing three/threlte: `ls -la build/_app/immutable/chunks/ 2>/dev/null | wc -l` (a chunk dir with multiple files) — the three.js code should be in a chunk, not the main entry. (Best-effort check; the build succeeding with the dynamic imports is the real signal.)

- [ ] **Step 6: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/routes/constellation/+page.svelte
git commit -m "feat(ui): port 3D PKI constellation page (graph endpoints + SSE + 2D fallback)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 5: Route + nav swap (/pki redirect, sidebar, breadcrumb)

**Files:**
- Replace: `frontend/src/routes/pki/+page.svelte`
- Modify: `frontend/src/lib/components/layout/Sidebar.svelte`
- Modify: `frontend/src/routes/+layout.svelte`

- [ ] **Step 1: Replace /pki with the redirect page**

Overwrite `frontend/src/routes/pki/+page.svelte` with EE's redirect (verbatim from EE, which CE can use as-is — `--cf-text-muted` is defined in CE):
```svelte
<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  onMount(() => {
    goto('/constellation', { replaceState: true });
  });
</script>

<svelte:head>
  <title>Redirecting... - CipherFlag</title>
</svelte:head>

<div class="redirect-page">
  Redirecting to Constellation...
</div>

<style>
  .redirect-page {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--cf-text-muted);
    font-size: 13px;
  }
</style>
```
(This removes the 2D ForceGraph explorer markup. The `$lib/components/graph/` components are NOT deleted — they remain for any other consumer. This page no longer imports them.)

- [ ] **Step 2: Update the Sidebar nav entry**

In `frontend/src/lib/components/layout/Sidebar.svelte`, find:
```svelte
		{ label: 'PKI Explorer', href: '/pki', icon: Orbit },
```
Change it to:
```svelte
		{ label: 'PKI Constellation', href: '/constellation', icon: Orbit },
```
(Keep the `Orbit` icon and the surrounding group structure unchanged.)

- [ ] **Step 3: Update the breadcrumb map**

In `frontend/src/routes/+layout.svelte`, the `BREADCRUMB_LABELS` map currently has `pki: 'PKI Explorer',`. Add a `constellation` entry (and relabel `pki` so the brief redirect shows a sensible crumb). Change:
```ts
		pki: 'PKI Explorer',
```
to:
```ts
		pki: 'PKI Constellation',
		constellation: 'PKI Constellation',
```
(The breadcrumb derives from the path segment; `/constellation` → "PKI Constellation". The `pki` entry is relabeled for the redirect instant.)

- [ ] **Step 4: Type-check + build**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -10`
Expected: 0 errors. (The redirect page is trivial; the Sidebar/breadcrumb edits are data-only. Note: the old `/pki` page's imports of `$lib/components/graph/*` are gone — confirm svelte-check doesn't now flag those graph components as unused-files; unused *files* aren't errors, only unused in-file symbols are. If a graph component becomes a "declared but never read" warning somewhere, that's pre-existing/elsewhere — don't chase it.)
Run: `npm run build 2>&1 | tail -5 && test -f build/index.html && echo BUILD-OK`
Expected: BUILD-OK.

- [ ] **Step 5: Run the full frontend test suite (regression)**

Run: `npx vitest run 2>&1 | tail -8`
Expected: all pass (the prior theme/Sidebar/analytics/SSE suites + the new constellation unit tests). Report counts.

- [ ] **Step 6: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/routes/pki/+page.svelte frontend/src/lib/components/layout/Sidebar.svelte frontend/src/routes/+layout.svelte
git commit -m "feat(ui): make PKI Constellation the explorer — /pki redirects to /constellation

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 6: Rebuild container + visual verification (3D + fallback + SSE)

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
Expected: FE-BUILD-OK; image builds; both services running. (Docker build takes minutes — generous timeout; re-check `docker compose ps` rather than concluding failure from empty output.)

- [ ] **Step 2: Confirm /pki redirects + /constellation serves**

Run:
```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://localhost:8443/pki
curl -sS -o /dev/null -w '%{http_code}\n' http://localhost:8443/constellation
```
Expected: both 200 (SPA fallback serves index.html for both client routes; the redirect happens in-app via goto). The real redirect + render check is the headless step below.

- [ ] **Step 3: Headless Chrome (real WebGL) — render the 3D scene, both themes**

Use the auth-mocked headless-Chrome / Playwright approach from prior phases (Playwright from /Users/Erik/projects/testify/e2e). Use a CHROME context with WebGL enabled (default for headless Chrome `--use-gl=angle`/swiftshader — confirm the browser launches with GPU/swiftshader so WebGL works; Playwright chromium supports swiftshader WebGL headless). Mock `GET /api/v1/auth/me` → admin + `/api/v1/auth/status` → `{has_users:true}` (context-level, 200 application/json). Optionally stub `**/api/v1/graph/landscape/aggregated` with a small sample (3 nodes/2 edges in the AggregatedLandscapeResponse shape) so the scene has content if the dev DB is empty.
- Navigate to `http://localhost:8443/pki` → confirm it lands on `/constellation` (page.url ends with /constellation) — proves the redirect.
- Wait for the canvas / scene to mount (wait for `canvas` element OR the `.fallback-svg`), screenshot `/tmp/constellation_dark.png`.
- `localStorage.setItem('cf-theme','light')`, reload, screenshot `/tmp/constellation_light.png`.
- Capture console messages.

- [ ] **Step 4: READ the screenshots + judge**

READ `/tmp/constellation_dark.png` and `/tmp/constellation_light.png`. Confirm:
- A 3D scene renders (a `<canvas>` with visible nodes — spheres/octahedra — and edges in the navy backdrop) OR, if WebGL is unavailable in the headless GPU, the 2D SVG fallback renders (circles + lines). EITHER is a pass for "the page works" — note which path rendered and why.
- The overlay UI is present: toolbar (search + grade pills), zoom controls, legend, and the operator shell around it (sidebar shows "PKI Constellation" active).
- Dark = navy palette; light = readable light palette.
- No uncaught console errors (a WebGL-unavailable warning that triggers the fallback is expected/fine; an actual exception is not).

- [ ] **Step 5: Force-test the 2D fallback (if Step 3 rendered 3D)**

To prove the fallback path: in a Playwright context, block the threlte chunk (route-abort any request whose URL contains `three` or `threlte`, OR launch with WebGL disabled) and reload `/constellation`. Confirm the inline 2D SVG graph renders (`.fallback-svg` present with `<circle>`/`<line>`), not a blank/error page. Screenshot `/tmp/constellation_fallback.png` and READ it. (If Step 3 already rendered the 2D fallback because the headless GPU lacks WebGL, this step is already demonstrated — note that and skip.)

- [ ] **Step 6: Live SSE check (closes the loop with Phase 2)**

With `/constellation` open in a headless page (or via the curl stream approach), trigger an `asset.discovered` for a certificate (INSERT a cert row in the dev DB as in Phase 2's verification, unique fingerprint). Confirm (via a brief wait + re-screenshot or a DOM node-count check) that a new node appears / the scene reacts. If wiring a live headless capture is impractical, document that the SSE consumer is verified by: (a) Phase 2 proved the stream delivers `asset.discovered`, and (b) the page's `$effect` subscribes the same callbacks — and confirm by reading the ported `$effect` that it appends a node on the event. Clean up any inserted test row.

- [ ] **Step 7: Report (no commit)**

Report: FE+docker build; `docker compose ps`; the curl codes; redirect confirmed (/pki → /constellation); per-theme screenshot judgment (3D scene or fallback rendered? overlay UI present? readable both themes?); the fallback-path result; the SSE check result; any console error. Overall PASS/FAIL for "the 3D constellation renders (or gracefully falls back), /pki redirects, and the page is wired to live SSE". If a genuine defect is found (page throws, fallback blank, redirect broken), describe it precisely; fix only if trivial, else report for the controller. Leave the container running for smoke-test.

---

## Notes for the implementer

- **Verbatim port.** The 7 components + page are EE's exact code. The ONLY content edits: the page's SSE import path (`$lib/api/events.svelte` → `$lib/events.svelte`) and the `cf-dark-zone` CSS rule. Do NOT refactor, rename, or "improve" the ported code — byte-parity with EE is intended (it's proven 3D code, and parity preserves upgrade/downgrade consistency).
- **No backend work.** CE already has the endpoints, types, and SSE. If something the page calls is "undefined", it's an import-path issue, not a missing feature — check the path, don't add backend code.
- **WebGL in tests.** jsdom has no WebGL, so the 3D Svelte components are NOT unit-tested (only the pure type/physics logic is). The 3D render is proven in the headless-Chrome visual gate (Task 6). Don't try to mock a WebGL context in vitest.
- **Lazy chunk.** three/threlte are dynamically imported — the build emits them in a separate chunk. If `npm run build` ever pulls them into the main entry (a static import slipped in), that's a regression; the ported code uses `await import(...)`, so keep it that way.
- **No push, no merge** without explicit user approval (per `docs/CLAUDE.md`). Branch is local.
- **Flaky bash:** redirect to a file and Read it if output is empty; quote real `git log -1` output for SHAs.
```
