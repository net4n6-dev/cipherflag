# CipherFlag CE Operator Shell — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace CipherFlag CE's v1 top-bar layout with EE's operator shell (AppShell + Sidebar + TopBar + theme store), reproducing EE's look-and-feel exactly so the upgrade/downgrade experience is one coherent product.

**Architecture:** Port three Svelte 5 components + a theme store from EE (`/Users/Erik/projects/cipherflag-EE`) into CE under `frontend/src/lib/components/layout/` and `frontend/src/lib/stores/`, adapting (a) the Sidebar nav to CE's real routes, (b) the badge text "EE"→"CE", (c) import paths (`$lib/api/auth`→`$lib/auth`), and (d) dropping the SSE backend (dot renders disconnected). Add EE's `--cf-*` design tokens (dark + light) additively to CE's `app.css`, plus fonts and global rules. Rewrite the root `+layout.svelte` to compose AppShell while preserving CE's existing auth gate.

**Tech Stack:** SvelteKit 2 / Svelte 5 (runes), `lucide-svelte`, `@fontsource-variable/inter` + `@fontsource-variable/jetbrains-mono`, adapter-static SPA embedded in the Go binary.

**Spec:** `docs/superpowers/specs/2026-05-31-ce-operator-shell-design.md`

---

## Pre-flight (read once)

- **Two repos on disk:** CE (this repo) `/Users/Erik/projects/cipherflag`; EE source `/Users/Erik/projects/cipherflag-EE`. You copy/adapt EE frontend components into CE. CE is **Svelte 5** (`^5.49.2`) — same as EE, so runes (`$props`, `$state`, `$derived`) port directly.
- **CE auth module** is `$lib/auth` (flat file) exporting `getCurrentUser, checkAuthStatus, logout, type AuthUser`. EE uses `$lib/api/auth` — **rewrite that import path** in anything ported that references auth.
- **CE has no SSE backend.** EE's TopBar takes `sseConnected: boolean`; CE passes `false` (dot shows disconnected — honest, visual parity). Do NOT port EE's `$lib/api/events.svelte`.
- **Icons:** EE shell imports from `lucide-svelte` (confirmed — both Sidebar.svelte and TopBar.svelte use `from 'lucide-svelte'`). Add `lucide-svelte` to CE (EE uses `^1.0.1`; use a compatible current version).
- **Favicon** is at `$lib/assets/favicon.svg` in BOTH repos (byte-identical); the sidebar logo `<img>` imports `$lib/assets/favicon.svg`. Nothing to copy.
- **Theme store storage key is `'cf-theme'`** and **sidebar-collapsed key is `'cf.sidebarCollapsed'`** — use these exact strings (the spec's `'cf.theme'` was approximate; EE's real key is `'cf-theme'`).
- **adapter-static constraint:** after any frontend change, `cd frontend && npm run build` must still emit `build/index.html` (the Go `//go:embed all:dist` depends on it). The SPA has `ssr=false` already.
- **Bash output in this environment is intermittently flaky.** If a command returns empty/garbled output, re-run it or redirect to a file and read it. Never conclude from a single blank result.
- **Do NOT port** `DetailShell.svelte`, `PageShell.svelte`, the shadcn oklch layer, `--radius` scale, or Rajdhani font (all out of scope per spec).

---

## File Structure

| Path | Responsibility |
|---|---|
| `frontend/src/lib/stores/theme.svelte.ts` (new) | dark/light/system theme store; writes `data-theme` on `<html>`; persists `'cf-theme'` |
| `frontend/src/lib/components/layout/AppShell.svelte` (new) | flex shell: Sidebar + (TopBar over scrollable content) |
| `frontend/src/lib/components/layout/Sidebar.svelte` (new) | 220/56px collapsible nav; CE-native 8-item nav; "CE" badge |
| `frontend/src/lib/components/layout/TopBar.svelte` (new) | 48px bar; breadcrumb, search-trigger, time-range, SSE dot, theme toggle, user/logout |
| `frontend/src/routes/+layout.svelte` (rewrite) | compose AppShell; preserve CE auth gate; init theme + sidebar-collapsed; bare-render /login + /setup-admin |
| `frontend/src/app.css` (modify) | add EE `--cf-*` tokens (dark + light), fonts, body ramp, focus ring, scrollbar |
| `frontend/package.json` + lockfile (modify) | add `lucide-svelte`, `@fontsource-variable/inter`, `@fontsource-variable/jetbrains-mono` |
| existing CE route `*.svelte` (light pass) | tokenize hardcoded dark colors that break light mode |

Tasks are ordered so the app builds after each: tokens+fonts first, then store, then leaf components, then AppShell, then the layout rewrite that wires it together, then the light-mode validation pass.

---

## Task 1: Design tokens, fonts, and global CSS in app.css

**Files:**
- Modify: `frontend/src/app.css`
- Modify: `frontend/package.json` (+ `frontend/package-lock.json`)

- [ ] **Step 1: Add the font + icon dependencies**

Run:
```bash
cd /Users/Erik/projects/cipherflag/frontend
npm install @fontsource-variable/inter @fontsource-variable/jetbrains-mono lucide-svelte
```
Expected: `package.json` gains all three under dependencies; lockfile updates. (`lucide-svelte` is needed by Tasks 3-4 but install it now in one shot.)

- [ ] **Step 2: Add font @imports to the top of app.css**

In `frontend/src/app.css`, immediately after the existing `@import "tailwindcss";` line, add:
```css
@import "@fontsource-variable/inter";
@import "@fontsource-variable/jetbrains-mono";
```

- [ ] **Step 3: Add EE's dark token block (additive) to the `:root` selector**

Append these EE tokens inside CE's existing `:root { ... }` in `app.css` (keep all of CE's current tokens; this is additive). Use these EXACT values:
```css
  /* EE operator-shell tokens (dark) — added for shell parity */
  --cf-bg-base: #0a0e17;
  --cf-bg-surface: #111827;
  --cf-bg-elevated: #1a2332;
  --cf-bg-active: #1e3a5f;
  --cf-bg-sidebar: #0d1320;
  --cf-border-accent: #2a3a4e;
  --cf-text-disabled: #475569;
  --cf-accent-secondary: #818cf8;
  --cf-grade-a: #22c55e; --cf-grade-b: #84cc16; --cf-grade-c: #eab308; --cf-grade-d: #f97316; --cf-grade-f: #ef4444;
  --cf-pqc-vulnerable: #ef4444; --cf-pqc-weakened: #f97316; --cf-pqc-safe: #22c55e; --cf-pqc-hybrid: #3b82f6; --cf-pqc-unknown: #64748b;
  --cf-severity-critical: #ef4444; --cf-severity-high: #f97316; --cf-severity-medium: #eab308; --cf-severity-low: #22c55e; --cf-severity-info: #64748b;
  --cf-status-active: #22c55e; --cf-status-stale: #eab308; --cf-status-removed: #64748b;
  --cf-badge-bg-alpha: 0.13;
  --font-sans: 'Inter Variable', sans-serif;
```
Then RECONCILE the one mismatch: change CE's existing `--cf-border` value to `#1f2937` (EE's value). Keep `--cf-text-primary`/`-secondary`/`-muted` and `--cf-accent` as-is (they already match EE). Keep all CE legacy names (`--cf-bg-primary`, `--cf-bg-secondary`, `--cf-bg-tertiary`, `--cf-bg-card`, `--cf-border-hover`, `--cf-accent-hover`, `--cf-risk-*`, `--cf-node-*`, `--cf-edge-*`) untouched.

- [ ] **Step 4: Add the light theme block**

Add a new top-level block in `app.css` (after `:root`) with EE's exact light values:
```css
[data-theme="light"] {
  --cf-bg-base: #f8fafc;
  --cf-bg-surface: #ffffff;
  --cf-bg-elevated: #f1f5f9;
  --cf-bg-active: #dbeafe;
  --cf-bg-sidebar: #ffffff;
  --cf-border: #e2e8f0;
  --cf-border-accent: #cbd5e1;
  --cf-text-primary: #0f172a;
  --cf-text-secondary: #475569;
  --cf-text-muted: #64748b;
  --cf-text-disabled: #94a3b8;
  --cf-accent: #0284c7;
  --cf-accent-secondary: #6366f1;
  --cf-grade-a: #15803d; --cf-grade-b: #65a30d; --cf-grade-c: #a16207; --cf-grade-d: #c2410c; --cf-grade-f: #b91c1c;
  --cf-pqc-vulnerable: #b91c1c; --cf-pqc-weakened: #c2410c; --cf-pqc-safe: #15803d; --cf-pqc-hybrid: #1d4ed8; --cf-pqc-unknown: #475569;
  --cf-severity-critical: #b91c1c; --cf-severity-high: #c2410c; --cf-severity-medium: #a16207; --cf-severity-low: #15803d; --cf-severity-info: #475569;
  --cf-status-active: #15803d; --cf-status-stale: #a16207; --cf-status-removed: #64748b;
  --cf-badge-bg-alpha: 0.10;
  color-scheme: light;
}
```
ALSO map CE's legacy background names so existing pages theme too: in the same `[data-theme="light"]` block add overrides for whatever legacy names CE pages actually use — at minimum `--cf-bg-primary: #f8fafc; --cf-bg-secondary: #ffffff; --cf-bg-tertiary: #f1f5f9; --cf-bg-card: #ffffff;` and `--cf-border-hover: #cbd5e1;`. (Grep `--cf-bg-` and `--cf-border-hover` usage across `frontend/src` first to confirm which legacy names need a light override; add only those that are referenced.)

- [ ] **Step 5: Add EE's global body ramp, scrollbar, focus ring, theme transition**

In `app.css`, set the `body` rule (merge with CE's existing body rule if present) to include:
```css
body {
  background-color: var(--cf-bg-base);
  color: var(--cf-text-primary);
  font-family: Inter, system-ui, -apple-system, sans-serif;
  font-size: 13px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
html, body { transition: background-color 200ms ease, color 200ms ease; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--cf-bg-base); }
::-webkit-scrollbar-thumb { background: var(--cf-border-accent); border-radius: 5px; }
::-webkit-scrollbar-thumb:hover { background: var(--cf-text-muted); }
:focus-visible { outline: 2px solid var(--cf-accent); outline-offset: 2px; }
```
If CE already defines `body`, scrollbar, or focus rules, REPLACE those with the above (do not leave CE's 6px/3px scrollbar). Keep CE's existing `--cf-bg-base` value — note CE's current `--cf-bg-primary` is already `#0a0e17`, so base matches.

- [ ] **Step 6: Build to verify CSS + deps are valid**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npm run build 2>&1 | tail -15`
Expected: build succeeds, `build/index.html` exists. If a font `@import` 404s, the package name is wrong — re-check Step 1 installed it.
Run: `test -f build/index.html && echo OK`

- [ ] **Step 7: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/app.css frontend/package.json frontend/package-lock.json
git commit -m "feat(ui): add EE design tokens (dark+light), fonts, global ramp

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Theme store

**Files:**
- Create: `frontend/src/lib/stores/theme.svelte.ts`
- Test: `frontend/src/lib/stores/theme.svelte.test.ts`

- [ ] **Step 1: Create the store (ported verbatim from EE)**

Create `frontend/src/lib/stores/theme.svelte.ts` with EXACTLY this content (this is EE's store, verified):
```ts
/**
 * Theme store — manages dark/light/system preference.
 * - Preference stored in localStorage under 'cf-theme'
 * - 'system' honors prefers-color-scheme media query
 * - Writes data-theme attribute on <html> (absent = dark, "light" = light)
 */

export type ThemeMode = 'dark' | 'light' | 'system';
export type EffectiveTheme = 'dark' | 'light';

const STORAGE_KEY = 'cf-theme';

interface ThemeStore {
  mode: ThemeMode;
  effective: EffectiveTheme;
}

export const themeStore: ThemeStore = $state({
  mode: 'system',
  effective: 'dark',
});

function computeEffective(mode: ThemeMode): EffectiveTheme {
  if (mode === 'system') {
    if (typeof window === 'undefined') return 'dark';
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  return mode;
}

function applyTheme(effective: EffectiveTheme): void {
  if (typeof document === 'undefined') return;
  if (effective === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
  } else {
    document.documentElement.removeAttribute('data-theme');
  }
}

export function setTheme(mode: ThemeMode): void {
  themeStore.mode = mode;
  themeStore.effective = computeEffective(mode);
  if (typeof window !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, mode);
  }
  applyTheme(themeStore.effective);
}

export function initTheme(): void {
  let mode: ThemeMode = 'system';
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'dark' || stored === 'light' || stored === 'system') {
      mode = stored;
    }
  }
  themeStore.mode = mode;
  themeStore.effective = computeEffective(mode);
  applyTheme(themeStore.effective);

  if (typeof window !== 'undefined') {
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    mq.addEventListener('change', () => {
      if (themeStore.mode === 'system') {
        themeStore.effective = computeEffective('system');
        applyTheme(themeStore.effective);
      }
    });
  }
}
```

- [ ] **Step 2: Write the test**

Create `frontend/src/lib/stores/theme.svelte.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { themeStore, setTheme } from './theme.svelte';

describe('theme store', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
  });

  it('setTheme(light) sets data-theme=light and persists', () => {
    setTheme('light');
    expect(themeStore.mode).toBe('light');
    expect(themeStore.effective).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(localStorage.getItem('cf-theme')).toBe('light');
  });

  it('setTheme(dark) removes data-theme attribute', () => {
    setTheme('light');
    setTheme('dark');
    expect(themeStore.mode).toBe('dark');
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
    expect(localStorage.getItem('cf-theme')).toBe('dark');
  });

  it('setTheme(system) persists system and resolves an effective theme', () => {
    setTheme('system');
    expect(themeStore.mode).toBe('system');
    expect(['dark', 'light']).toContain(themeStore.effective);
    expect(localStorage.getItem('cf-theme')).toBe('system');
  });
});
```

- [ ] **Step 3: Run the test**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx vitest run src/lib/stores/theme.svelte.test.ts 2>&1 | tail -15`
Expected: 3 passing. (CE already has vitest + jsdom configured — confirm `vitest-setup.ts` exists; it does.)

- [ ] **Step 4: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/stores/theme.svelte.ts frontend/src/lib/stores/theme.svelte.test.ts
git commit -m "feat(ui): add dark/light/system theme store

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Sidebar component (CE-native nav, "CE" badge)

**Files:**
- Create: `frontend/src/lib/components/layout/Sidebar.svelte`
- Test: `frontend/src/lib/components/layout/Sidebar.svelte.test.ts`

- [ ] **Step 1: Read the EE Sidebar as the template**

Run: `cat /Users/Erik/projects/cipherflag-EE/frontend/src/lib/components/layout/Sidebar.svelte` and read it fully. It is the visual source of truth (6313 bytes). You will reproduce its structure and `<style>` VERBATIM, changing only: the nav data, the badge text, and the favicon import (already `$lib/assets/favicon.svg`, no change needed).

- [ ] **Step 2: Create CE's Sidebar**

Create `frontend/src/lib/components/layout/Sidebar.svelte` reproducing EE's component, with these REQUIRED adaptations:
- **Props** (verbatim from EE): `currentPath: string`, `collapsed = false`, `onToggleCollapse?: () => void`.
- **Imports:** from `lucide-svelte` import exactly the icons used by the nav below plus `PanelLeftClose, PanelLeftOpen, Settings`; and `import scopeIcon from '$lib/assets/favicon.svg';`.
- **Nav data** — replace EE's `groups` array with this CE-native nav (every route exists in CE):
```ts
const groups: NavGroup[] = [
  { label: 'Overview', items: [
    { label: 'Dashboard', href: '/', icon: LayoutGrid },
  ]},
  { label: 'Inventory', items: [
    { label: 'Certificates', href: '/certificates', icon: Shield },
  ]},
  { label: 'Explore', items: [
    { label: 'PKI Explorer', href: '/pki', icon: Orbit },
    { label: 'Analytics', href: '/analytics', icon: BarChart3 },
    { label: 'Reports', href: '/reports', icon: FileText },
    { label: 'Statistics', href: '/stats', icon: Layers },
  ]},
  { label: 'Ingest', items: [
    { label: 'Upload', href: '/upload', icon: Upload },
  ]},
];
const settingsItem: NavItem = { label: 'Settings', href: '/settings', icon: Settings };
```
  (lucide imports for the nav: `LayoutGrid, Shield, Orbit, BarChart3, FileText, Layers, Upload, Settings, PanelLeftClose, PanelLeftOpen`. Keep EE's `NavItem`/`NavGroup` interfaces.)
- **Active match** (verbatim from EE): `function isActive(href: string) { return href === '/' ? currentPath === '/' : currentPath.startsWith(href); }` — match EE's exact logic; if EE uses `startsWith(href + '/')` plus exact, copy that form exactly.
- **Badge:** wherever EE renders `<span class="cf-logo-badge">EE</span>`, change the text to `CE`. Keep the class and all styling identical.
- **Collapse:** keep EE's `data-collapsed={collapsed}` attribute binding, the `{#if !collapsed}` label removal, and the `PanelLeftClose`/`PanelLeftOpen` swap exactly.
- **`<style>`:** copy EE's entire `<style>` block VERBATIM (the 220/56px widths, `transition: width 300ms cubic-bezier(0.34, 1.56, 0.64, 1)`, all the `--cf-*` references, nav-item resting/hover/active, footer). Do not alter any value.

- [ ] **Step 3: Build the package compiles**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -15`
Expected: no errors in `Sidebar.svelte` (warnings about other pre-existing files are fine). If an icon name doesn't exist in `lucide-svelte`, pick the nearest valid name and note it.

- [ ] **Step 4: Write the test**

Create `frontend/src/lib/components/layout/Sidebar.svelte.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import Sidebar from './Sidebar.svelte';

describe('Sidebar', () => {
  it('renders the CE-native nav items', () => {
    const { getByText } = render(Sidebar, { props: { currentPath: '/' } });
    for (const label of ['Dashboard', 'Certificates', 'PKI Explorer', 'Analytics', 'Reports', 'Statistics', 'Upload', 'Settings']) {
      expect(getByText(label)).toBeTruthy();
    }
  });

  it('shows the CE badge, not EE', () => {
    const { getByText, queryByText } = render(Sidebar, { props: { currentPath: '/' } });
    expect(getByText('CE')).toBeTruthy();
    expect(queryByText('EE')).toBeNull();
  });

  it('marks the active route', () => {
    const { container } = render(Sidebar, { props: { currentPath: '/certificates' } });
    const active = container.querySelector('.cf-nav-item.active, [data-active="true"], a[aria-current="page"]');
    expect(active?.textContent).toContain('Certificates');
  });

  it('reflects collapsed state via data attribute', () => {
    const { container } = render(Sidebar, { props: { currentPath: '/', collapsed: true } });
    expect(container.querySelector('[data-collapsed="true"]')).toBeTruthy();
  });
});
```
(If EE marks the active item with a different selector than `.cf-nav-item.active`, update the third test's querySelector to match the actual class/attribute EE uses — read it from the Sidebar you wrote.)

- [ ] **Step 5: Run the test**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx vitest run src/lib/components/layout/Sidebar.svelte.test.ts 2>&1 | tail -20`
Expected: 4 passing.

- [ ] **Step 6: gofmt-equivalent — prettier/format check is not enforced in CE; skip. Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/components/layout/Sidebar.svelte frontend/src/lib/components/layout/Sidebar.svelte.test.ts
git commit -m "feat(ui): port operator Sidebar with CE-native nav + CE badge

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: TopBar component

**Files:**
- Create: `frontend/src/lib/components/layout/TopBar.svelte`

- [ ] **Step 1: Read the EE TopBar as the template**

Run: `cat /Users/Erik/projects/cipherflag-EE/frontend/src/lib/components/layout/TopBar.svelte` and read it fully (4073 bytes). Reproduce VERBATIM except: remove any EE-specific user-menu links that point at EE-only routes, and keep the import of the theme store at `$lib/stores/theme.svelte` (same path in CE now).

- [ ] **Step 2: Create CE's TopBar**

Create `frontend/src/lib/components/layout/TopBar.svelte` reproducing EE's component:
- **Imports:** `import { Sun, Moon, Monitor, Search, User, LogOut } from 'lucide-svelte';` and `import { themeStore, setTheme, type ThemeMode } from '$lib/stores/theme.svelte';`.
- **Props** (verbatim): `breadcrumb: string[]`, `sseConnected: boolean`, `onLogout?: () => void`.
- **Theme cycle** (verbatim from EE): `function cycleTheme() { const next: Record<ThemeMode, ThemeMode> = { dark: 'light', light: 'system', system: 'dark' }; setTheme(next[themeStore.mode]); }` and the `{#if themeStore.mode === 'dark'}<Moon .../>...` icon switch.
- **Template:** breadcrumb (with `›` separators, `.current` on last), spacer, search-trigger (visual only — `<button>` with Search icon + "Search assets, hosts, findings…" + `<kbd>⌘K</kbd>`), time-range stub (`<button>Last 7d ▾</button>`), SSE dot (`class:connected={sseConnected}`), theme-toggle button, user/logout button calling `onLogout`.
- **`<style>`:** copy EE's entire `<style>` VERBATIM (48px height, `--cf-bg-surface`, search-trigger 280px, SSE dot 8px + box-shadow `color-mix(in srgb, var(--cf-status-active) 25%, transparent)`, button styles, breadcrumb). Do not alter values.

- [ ] **Step 3: svelte-check**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -15`
Expected: no errors in `TopBar.svelte`.

- [ ] **Step 4: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/components/layout/TopBar.svelte
git commit -m "feat(ui): port operator TopBar (breadcrumb, theme toggle, search, SSE dot)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: AppShell component

**Files:**
- Create: `frontend/src/lib/components/layout/AppShell.svelte`

- [ ] **Step 1: Create AppShell (verbatim from EE — already captured)**

Create `frontend/src/lib/components/layout/AppShell.svelte` with EXACTLY this content (this is EE's AppShell, verified):
```svelte
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Sidebar from './Sidebar.svelte';
  import TopBar from './TopBar.svelte';

  interface Props {
    currentPath: string;
    breadcrumb: string[];
    sseConnected: boolean;
    sidebarCollapsed?: boolean;
    onToggleSidebar?: () => void;
    onLogout?: () => void;
    children?: Snippet;
  }
  let {
    currentPath,
    breadcrumb,
    sseConnected,
    sidebarCollapsed = false,
    onToggleSidebar,
    onLogout,
    children,
  }: Props = $props();
</script>

<div class="cf-app-shell">
  <Sidebar {currentPath} collapsed={sidebarCollapsed} onToggleCollapse={onToggleSidebar} />
  <div class="cf-app-main">
    <TopBar {breadcrumb} {sseConnected} {onLogout} />
    <div class="cf-app-content">
      {#if children}
        {@render children()}
      {/if}
    </div>
  </div>
</div>

<style>
  .cf-app-shell {
    display: flex;
    height: 100vh;
    width: 100%;
    background: var(--cf-bg-base);
  }
  .cf-app-main {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }
  .cf-app-content {
    flex: 1;
    overflow: auto;
  }
</style>
```

- [ ] **Step 2: svelte-check + build**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -10 && npm run build 2>&1 | tail -5 && test -f build/index.html && echo BUILD-OK`
Expected: no errors; BUILD-OK. (AppShell isn't wired into a route yet, so the app still uses the old top-bar — that's fine; Task 6 wires it.)

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/lib/components/layout/AppShell.svelte
git commit -m "feat(ui): add AppShell layout wrapper (sidebar + topbar + content)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Rewrite +layout.svelte to use AppShell

**Files:**
- Modify (rewrite): `frontend/src/routes/+layout.svelte`

- [ ] **Step 1: Read the current CE layout + EE's layout for reference**

Run both and read fully:
`cat /Users/Erik/projects/cipherflag/frontend/src/routes/+layout.svelte` (the current top-bar layout + CE's exact auth-gate logic to PRESERVE)
`cat /Users/Erik/projects/cipherflag-EE/frontend/src/routes/+layout.svelte` (the shell composition + breadcrumb derivation to ADOPT)

- [ ] **Step 2: Rewrite the layout**

Rewrite `frontend/src/routes/+layout.svelte` to:
- Keep CE's EXISTING auth-gate logic verbatim (imports from `$lib/auth`: `getCurrentUser, checkAuthStatus, logout as doLogout, type AuthUser`; the `authChecked` flag; the anonymous→`/setup-admin`, null→login/setup redirects). Do NOT switch to EE's `$lib/api/auth`.
- Add imports: `import AppShell from '$lib/components/layout/AppShell.svelte';`, `import { initTheme } from '$lib/stores/theme.svelte';`, and `import { page } from '$app/stores';` (or `$app/state` — match what CE already uses elsewhere).
- Add state: `let sidebarCollapsed = $state(false);`
- Add a `BREADCRUMB_LABELS` map covering CE routes and a derived `breadcrumb` from `page.url.pathname`, e.g.:
```ts
const BREADCRUMB_LABELS: Record<string, string> = {
  '': 'Dashboard', certificates: 'Certificates', pki: 'PKI Explorer',
  analytics: 'Analytics', reports: 'Reports', stats: 'Statistics',
  upload: 'Upload', settings: 'Settings',
};
const breadcrumb = $derived(
  (() => {
    const segs = page.url.pathname.split('/').filter(Boolean);
    if (segs.length === 0) return ['Dashboard'];
    return segs.map((s) => BREADCRUMB_LABELS[s] ?? s);
  })()
);
const currentPath = $derived(page.url.pathname);
```
- In `onMount`: call `initTheme()` and restore `sidebarCollapsed` from `localStorage.getItem('cf.sidebarCollapsed') === 'true'` (BEFORE/alongside the existing auth check).
- Add `function toggleSidebar() { sidebarCollapsed = !sidebarCollapsed; if (typeof localStorage !== 'undefined') localStorage.setItem('cf.sidebarCollapsed', String(sidebarCollapsed)); }`.
- Template: if pathname is `/login` or `/setup-admin`, render `{@render children()}` bare (no shell). Otherwise, if `authChecked`, render:
```svelte
<AppShell {currentPath} {breadcrumb} sseConnected={false} {sidebarCollapsed} onToggleSidebar={toggleSidebar} onLogout={doLogout}>
  {@render children()}
</AppShell>
```
  (and a loading div while `!authChecked`, matching CE's current behavior). Note `sseConnected={false}` — CE has no event stream.
- REMOVE the old top-bar `<nav>` markup and its `<style>` (the shell owns layout now). Any CE-specific top-bar styles that are now unused should be deleted.

- [ ] **Step 3: svelte-check + build**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check --tsconfig ./tsconfig.json 2>&1 | tail -15 && npm run build 2>&1 | tail -5 && test -f build/index.html && echo BUILD-OK`
Expected: no new errors; BUILD-OK.

- [ ] **Step 4: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src/routes/+layout.svelte
git commit -m "feat(ui): replace top-bar layout with operator AppShell

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Rebuild container + dual-theme visual verification

**Files:** none (verification + screenshots)

- [ ] **Step 1: Rebuild the image and recreate the stack**

Run:
```bash
cd /Users/Erik/projects/cipherflag
docker compose build cipherflag 2>&1 | tail -5
docker compose up -d 2>&1 | tail -5
docker compose ps --format '{{.Service}}={{.State}}'
```
Expected: both services up; cipherflag built from current HEAD.

- [ ] **Step 2: Confirm the SPA still serves the embedded build**

Run: `curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' http://localhost:8443/`
Expected: `200 text/html`. (Plain http — 8443 is not TLS here.)

- [ ] **Step 3: Screenshot the dashboard in DARK mode (the look-at-it gate)**

Use system Chrome headless (no Playwright dep needed):
```bash
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CHROME" --headless --disable-gpu --no-sandbox --hide-scrollbars --virtual-time-budget=6000 --window-size=1400,900 --screenshot=/tmp/ce_shell_dark.png "http://localhost:8443/"
```
Then READ `/tmp/ce_shell_dark.png` (it renders visually). CONFIRM by looking: left sidebar present with the 8 nav items + scope-reticle logo + "CE" badge; top bar with breadcrumb + theme toggle; dark navy palette (#0a0e17 / #0d1320). If it shows the OLD top-bar or a blank page, the build didn't pick up the change — rebuild.
NOTE: the first screen may be the login/setup-admin page (no shell, by design) if no admin/session exists. If so, that's expected — the shell only appears post-auth. To see the shell, either create an admin and authenticate, or screenshot a route that renders the shell; document which state the screenshot shows.

- [ ] **Step 4: Screenshot in LIGHT mode**

Toggle theme by pre-seeding localStorage, then screenshot. Simplest: use a small Chrome run that sets `localStorage['cf-theme']='light'` then reloads — or, since that needs scripting, instead verify light mode via the theme store unit test (already covered in Task 2) PLUS a manual note. Preferred automated approach if `chromium`/Playwright is available: navigate, `localStorage.setItem('cf-theme','light')`, reload, screenshot to `/tmp/ce_shell_light.png`, READ it, confirm light palette (#f8fafc / #ffffff sidebar, dark text). If no scriptable browser is available, document that light mode is verified by the theme-store test + token block, and defer the visual light screenshot to the light-pass task (Task 8).

- [ ] **Step 5: Record results (no commit — verification only)**

Note in your report: dark screenshot result (sidebar/badge/nav present?), light screenshot result (or why deferred), and any visual defect vs EE.

---

## Task 8: Light-mode validation pass over existing CE pages

**Files:**
- Modify: existing CE route/component `*.svelte` files ONLY where a hardcoded dark color breaks light mode

- [ ] **Step 1: Find hardcoded colors that won't theme**

Run:
```bash
cd /Users/Erik/projects/cipherflag/frontend
grep -rnE '#[0-9a-fA-F]{3,6}|rgba?\(' src/routes src/lib/components --include='*.svelte' | grep -vE 'var\(--cf-' | grep -viE 'favicon|\.svg|stroke=|fill="#fff"|currentColor' | head -60
```
This lists hardcoded color literals in markup/styles that bypass the `--cf-*` tokens — these are the candidates that will look wrong in light mode. (Many may be inside SVG graph components which are intentionally fixed — judge each.)

- [ ] **Step 2: Visually audit each existing route in light mode**

With the stack running and `localStorage['cf-theme']='light'`, screenshot each CE route via headless Chrome and READ each image:
`/` , `/certificates`, `/certificates/<any-fingerprint or empty state>`, `/pki`, `/analytics`, `/reports`, `/stats`, `/settings`, `/upload`, `/login`, `/setup-admin`.
For each, note any element that is unreadable/wrong in light mode (e.g. dark text on dark hardcoded bg, white-on-white).

- [ ] **Step 3: Tokenize the breakages**

For each confirmed light-mode breakage, replace the hardcoded color with the appropriate `--cf-*` token (e.g. a hardcoded `#0a0e17` panel bg → `var(--cf-bg-base)`; `#1e293b` border → `var(--cf-border)`; hardcoded text greys → `var(--cf-text-secondary)`/`-muted`). Make the SMALLEST change that fixes the contrast; do not restyle. Re-screenshot to confirm.
Constraint: do NOT touch the constellation/graph SVG node/edge colors (`--cf-node-*`/`--cf-edge-*` are intentionally fixed data-viz colors) unless they're literally unreadable.

- [ ] **Step 4: Rebuild + re-verify both themes**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npm run build 2>&1 | tail -3 && cd .. && docker compose build cipherflag 2>&1 | tail -3 && docker compose up -d 2>&1 | tail -2`
Then re-screenshot the dashboard in both dark and light; READ both; confirm dark is unchanged and light is now readable across pages.

- [ ] **Step 5: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add frontend/src
git commit -m "fix(ui): tokenize hardcoded colors for light-theme readability

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```
(Stage only the `.svelte` files you actually changed; if Step 1-3 found NO breakages, skip the commit and note that existing pages were already token-clean.)

---

## Notes for the implementer

- **Verbatim where possible:** AppShell + theme store are given in full above (copy exactly). Sidebar + TopBar `<style>` blocks must be copied VERBATIM from the EE files — read them with `cat` and reproduce; the visual parity depends on not paraphrasing any px/color/timing value.
- **The only intentional content changes** vs EE: nav data (CE routes), badge "EE"→"CE", auth import path (`$lib/api/auth`→`$lib/auth`), `sseConnected={false}`, no events store.
- **adapter-static:** every task that touches frontend must end green on `npm run build` with `build/index.html` present, or the Go embed breaks.
- **Pre-existing state:** branch off `main` (HEAD `0bd8136`, the merged connectors). Do NOT push. The CE-only token names and existing pages must keep working in dark mode (additive tokens guarantee this).
- **Flaky bash:** redirect to a file and Read it if output is empty/garbled; never conclude from one blank result.
