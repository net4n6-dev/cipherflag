# CipherFlag CE — Operator Shell Port Design (Strategy C)

**Date:** 2026-05-31
**Status:** Approved (pending written-spec review)
**Author:** Erik + Claude (Opus 4.8)
**Related:** the CE v2 strategy decision (Strategy C: keep clean-room CE + port a de-moated
EE operator frontend shell). Look-and-feel research captured EE's exact design tokens,
typography, and shell dimensions; this spec turns that into a port plan.

---

## Goal

Replace CE's v1 horizontal top-bar layout with the EE **operator shell** — a left **Sidebar**
+ top **TopBar** wrapped in an **AppShell** — reproducing EE's look-and-feel exactly so users
moving between editions (upgrade EE ↔ downgrade CE) see one coherent product. This fixes the
"no sidebar" gap that has surfaced repeatedly during smoke testing.

## Locked decisions (from brainstorming)

1. **Additive tokens.** Add EE's complete `--cf-*` token vocabulary to CE's `app.css`
   *alongside* CE's existing token names (no mass rename of existing CE pages). Reconcile only
   the one shared-name mismatch (`--cf-border`).
2. **Full light-theme parity.** Port EE's `[data-theme="light"]` token values, a theme store,
   and a live 3-state theme toggle — including a light-mode validation pass over CE's existing
   pages.
3. **CE-native nav in EE grammar.** The sidebar nav reflects CE's *real* routes (no 404s, no
   moat links) but uses EE's exact visual treatment (groups, eyebrow labels, icons, active
   state).
4. **Badge = "CE".** EE renders an indigo "EE" pill; CE renders the identical pill reading
   "CE" — same font/size/color/border/position, only the text changes.

## Confirmed environment facts (verified on disk)

- CE frontend is **Svelte 5** (`^5.49.2`) — runes available, matching EE's component idiom.
- CE auth lives at **`$lib/auth`** (flat `auth.ts`), exporting `getCurrentUser`,
  `checkAuthStatus`, `logout`. (EE uses `$lib/api/auth` — import paths must be adapted.)
- CE has **`$lib/assets/`** with the full icon set already present: `favicon.svg` (the
  scope-reticle mark, byte-identical to EE), `favicon.ico`, `favicon-16x16.png`,
  `favicon-32x32.png`, `apple-touch-icon.png`, `icon-192.png`, `icon-512.png`. **No
  `frontend/static/` dir** — CE serves icons from `$lib/assets`. So no raster icons need
  copying; the shell's logo `<img>` points at `$lib/assets/favicon.svg`.
- CE has **no** `lucide-svelte`, **no** `@fontsource*`, **no** `$lib/stores/`,
  **no** `$lib/components/layout/` — all greenfield for this port.
- EE shell imports icons from one of `lucide-svelte` (`^1.0.1`) / `@lucide/svelte` (`^1.8.0`)
  — EE declares both. **At implementation, confirm which package the EE Sidebar/TopBar
  actually import** (read the top-of-file import line) and add exactly that one to CE
  `package.json`; do not add both.

## Out of scope

- `DetailShell.svelte` / `PageShell.svelte` (EE page-content wrappers) — only AppShell +
  Sidebar + TopBar are needed for the shell; defer the page wrappers unless a ported route
  needs them.
- The shadcn-svelte oklch variable layer + `--radius` scale — the shell is pure `--cf-*` CSS;
  skip shadcn unless a ported component renders a shadcn primitive (it does not).
- New CE routes (assets/hosts/applications/pqc/etc.) — nav links only CE's existing routes.
- Global search *logic* — the TopBar search-trigger is visual only for now (⌘K affordance,
  no palette wired), matching how it can ship as a shell element.

---

## Architecture

New dir `frontend/src/lib/components/layout/`:

| File | Responsibility |
|---|---|
| `AppShell.svelte` | `flex` shell, `height:100vh`, bg `--cf-bg-base`; renders `<Sidebar>` + a `flex:1; min-width:0` column holding `<TopBar>` over a `flex:1; overflow:auto` content slot. No content padding (pages own it). |
| `Sidebar.svelte` | 220px expanded / 56px collapsed (`data-collapsed="true"`); bg `--cf-bg-sidebar`; logo + CE badge + the CE-native nav; collapse via `{#if !collapsed}` DOM removal + `PanelLeftClose↔PanelLeftOpen` icon swap; Settings + collapse button in `margin-top:auto` footer. |
| `TopBar.svelte` | 48px; breadcrumb · spacer · search-trigger (280px, ⌘K, visual) · time-range · SSE dot · **theme toggle (live 3-state)** · user/logout. |

New store `frontend/src/lib/stores/theme.svelte.ts`: exports `themeStore`, `setTheme(mode)`,
`initTheme()`. Modes `dark | light | system`; persists to `localStorage 'cf.theme'`; writes
`data-theme` on `<html>` (omit attribute or set per resolved value for "system" via
`prefers-color-scheme`). Ported/adapted from EE's `$lib/stores/theme.svelte`.

Rewrite `frontend/src/routes/+layout.svelte`:
- Compose `<AppShell currentPath breadcrumb sseConnected sidebarCollapsed onToggleSidebar onLogout>`.
- Preserve CE's existing auth-gate logic against `$lib/auth` (do not swap to EE's `$lib/api/auth`).
- `onMount`: `initTheme()` + restore `sidebarCollapsed` from `localStorage 'cf.sidebarCollapsed'`.
- Bare-render `/login` and `/setup-admin` (no shell), matching EE.
- `breadcrumb` derived from `page.url.pathname` via a small `BREADCRUMB_LABELS` map covering CE
  routes.
- `sseConnected`: CE has no SSE backend → pass a constant `false` (the dot renders
  "disconnected" grey) OR hide the dot. **Decision: render the dot as disconnected** (visual
  parity, honest state) rather than stub a fake-connected indicator. Revisit if CE adds an
  event stream.

### Sidebar nav (CE-native, EE grammar)

| Group | Item | Route | lucide icon |
|---|---|---|---|
| Overview | Dashboard | `/` | `LayoutGrid` |
| Inventory | Certificates | `/certificates` | `Shield` |
| Explore | PKI Explorer | `/pki` | `Orbit` |
| Explore | Analytics | `/analytics` | `BarChart3` |
| Explore | Reports | `/reports` | `FileText` |
| Explore | Statistics | `/stats` | `Layers` |
| Ingest | Upload | `/upload` | `Upload` |
| _footer_ | Settings | `/settings` | `Settings` |

Active match: exact `===` for `/`, else `pathname.startsWith(href + '/')` (EE's rule). All
icons are from the lucide set EE already uses; final icon names may be tweaked to taste at
implementation, but each must exist in the chosen lucide package.

---

## Design tokens & global CSS (`frontend/src/app.css`)

Add EE's complete token block **additively** (CE's old names stay defined). Dark `:root`
values (verbatim from EE `app.css`):

```
--cf-bg-base: #0a0e17;  --cf-bg-surface: #111827;  --cf-bg-sidebar: #0d1320;
--cf-bg-elevated: #1a2332;  --cf-bg-active: #1e3a5f;
--cf-border: #1f2937;  --cf-border-accent: #2a3a4e;
--cf-text-primary: #f1f5f9;  --cf-text-secondary: #94a3b8;  --cf-text-muted: #64748b;  --cf-text-disabled: #475569;
--cf-accent: #38bdf8;  --cf-accent-secondary: #818cf8;
--cf-grade-a:#22c55e; --cf-grade-b:#84cc16; --cf-grade-c:#eab308; --cf-grade-d:#f97316; --cf-grade-f:#ef4444;
--cf-severity-critical:#ef4444; --cf-severity-high:#f97316; --cf-severity-medium:#eab308; --cf-severity-low:#22c55e; --cf-severity-info:#64748b;
--cf-status-active:#22c55e; --cf-status-stale:#eab308; --cf-status-removed:#64748b;
--cf-pqc-vulnerable:#ef4444; --cf-pqc-weakened:#f97316; --cf-pqc-safe:#22c55e; --cf-pqc-hybrid:#3b82f6; --cf-pqc-unknown:#64748b;
--cf-badge-bg-alpha: 0.13;
```

`[data-theme="light"]` block — port EE's exact light values (base #f8fafc, surface #ffffff,
sidebar #ffffff, elevated #f1f5f9, active #dbeafe, border #e2e8f0, border-accent #cbd5e1,
text-primary #0f172a / secondary #475569 / muted #64748b / disabled #94a3b8, accent #0284c7,
accent-secondary #6366f1, grades/severity/status/pqc light variants, badge-bg-alpha 0.10).

**Reconcile the one mismatch:** CE currently `--cf-border: #1e293b` → change to EE's `#1f2937`.
Keep CE's legacy names (`--cf-bg-primary/secondary/tertiary/card`, `--cf-border-hover`,
`--cf-accent-hover`, `--cf-risk-*`, `--cf-node-*`, `--cf-edge-*`) so existing CE pages are
unaffected.

Fonts — add deps + `@import` (mirroring EE `app.css`):
`@fontsource-variable/inter` `^5.2.8`, `@fontsource-variable/jetbrains-mono` `^5.2.8`.
(Rajdhani only if the login splash is later ported — out of scope here.) Add
`--font-sans: 'Inter Variable', sans-serif;`.

Global ramp (add to CE, currently absent): body `font-family: Inter, system-ui, -apple-system,
sans-serif; font-size: 13px; line-height: 1.5; -webkit-font-smoothing: antialiased;`. Hash/code
text → `'JetBrains Mono', ui-monospace, monospace`. Add `:focus-visible { outline: 2px solid
var(--cf-accent); outline-offset: 2px; }`; `html, body { transition: background-color 200ms ease,
color 200ms ease; }`. Scrollbar → 10px/5px, thumb `--cf-border-accent`, hover `--cf-text-muted`,
track `--cf-bg-base`. Eliminate CE's two hardcoded rgba tints (active-nav cyan, admin amber) →
route through tokens.

---

## Visual fidelity (exact, from research — reproduce verbatim)

- **Sidebar:** width 220/56px via `data-collapsed`; `transition: width 300ms
  cubic-bezier(0.34, 1.56, 0.64, 1)` (signature spring — match exactly); bg `--cf-bg-sidebar`;
  `border-right: 1px solid var(--cf-border)`; `padding: 12px 0`.
- **Logo header:** `gap 8px; padding 4px 16px 16px`; mark = `favicon.svg` `<img>` 24×24, radius 6.
- **Wordmark "CipherFlag":** `--cf-text-primary`; 14px; weight 600; `letter-spacing -0.02em`; Inter.
- **CE badge:** 10px; color + border `--cf-accent-secondary` (#818cf8 dark / #6366f1 light);
  radius 3; `padding 0 4px`; **no fill, no uppercase**; text **"CE"**.
- **Nav group label (eyebrow):** 10px; weight 600; uppercase; `letter-spacing 0.08em`;
  `--cf-text-disabled`; `padding 10px 8px 4px`.
- **Nav container:** `padding 0 8px; gap 1px`.
- **Nav item resting:** `gap 8px`; `--cf-text-secondary`; 12px; `padding 7px 8px`; radius 6;
  `transition: background 100ms ease, color 100ms ease`; lucide icon size 16.
- **Nav item hover:** bg `--cf-bg-elevated`; text `--cf-text-primary`.
- **Nav item active:** **solid `--cf-bg-active` (#1e3a5f) fill + `--cf-text-primary` + weight
  500 — NO left-accent bar, no `::before`.**
- **Footer:** `margin-top:auto; padding 8px; border-top: 1px solid var(--cf-border); gap 1px`;
  Settings nav-item + collapse button (reuses nav-item style, `--cf-text-muted`, hover
  `--cf-text-primary`).
- **TopBar:** 48px; bg `--cf-bg-surface`; `border-bottom: 1px solid var(--cf-border)`;
  `padding 0 20px; gap 12px`. L→R: breadcrumb, spacer (`flex:1`), search-trigger, time-range,
  SSE dot, theme toggle, user-menu.
- **Breadcrumb:** `gap 6px`; 11px; `--cf-text-muted`; separator literal `›` in
  `--cf-text-disabled`; current crumb `--cf-text-primary`.
- **Search trigger:** width 280px; bg `--cf-bg-elevated`; `border 1px solid var(--cf-border-accent)`;
  radius 6; `padding 4px 12px`; 12px; hover border `--cf-accent`; lucide `Search` 14 +
  placeholder "Search assets, hosts, findings…" + `.cf-kbd "⌘K"` (10px, border
  `--cf-border-accent`, radius 3, `padding 1px 4px`, `margin-left auto`).
- **TopBar buttons (time-range / theme / user):** `--cf-text-secondary`; `border 1px solid
  var(--cf-border-accent)`; radius 6; `padding 4px 10px`; 12px; transparent bg; hover color +
  border `--cf-accent`; lucide icons 14.
- **Theme toggle:** 3-state cycle dark→light→system; `$derived` icon `Moon`/`Sun`/`Monitor`;
  `title "Theme: {mode}"`.
- **SSE dot:** bare 8×8 circle, radius 50%, no label/animation. Connected: `--cf-status-active`
  + `box-shadow 0 0 0 2px color-mix(in srgb, var(--cf-status-active) 25%, transparent)`.
  Disconnected: `--cf-text-disabled`. (CE ships disconnected — see Architecture note.)

---

## Light-theme wiring (decision B) + validation scope

- Theme store cycles dark→light→system, writes `data-theme` on `<html>`, persists to
  `localStorage 'cf.theme'`, resolves "system" via `prefers-color-scheme: light`.
- The shell itself is fully tokenized, so it themes for free once the `[data-theme="light"]`
  block exists.
- **The extra surface B implies:** CE's *existing* pages (dashboard `/`, certificates, PKI,
  analytics, reports, stats, settings, upload, login, setup-admin) were authored dark-only and
  may contain hardcoded dark colors that look wrong in light mode. The plan MUST include a
  light-mode pass: load each route in light, screenshot, and tokenize any hardcoded dark color
  found. This is acceptance criteria, not optional polish.

---

## Testing & verification

- **Unit (vitest + @testing-library/svelte):**
  - Sidebar renders the 8 nav items with correct labels/hrefs; renders **"CE"** badge (assert
    `getByText('CE')`, and assert **no** `'EE'`).
  - Collapse toggles `data-collapsed` and persists to `localStorage 'cf.sidebarCollapsed'`.
  - Active-state: `/` matches only at root; `/certificates/x` marks the Certificates item
    active via `startsWith`.
  - Theme store: cycles dark→light→system, sets `data-theme` on `document.documentElement`,
    persists to `localStorage 'cf.theme'`.
- **Build:** `npm run build` clean (adapter-static SPA — must still emit `index.html` for the
  Go embed); `gofmt`/Go untouched.
- **Visual gate (the look-at-it requirement):** rebuild the container, then headless-Chrome
  screenshot the post-login dashboard in **both dark and light** at `http://localhost:8443`.
  Confirm: sidebar renders with all 8 items + CE badge; collapse works; theme toggle flips
  dark↔light; every nav link resolves (no 404). Inspect the screenshots, do not infer from
  HTTP 200s.
- **No-404 guarantee:** nav links only CE's real routes (verified list), so navigation cannot
  404.

## Files touched

| Path | Change |
|---|---|
| `frontend/src/lib/components/layout/AppShell.svelte` | new |
| `frontend/src/lib/components/layout/Sidebar.svelte` | new (+ unit test) |
| `frontend/src/lib/components/layout/TopBar.svelte` | new (+ unit test) |
| `frontend/src/lib/stores/theme.svelte.ts` | new (+ unit test) |
| `frontend/src/routes/+layout.svelte` | rewrite (top-bar → AppShell) |
| `frontend/src/app.css` | add EE tokens (dark + light) + global ramp + fonts |
| `frontend/package.json` / lockfile | add `@fontsource-variable/inter`, `@fontsource-variable/jetbrains-mono`, the chosen lucide pkg |
| existing CE route `*.svelte` | light-mode tokenization pass (only where hardcoded dark colors break light) |

## Open questions (non-blocking; resolvable at implementation)

- Which lucide package the EE shell imports (`lucide-svelte` vs `@lucide/svelte`) — confirm
  from EE source, add exactly that one.
- Final nav icon choices (the table is a sensible default; swap any icon as long as it exists
  in the chosen lucide pkg).
- Time-range control (`Last 7d ▾`): render as a static visual element for parity, or omit since
  CE has no time-range backend? Default: render static (visual parity), non-functional, like
  the search trigger. Confirm at review if you'd rather omit.
