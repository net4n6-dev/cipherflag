# PKI Explorer: Force-Directed Graph Visualization

Replaces the current `/pki` tree view with an interactive force-directed graph built on D3-force with SVG rendering. Designed for enterprise-scale PKI estates (thousands of certificates) with server-side aggregation to keep the frontend fast.

## Use Cases

1. **Security posture overview** (default) — see all CAs and chain health at a glance. Risk nodes pulse, healthy ones recede.
2. **Discovery & exploration** — understand the CA landscape after ingesting certificates. See which CAs dominate, find unexpected trust paths, drill into details.
3. **Incident response** — select a CA and instantly see its blast radius: every certificate it signed, recursively.

## Architecture

### Server-Side Aggregation

The frontend never loads all certificates at once. The API returns a collapsed graph (CAs only) on initial load, and serves children on demand.

### New/Modified API Endpoints

**`GET /api/graph/landscape`** (modified)

Returns only Root CA and Intermediate CA nodes with aggregate stats. No leaf certificates.

Response shape:
```json
{
  "nodes": [
    {
      "fingerprint": "abc123...",
      "common_name": "DigiCert Global Root G2",
      "organization": "DigiCert Inc",
      "type": "root",
      "cert_count": 1247,
      "worst_grade": "B",
      "avg_score": 87.3,
      "expired_count": 4,
      "expiring_30d_count": 12,
      "key_algorithm": "RSA",
      "key_size": 2048
    }
  ],
  "edges": [
    {
      "source": "abc123...",
      "target": "def456...",
      "child_grade": "B"
    }
  ]
}
```

**`GET /api/graph/ca/{fingerprint}/children`**

Returns the direct children of a CA node. If children are intermediates, they are returned as aggregate nodes (same shape as landscape nodes). If children are leaf certs, they are returned with individual cert details.

Query parameters:
- `limit` (int, default 100) — max children to return
- `offset` (int, default 0) — pagination offset

Response shape:
```json
{
  "parent_fingerprint": "abc123...",
  "nodes": [ ... ],
  "edges": [ ... ],
  "total": 342,
  "has_more": true
}
```

**`GET /api/graph/ca/{fingerprint}/blast-radius`**

Returns the full downstream subgraph of a CA: all descendants (intermediates and leaves) with edges. Capped at 500 nodes — if the subgraph exceeds this, the response includes `truncated: true` and the summary still reflects the full count. The frontend shows a warning: "Showing 500 of 2,341 certificates."

Response shape:
```json
{
  "root_fingerprint": "abc123...",
  "nodes": [ ... ],
  "edges": [ ... ],
  "summary": {
    "total_certs": 342,
    "expired": 12,
    "expiring_30d": 8,
    "grade_f": 3,
    "intermediates": 4
  },
  "truncated": false
}
```

### Backend Implementation

All three endpoints are served from the existing `internal/api/handler/graph.go` handler. The store layer needs new queries:

- `GetAggregatedLandscape()` — returns CAs with aggregate stats (cert count, worst grade, avg score, expired count, expiring count). Uses GROUP BY on issuer relationships.
- `GetCAChildren(fingerprint, limit, offset)` — returns direct children of a CA with pagination.
- `GetBlastRadius(fingerprint)` — recursive CTE query to get all descendants of a CA.

The existing `internal/analysis/chain.go` logic for classifying nodes (root/intermediate/leaf) and resolving issuer relationships is reused.

## Frontend Design

### Page Structure

The `/pki` route is replaced entirely. The new page is a full-viewport SVG graph with translucent overlay controls.

**Layout layers (bottom to top):**
1. SVG graph canvas (full viewport, dark background `#0a0e17`)
2. Top toolbar overlay (translucent, contains search + filters + zoom)
3. Hover tooltip (follows cursor)
4. Bottom-left legend overlay
5. Bottom-right live stats overlay

### Technology

- **d3-force** — force simulation (charge, link, collision, centering)
- **d3-zoom** — pan and zoom on the SVG
- **d3-selection** — DOM manipulation for nodes and edges
- **d3-transition** — animated expand/collapse, fade in/out

These are imported as individual d3 packages, not the full d3 bundle.

### Node Rendering

| Role | Radius | Stroke | Label | Badge |
|------|--------|--------|-------|-------|
| Root CA | 24-32px | 2px, grade color | CN + cert count, always visible | Worst grade |
| Intermediate CA | 14-20px (scaled by cert count) | 1.5px, grade color | CN + count, always visible | Worst grade |
| Leaf cert | 5-7px | 1px, grade color | Hidden (shown on hover) | None |

- Fill: grade color at 12-15% opacity (translucent)
- Stroke: grade color at full opacity
- At-risk nodes (expired or grade F): pulsing opacity animation (1.0 to 0.6, 2s cycle)

Grade color mapping:
- A+/A: `#22c55e` (green)
- B: `#84cc16` (lime)
- C: `#eab308` (yellow)
- D: `#f97316` (orange)
- F: `#ef4444` (red)

### Edge Rendering

- Solid lines, 1-1.5px width
- Color: child node's grade color at 20-25% opacity
- Opacity fades further for nodes distant from selection/hover

### Force Simulation Parameters

- **Charge force**: Root CAs repel strongly (-300), intermediates moderately (-150), leaves weakly (-30)
- **Link force**: Root→intermediate strong (strength 0.7), intermediate→leaf weaker (strength 0.3) so leaves form soft clusters
- **Collision force**: Prevents overlap, radius matched to node size + padding
- **Center force**: Gentle pull toward viewport center (strength 0.05)
- **Simulation**: alpha decay 0.02 (settles in ~2 seconds), reheats on expand/collapse

### Interaction Modes

**1. Explore (default)**
- Pan: click-drag on background
- Zoom: scroll wheel
- Hover node: tooltip with CN, grade, cert count, expiry stats, key info
- Click CA node: fetches children via `/api/graph/ca/{fp}/children`, animates them into the simulation
- Click expanded CA: collapses children (removes from simulation with retract animation)
- Click leaf cert: navigates to `/certificates/{fingerprint}`

**2. Search**
- Activated by typing in the search bar
- First pass: client-side filter on currently loaded nodes (CAs + any expanded children)
- If fewer than 5 client-side matches: fires a server search (`GET /api/certificates?q=...&limit=10`) to find leaf certs not yet loaded. Results appear in the dropdown with a "not in graph" indicator — clicking one expands the parent CA chain to reveal it.
- Matching nodes: full opacity. Non-matching: fade to 15% opacity
- Click a match in the dropdown: centers and zooms to that node
- Clear search: all nodes restore to full opacity

**3. Blast Radius**
- Activated via toolbar toggle button, or right-click CA → "Show Blast Radius"
- Fetches full subgraph via `/api/graph/ca/{fp}/blast-radius`
- Selected CA + all descendants: highlighted at full opacity
- All other nodes: dimmed to 10% opacity
- Summary badge appears near the selected CA: "342 certs, 12 expired, 3 grade F"
- Exit: click background, press Escape, or click the toolbar toggle again

### Animations

| Action | Duration | Effect |
|--------|----------|--------|
| Initial load | ~1000ms | Nodes fade in as simulation stabilizes |
| Expand CA | ~300ms | Children fly out from parent position, simulation reheats |
| Collapse CA | ~300ms | Children retract into parent, then removed from DOM |
| Blast radius activate | ~200ms | Non-selected nodes fade out |
| Blast radius deactivate | ~200ms | All nodes fade back in |
| At-risk pulse | 2000ms cycle | Opacity oscillates 1.0 → 0.6 (continuous) |

### Toolbar Controls

From left to right:
1. **Search input** — text field with magnifying glass icon
2. **Grade filter pills** — "All", "A", "B", "C", "D", "F" — toggle to show/hide nodes by grade
3. **Expired filter** — highlights expired certs and their chains
4. **Blast Radius toggle** — enters blast radius mode (then click a CA)
5. **Zoom controls** — +, -, reset (fit to viewport)

### Component Structure

```
frontend/src/routes/pki/
  +page.svelte          — page shell, toolbar, overlays, state management

frontend/src/lib/components/graph/
  ForceGraph.svelte     — D3 force simulation, SVG rendering, pan/zoom
  GraphTooltip.svelte   — hover tooltip component
  GraphToolbar.svelte   — search, filters, zoom controls
  GraphLegend.svelte    — bottom-left legend overlay
  graph-simulation.ts   — D3 force setup, node/edge management, expand/collapse logic
  graph-types.ts        — TypeScript types for graph nodes, edges, state
```

### State Management

All graph state lives in the `+page.svelte` component using Svelte 5 runes:

- `nodes: GraphNode[]` — currently visible nodes
- `edges: GraphEdge[]` — currently visible edges
- `expandedCAs: Set<string>` — fingerprints of expanded CAs
- `mode: 'explore' | 'search' | 'blast-radius'`
- `searchQuery: string`
- `blastRadiusTarget: string | null` — fingerprint of selected CA in blast radius mode
- `hoveredNode: GraphNode | null`

## Dependencies

New npm packages:
- `d3-force` — force simulation
- `d3-zoom` — pan/zoom behavior
- `d3-selection` — DOM binding
- `d3-transition` — animations
- `@types/d3-force`, `@types/d3-zoom`, `@types/d3-selection`, `@types/d3-transition`

No changes to Go dependencies.

## What Gets Removed

- The current `/pki` tree view (`frontend/src/routes/pki/+page.svelte`) is replaced entirely
- The existing Cytoscape.js usage on the certificate detail page (`/certificates/[fingerprint]`) is **not affected** — it stays as-is

## Out of Scope

- WebGL rendering (server-side aggregation keeps node counts manageable for SVG)
- Real-time updates / WebSocket push (certificates don't change fast enough to warrant this)
- Export/screenshot functionality
- Mobile layout (enterprise tool, desktop-first)
- Certificate revocation status checking (separate feature)
