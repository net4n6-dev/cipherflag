# Analytics: Chain Flow & Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the analytics page with a tabbed layout containing a D3 Sankey chain flow diagram and an ownership view (treemap + deployment bar chart).

**Architecture:** Three new API endpoints (`chain-flow`, `ownership`, `deployment`) backed by store queries, feeding D3 visualizations on a tabbed SvelteKit page. Model types in a new `analytics.go` file. Frontend components split by visualization type.

**Tech Stack:** Go (chi, pgx/PostgreSQL), SvelteKit 5, D3 (d3-sankey, d3-hierarchy, d3-selection, d3-transition), TypeScript.

**Spec:** `docs/superpowers/specs/2026-03-27-analytics-chain-ownership-design.md`

---

## File Map

### Backend — New/Modified

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/model/analytics.go` | Create | ChainFlow, Ownership, Deployment response types |
| `internal/store/store.go` | Modify | Add 3 new methods to CertStore interface |
| `internal/store/postgres.go` | Modify | Implement 3 new store methods |
| `internal/api/handler/stats.go` | Modify | Add ChainFlow, Ownership, Deployment handlers |
| `internal/api/server.go` | Modify | Register 3 new routes |

### Frontend — New/Modified

| File | Action | Responsibility |
|------|--------|----------------|
| `frontend/src/lib/api.ts` | Modify | Add new types + API methods |
| `frontend/src/lib/components/analytics/analytics-types.ts` | Create | Shared types/constants for analytics components |
| `frontend/src/lib/components/analytics/ChainFlowTab.svelte` | Create | Sankey wrapper, loads data |
| `frontend/src/lib/components/analytics/SankeyChart.svelte` | Create | D3 sankey rendering |
| `frontend/src/lib/components/analytics/OwnershipTab.svelte` | Create | Ownership wrapper, loads both datasets |
| `frontend/src/lib/components/analytics/OwnershipTreemap.svelte` | Create | D3 treemap rendering |
| `frontend/src/lib/components/analytics/DeploymentChart.svelte` | Create | D3 horizontal bar chart |
| `frontend/src/routes/analytics/+page.svelte` | Replace | Tab shell, URL sync |

---

## Task 1: Backend — Model Types

**Files:**
- Create: `internal/model/analytics.go`
- Modify: `internal/store/store.go`

- [ ] **Step 1: Create analytics.go with all response types**

```go
package model

// ChainFlowNode represents a node in the Sankey chain flow diagram.
type ChainFlowNode struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	NodeType     string `json:"type"`
	CertCount    int    `json:"cert_count"`
	Grade        string `json:"grade"`
	ExpiredCount int    `json:"expired_count"`
}

// ChainFlowLink represents a link in the Sankey chain flow diagram.
type ChainFlowLink struct {
	Source       string `json:"source"`
	Target       string `json:"target"`
	Value        int    `json:"value"`
	WorstGrade   string `json:"worst_grade"`
	ExpiredCount int    `json:"expired_count"`
}

// ChainFlowResponse is the API response for the chain flow Sankey.
type ChainFlowResponse struct {
	Nodes []ChainFlowNode `json:"nodes"`
	Links []ChainFlowLink `json:"links"`
}

// OwnershipGroup represents a grouping of certs by issuer org + subject OU.
type OwnershipGroup struct {
	IssuerOrg        string  `json:"issuer_org"`
	SubjectOU        string  `json:"subject_ou"`
	CertCount        int     `json:"cert_count"`
	ExpiredCount     int     `json:"expired_count"`
	Expiring30dCount int     `json:"expiring_30d_count"`
	WorstGrade       string  `json:"worst_grade"`
	AvgScore         float64 `json:"avg_score"`
}

// OwnershipResponse is the API response for ownership analytics.
type OwnershipResponse struct {
	Groups       []OwnershipGroup `json:"groups"`
	TotalCerts   int              `json:"total_certs"`
	TotalIssuers int              `json:"total_issuers"`
	TotalOUs     int              `json:"total_ous"`
}

// DeploymentGroup represents a grouping of certs by observed domain.
type DeploymentGroup struct {
	Domain       string  `json:"domain"`
	CertCount    int     `json:"cert_count"`
	UniqueIPs    int     `json:"unique_ips"`
	ExpiredCount int     `json:"expired_count"`
	WorstGrade   string  `json:"worst_grade"`
	AvgScore     float64 `json:"avg_score"`
}

// DeploymentResponse is the API response for deployment analytics.
type DeploymentResponse struct {
	Groups             []DeploymentGroup `json:"groups"`
	TotalObservedCerts int               `json:"total_observed_certs"`
	TotalDomains       int               `json:"total_domains"`
}
```

- [ ] **Step 2: Add 3 new methods to CertStore interface in store.go**

Add these in the `// PKI tree + analytics` section, after `GetExpiryTimeline`:

```go
	GetChainFlow(ctx context.Context) (*model.ChainFlowResponse, error)
	GetOwnershipStats(ctx context.Context) (*model.OwnershipResponse, error)
	GetDeploymentStats(ctx context.Context) (*model.DeploymentResponse, error)
```

- [ ] **Step 3: Verify it compiles (expect missing method error)**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: Compile error — PostgresStore missing 3 methods.

- [ ] **Step 4: Commit**

```bash
git add internal/model/analytics.go internal/store/store.go
git commit -m "feat(model): add analytics types for chain flow, ownership, deployment"
```

---

## Task 2: Backend — GetChainFlow Store Method

**Files:**
- Modify: `internal/store/postgres.go`

- [ ] **Step 1: Implement GetChainFlow**

Add this method after the existing `GetExpiryTimeline` method. The query gets all CAs with their issuer relationships, then builds Sankey nodes and links in Go.

```go
func (s *PostgresStore) GetChainFlow(ctx context.Context) (*model.ChainFlowResponse, error) {
	// Get all CAs with health grades and leaf counts
	rows, err := s.pool.Query(ctx, `
		SELECT
			ca.fingerprint_sha256,
			ca.subject_cn,
			ca.issuer_cn,
			ca.is_ca,
			CASE WHEN ca.subject_cn = ca.issuer_cn OR ca.issuer_cn = '' THEN 'root' ELSE 'intermediate' END as node_type,
			COALESCE(h.grade, '?') as grade,
			(SELECT COUNT(*) FROM certificates ch
			 WHERE ch.issuer_cn = ca.subject_cn AND ch.is_ca = false
			 AND ch.fingerprint_sha256 != ca.fingerprint_sha256) as leaf_count,
			(SELECT COUNT(*) FROM certificates ch
			 WHERE ch.issuer_cn = ca.subject_cn AND ch.is_ca = false
			 AND ch.not_after < NOW()
			 AND ch.fingerprint_sha256 != ca.fingerprint_sha256) as leaf_expired,
			(SELECT COALESCE(MAX(h2.grade), '?') FROM certificates ch2
			 JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
			 WHERE ch2.issuer_cn = ca.subject_cn AND ch2.is_ca = false
			 AND ch2.fingerprint_sha256 != ca.fingerprint_sha256) as leaf_worst_grade
		FROM certificates ca
		LEFT JOIN health_reports h ON ca.fingerprint_sha256 = h.cert_fingerprint
		WHERE ca.is_ca = true
		ORDER BY node_type, ca.subject_cn
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.ChainFlowResponse{
		Nodes: []model.ChainFlowNode{},
		Links: []model.ChainFlowLink{},
	}

	type caInfo struct {
		fp, cn, issuerCN, nodeType, grade, leafWorstGrade string
		leafCount, leafExpired                             int
	}
	var cas []caInfo
	caSubjects := map[string]string{} // subject_cn → fingerprint

	for rows.Next() {
		var c caInfo
		var isCA bool
		if err := rows.Scan(&c.fp, &c.cn, &c.issuerCN, &isCA,
			&c.nodeType, &c.grade, &c.leafCount, &c.leafExpired, &c.leafWorstGrade); err != nil {
			return nil, err
		}
		cas = append(cas, c)
		caSubjects[c.cn] = c.fp
	}

	// Build nodes: CAs + leaf aggregates
	for _, ca := range cas {
		// CA node
		resp.Nodes = append(resp.Nodes, model.ChainFlowNode{
			ID:           "fp-" + ca.fp,
			Label:        ca.cn,
			NodeType:     ca.nodeType,
			CertCount:    ca.leafCount,
			Grade:        ca.grade,
			ExpiredCount: ca.leafExpired,
		})

		// Leaf aggregate node (only if this CA has leaf children)
		if ca.leafCount > 0 {
			leafGrade := ca.leafWorstGrade
			if leafGrade == "" {
				leafGrade = "?"
			}
			resp.Nodes = append(resp.Nodes, model.ChainFlowNode{
				ID:           "leaves-fp-" + ca.fp,
				Label:        fmt.Sprintf("%d leaf certificates", ca.leafCount),
				NodeType:     "leaf-aggregate",
				CertCount:    ca.leafCount,
				Grade:        leafGrade,
				ExpiredCount: ca.leafExpired,
			})

			// Link: CA → its leaf aggregate
			resp.Links = append(resp.Links, model.ChainFlowLink{
				Source:       "fp-" + ca.fp,
				Target:       "leaves-fp-" + ca.fp,
				Value:        ca.leafCount,
				WorstGrade:   leafGrade,
				ExpiredCount: ca.leafExpired,
			})
		}
	}

	// Build links between CAs: intermediate → root (or intermediate → intermediate)
	for _, ca := range cas {
		if ca.nodeType == "intermediate" {
			if issuerFP, ok := caSubjects[ca.issuerCN]; ok && ca.issuerCN != ca.cn {
				// Link value = total certs flowing through this intermediate
				resp.Links = append(resp.Links, model.ChainFlowLink{
					Source:       "fp-" + issuerFP,
					Target:       "fp-" + ca.fp,
					Value:        max(ca.leafCount, 1),
					WorstGrade:   ca.grade,
					ExpiredCount: ca.leafExpired,
				})
			}
		}
	}

	return resp, nil
}
```

- [ ] **Step 2: Verify partial compilation**

Run: `cd /Users/Erik/projects/cipherflag && go build ./internal/store/...`
Expected: Still missing 2 methods, but no syntax errors in GetChainFlow.

- [ ] **Step 3: Commit**

```bash
git add internal/store/postgres.go
git commit -m "feat(store): implement GetChainFlow for Sankey diagram"
```

---

## Task 3: Backend — GetOwnershipStats Store Method

**Files:**
- Modify: `internal/store/postgres.go`

- [ ] **Step 1: Implement GetOwnershipStats**

Add after `GetChainFlow`:

```go
func (s *PostgresStore) GetOwnershipStats(ctx context.Context) (*model.OwnershipResponse, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			COALESCE(NULLIF(c.issuer_org, ''), 'Unknown Issuer') as issuer_org,
			COALESCE(NULLIF(c.subject_ou, ''), '') as subject_ou,
			COUNT(*) as cert_count,
			COUNT(*) FILTER (WHERE c.not_after < NOW()) as expired_count,
			COUNT(*) FILTER (WHERE c.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days') as expiring_30d_count,
			COALESCE(MAX(h.grade), '?') as worst_grade,
			COALESCE(AVG(h.score)::numeric(5,1), 0) as avg_score
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		GROUP BY COALESCE(NULLIF(c.issuer_org, ''), 'Unknown Issuer'),
		         COALESCE(NULLIF(c.subject_ou, ''), '')
		ORDER BY cert_count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.OwnershipResponse{
		Groups: []model.OwnershipGroup{},
	}

	issuers := map[string]bool{}
	ous := map[string]bool{}

	for rows.Next() {
		var g model.OwnershipGroup
		if err := rows.Scan(&g.IssuerOrg, &g.SubjectOU, &g.CertCount,
			&g.ExpiredCount, &g.Expiring30dCount, &g.WorstGrade, &g.AvgScore); err != nil {
			return nil, err
		}
		resp.Groups = append(resp.Groups, g)
		resp.TotalCerts += g.CertCount
		issuers[g.IssuerOrg] = true
		if g.SubjectOU != "" {
			ous[g.SubjectOU] = true
		}
	}

	resp.TotalIssuers = len(issuers)
	resp.TotalOUs = len(ous)

	return resp, nil
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/store/postgres.go
git commit -m "feat(store): implement GetOwnershipStats for org/OU analytics"
```

---

## Task 4: Backend — GetDeploymentStats Store Method

**Files:**
- Modify: `internal/store/postgres.go`

- [ ] **Step 1: Implement GetDeploymentStats**

Add after `GetOwnershipStats`. This joins certificates to observations via `cert_fingerprint` and groups by extracted domain from `server_name`:

```go
func (s *PostgresStore) GetDeploymentStats(ctx context.Context) (*model.DeploymentResponse, error) {
	// Extract base domain: strip leftmost subdomain label if 3+ labels exist.
	// e.g., "api.payments.acme.com" → "payments.acme.com", "acme.com" stays as-is.
	rows, err := s.pool.Query(ctx, `
		WITH cert_domains AS (
			SELECT DISTINCT
				o.cert_fingerprint,
				o.server_ip,
				CASE
					WHEN array_length(string_to_array(o.server_name, '.'), 1) >= 3
					THEN substring(o.server_name from position('.' in o.server_name) + 1)
					ELSE o.server_name
				END as domain
			FROM observations o
			WHERE o.server_name IS NOT NULL AND o.server_name != ''
		)
		SELECT
			cd.domain,
			COUNT(DISTINCT cd.cert_fingerprint) as cert_count,
			COUNT(DISTINCT cd.server_ip) as unique_ips,
			COUNT(DISTINCT cd.cert_fingerprint) FILTER (WHERE c.not_after < NOW()) as expired_count,
			COALESCE(MAX(h.grade), '?') as worst_grade,
			COALESCE(AVG(h.score)::numeric(5,1), 0) as avg_score
		FROM cert_domains cd
		JOIN certificates c ON c.fingerprint_sha256 = cd.cert_fingerprint
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		GROUP BY cd.domain
		ORDER BY cert_count DESC
		LIMIT 50
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.DeploymentResponse{
		Groups: []model.DeploymentGroup{},
	}

	domains := map[string]bool{}
	for rows.Next() {
		var g model.DeploymentGroup
		if err := rows.Scan(&g.Domain, &g.CertCount, &g.UniqueIPs,
			&g.ExpiredCount, &g.WorstGrade, &g.AvgScore); err != nil {
			return nil, err
		}
		resp.Groups = append(resp.Groups, g)
		resp.TotalObservedCerts += g.CertCount
		domains[g.Domain] = true
	}

	resp.TotalDomains = len(domains)

	return resp, nil
}
```

- [ ] **Step 2: Verify full Go compilation**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: PASS — all interface methods implemented.

- [ ] **Step 3: Commit**

```bash
git add internal/store/postgres.go
git commit -m "feat(store): implement GetDeploymentStats for observation-based analytics"
```

---

## Task 5: Backend — API Handlers & Routes

**Files:**
- Modify: `internal/api/handler/stats.go`
- Modify: `internal/api/server.go`

- [ ] **Step 1: Add three new handlers to stats.go**

Append after the existing `ExpiryTimeline` method:

```go
func (h *StatsHandler) ChainFlow(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetChainFlow(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) Ownership(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetOwnershipStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) Deployment(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetDeploymentStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
```

- [ ] **Step 2: Register routes in server.go**

Add these lines after the existing stats routes (after `r.Get("/stats/expiry-timeline", statsH.ExpiryTimeline)`):

```go
		r.Get("/stats/chain-flow", statsH.ChainFlow)
		r.Get("/stats/ownership", statsH.Ownership)
		r.Get("/stats/deployment", statsH.Deployment)
```

- [ ] **Step 3: Verify compilation**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/api/handler/stats.go internal/api/server.go
git commit -m "feat(api): add chain-flow, ownership, and deployment stats endpoints"
```

---

## Task 6: Frontend — Install D3 Packages & Add API Types

**Files:**
- Modify: `frontend/package.json` (via npm install)
- Modify: `frontend/src/lib/api.ts`

- [ ] **Step 1: Install D3 sankey and hierarchy packages**

```bash
cd /Users/Erik/projects/cipherflag/frontend && npm install d3-sankey d3-hierarchy d3-scale d3-shape && npm install -D @types/d3-sankey @types/d3-hierarchy @types/d3-scale @types/d3-shape
```

- [ ] **Step 2: Add new types and API methods to api.ts**

Add these types before the `export const api = {` line:

```typescript
export interface ChainFlowNode {
	id: string;
	label: string;
	type: 'root' | 'intermediate' | 'leaf-aggregate';
	cert_count: number;
	grade: string;
	expired_count: number;
}

export interface ChainFlowLink {
	source: string;
	target: string;
	value: number;
	worst_grade: string;
	expired_count: number;
}

export interface ChainFlowResponse {
	nodes: ChainFlowNode[];
	links: ChainFlowLink[];
}

export interface OwnershipGroup {
	issuer_org: string;
	subject_ou: string;
	cert_count: number;
	expired_count: number;
	expiring_30d_count: number;
	worst_grade: string;
	avg_score: number;
}

export interface OwnershipResponse {
	groups: OwnershipGroup[];
	total_certs: number;
	total_issuers: number;
	total_ous: number;
}

export interface DeploymentGroup {
	domain: string;
	cert_count: number;
	unique_ips: number;
	expired_count: number;
	worst_grade: string;
	avg_score: number;
}

export interface DeploymentResponse {
	groups: DeploymentGroup[];
	total_observed_certs: number;
	total_domains: number;
}
```

Add these methods inside the `api` object:

```typescript
	getChainFlow: () => fetchJSON<ChainFlowResponse>('/stats/chain-flow'),
	getOwnership: () => fetchJSON<OwnershipResponse>('/stats/ownership'),
	getDeployment: () => fetchJSON<DeploymentResponse>('/stats/deployment'),
```

- [ ] **Step 3: Verify frontend compiles**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check`
Expected: No new errors.

- [ ] **Step 4: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/package.json frontend/package-lock.json frontend/src/lib/api.ts
git commit -m "feat(frontend): add D3 sankey/hierarchy deps and analytics API types"
```

---

## Task 7: Frontend — Analytics Types & Shared Constants

**Files:**
- Create: `frontend/src/lib/components/analytics/analytics-types.ts`

- [ ] **Step 1: Create directory and types file**

```bash
mkdir -p /Users/Erik/projects/cipherflag/frontend/src/lib/components/analytics
```

```typescript
// analytics-types.ts — Shared constants for analytics components

export const GRADE_COLORS: Record<string, string> = {
	'A+': '#22c55e',
	'A': '#22c55e',
	'B': '#84cc16',
	'C': '#eab308',
	'D': '#f97316',
	'F': '#ef4444',
	'?': '#64748b',
};

export function gradeColor(grade: string): string {
	return GRADE_COLORS[grade] ?? '#64748b';
}
```

- [ ] **Step 2: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/lib/components/analytics/
git commit -m "feat(frontend): add analytics shared types and constants"
```

---

## Task 8: Frontend — SankeyChart Component

**Files:**
- Create: `frontend/src/lib/components/analytics/SankeyChart.svelte`

- [ ] **Step 1: Create SankeyChart.svelte**

```svelte
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { sankey, sankeyLinkHorizontal, type SankeyNode, type SankeyLink } from 'd3-sankey';
	import { select } from 'd3-selection';
	import type { ChainFlowNode, ChainFlowLink } from '$lib/api';
	import { gradeColor } from './analytics-types';
	import 'd3-transition';

	interface Props {
		nodes: ChainFlowNode[];
		links: ChainFlowLink[];
		onNodeClick: (nodeId: string, nodeType: string) => void;
	}

	let { nodes, links, onNodeClick }: Props = $props();

	let containerEl: HTMLDivElement;
	let width = $state(900);
	let height = $state(500);
	let resizeObserver: ResizeObserver;

	type SNode = SankeyNode<ChainFlowNode, ChainFlowLink>;
	type SLink = SankeyLink<ChainFlowNode, ChainFlowLink>;

	let sankeyNodes: SNode[] = $state([]);
	let sankeyLinks: SLink[] = $state([]);

	let hoveredLink: SLink | null = $state(null);
	let hoveredNode: SNode | null = $state(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);

	function computeLayout() {
		if (nodes.length === 0) return;

		const nodeMap = new Map(nodes.map((n, i) => [n.id, i]));
		const validLinks = links.filter(l => nodeMap.has(l.source) && nodeMap.has(l.target) && l.value > 0);

		const layout = sankey<ChainFlowNode, ChainFlowLink>()
			.nodeId(d => d.id)
			.nodeWidth(16)
			.nodePadding(8)
			.extent([[60, 20], [width - 60, height - 20]]);

		const graph = layout({
			nodes: nodes.map(n => ({ ...n })),
			links: validLinks.map(l => ({ ...l })),
		});

		sankeyNodes = graph.nodes as SNode[];
		sankeyLinks = graph.links as SLink[];
	}

	onMount(() => {
		const rect = containerEl.getBoundingClientRect();
		width = rect.width;
		height = Math.max(400, Math.min(700, nodes.length * 12 + 100));

		resizeObserver = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) {
				width = entry.contentRect.width;
				computeLayout();
			}
		});
		resizeObserver.observe(containerEl);

		computeLayout();
	});

	onDestroy(() => {
		if (resizeObserver) resizeObserver.disconnect();
	});

	$effect(() => {
		if (nodes && links && width > 0) {
			computeLayout();
		}
	});

	function linkPath(link: SLink): string {
		return sankeyLinkHorizontal()(link as any) ?? '';
	}

	function nodeLabel(node: SNode): string {
		const d = node as unknown as ChainFlowNode;
		if (d.type === 'leaf-aggregate') return `${d.cert_count.toLocaleString()} leaves`;
		const label = d.label.length > 28 ? d.label.slice(0, 26) + '...' : d.label;
		return label;
	}

	function handleLinkHover(link: SLink | null, e?: PointerEvent) {
		hoveredLink = link;
		if (e) { tooltipX = e.clientX; tooltipY = e.clientY; }
	}

	function handleNodeHover(node: SNode | null, e?: PointerEvent) {
		hoveredNode = node;
		if (e) { tooltipX = e.clientX; tooltipY = e.clientY; }
	}
</script>

<div class="sankey-container" bind:this={containerEl}>
	<svg {width} {height}>
		<!-- Links -->
		{#each sankeyLinks as link, i (i)}
			{@const src = link.source as SNode}
			{@const tgt = link.target as SNode}
			<path
				class="sankey-link"
				d={linkPath(link)}
				fill="none"
				stroke={gradeColor((link as unknown as ChainFlowLink).worst_grade)}
				stroke-opacity={hoveredLink === link ? 0.8 : 0.4}
				stroke-width={Math.max(link.width ?? 1, 1)}
				onpointerenter={(e) => handleLinkHover(link, e)}
				onpointerleave={() => handleLinkHover(null)}
			/>
		{/each}

		<!-- Nodes -->
		{#each sankeyNodes as node, i (i)}
			{@const d = node as unknown as ChainFlowNode}
			<g
				class="sankey-node"
				transform="translate({node.x0 ?? 0},{node.y0 ?? 0})"
				onclick={() => onNodeClick(d.id, d.type)}
				onpointerenter={(e) => handleNodeHover(node, e)}
				onpointerleave={() => handleNodeHover(null)}
				role="button"
				tabindex="-1"
			>
				<rect
					width={(node.x1 ?? 0) - (node.x0 ?? 0)}
					height={(node.y1 ?? 0) - (node.y0 ?? 0)}
					fill={gradeColor(d.grade)}
					fill-opacity={0.25}
					stroke={gradeColor(d.grade)}
					stroke-width={1}
					rx={3}
				/>
				{#if ((node.y1 ?? 0) - (node.y0 ?? 0)) > 14}
					<text
						x={d.type === 'leaf-aggregate' ? -6 : ((node.x1 ?? 0) - (node.x0 ?? 0)) + 6}
						y={((node.y1 ?? 0) - (node.y0 ?? 0)) / 2}
						text-anchor={d.type === 'leaf-aggregate' ? 'end' : 'start'}
						dominant-baseline="middle"
						fill="#cbd5e1"
						font-size="11"
					>
						{nodeLabel(node)}
					</text>
				{/if}
			</g>
		{/each}
	</svg>

	<!-- Column labels -->
	<div class="column-labels">
		<span style="left: 60px">Root CAs</span>
		<span style="left: {width / 2}px; transform: translateX(-50%)">Intermediates</span>
		<span style="right: 60px">Leaf Certificates</span>
	</div>

	<!-- Tooltip -->
	{#if hoveredLink}
		{@const src = hoveredLink.source as unknown as ChainFlowNode}
		{@const tgt = hoveredLink.target as unknown as ChainFlowNode}
		{@const ld = hoveredLink as unknown as ChainFlowLink}
		<div class="sankey-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
			<div class="tt-flow">{src.label} &rarr; {tgt.label}</div>
			<div class="tt-stats">
				<span>{ld.value.toLocaleString()} certs</span>
				{#if ld.expired_count > 0}<span class="tt-expired">{ld.expired_count} expired</span>{/if}
				<span class="tt-grade" style="color:{gradeColor(ld.worst_grade)}">Grade {ld.worst_grade}</span>
			</div>
		</div>
	{/if}

	{#if hoveredNode && !hoveredLink}
		{@const nd = hoveredNode as unknown as ChainFlowNode}
		<div class="sankey-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
			<div class="tt-flow">{nd.label}</div>
			<div class="tt-stats">
				<span>{nd.cert_count.toLocaleString()} certs</span>
				{#if nd.expired_count > 0}<span class="tt-expired">{nd.expired_count} expired</span>{/if}
				<span class="tt-grade" style="color:{gradeColor(nd.grade)}">Grade {nd.grade}</span>
			</div>
		</div>
	{/if}
</div>

<style>
	.sankey-container {
		position: relative;
		width: 100%;
	}

	svg { display: block; }

	.sankey-link { cursor: pointer; transition: stroke-opacity 0.15s; }
	.sankey-node { cursor: pointer; }

	.column-labels {
		position: absolute;
		top: 2px;
		left: 0;
		right: 0;
		display: flex;
		justify-content: space-between;
		pointer-events: none;
	}

	.column-labels span {
		position: absolute;
		font-size: 0.65rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: #64748b;
	}

	.sankey-tooltip {
		position: fixed;
		background: rgba(15, 23, 42, 0.95);
		border: 1px solid rgba(56, 189, 248, 0.25);
		border-radius: 8px;
		padding: 0.5rem 0.75rem;
		z-index: 50;
		pointer-events: none;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
	}

	.tt-flow { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; margin-bottom: 0.25rem; }
	.tt-stats { display: flex; gap: 0.75rem; font-size: 0.75rem; color: #94a3b8; }
	.tt-expired { color: #ef4444; }
	.tt-grade { font-weight: 600; }
</style>
```

- [ ] **Step 2: Verify compilation**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check`
Expected: No new errors.

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/lib/components/analytics/
git commit -m "feat(frontend): add SankeyChart D3 component for chain flow"
```

---

## Task 9: Frontend — ChainFlowTab Wrapper

**Files:**
- Create: `frontend/src/lib/components/analytics/ChainFlowTab.svelte`

- [ ] **Step 1: Create ChainFlowTab.svelte**

```svelte
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api } from '$lib/api';
	import type { ChainFlowNode, ChainFlowLink } from '$lib/api';
	import SankeyChart from './SankeyChart.svelte';

	let nodes: ChainFlowNode[] = $state([]);
	let links: ChainFlowLink[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	onMount(async () => {
		try {
			const resp = await api.getChainFlow();
			nodes = resp.nodes;
			links = resp.links;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load chain flow';
		}
		loading = false;
	});

	function handleNodeClick(nodeId: string, nodeType: string) {
		if (nodeType === 'leaf-aggregate') {
			// Navigate to certificate list filtered by this intermediate's CN
			const intermediateId = nodeId.replace('leaves-fp-', 'fp-');
			const intermediateNode = nodes.find(n => n.id === intermediateId);
			if (intermediateNode) {
				goto(`/certificates?issuer_cn=${encodeURIComponent(intermediateNode.label)}`);
			}
		} else {
			// Navigate to PKI explorer to inspect this CA
			const fp = nodeId.replace('fp-', '');
			goto(`/pki?select=${fp}`);
		}
	}
</script>

<div class="chain-flow-tab">
	{#if loading}
		<div class="tab-loading">Loading chain flow...</div>
	{:else if error}
		<div class="tab-error">{error}</div>
	{:else if nodes.length === 0}
		<div class="tab-empty">No certificate chain data available.</div>
	{:else}
		<div class="tab-header">
			<h2>Certificate Chain Flow</h2>
			<span class="tab-meta">
				{nodes.filter(n => n.type === 'root').length} roots &middot;
				{nodes.filter(n => n.type === 'intermediate').length} intermediates &middot;
				{nodes.filter(n => n.type === 'leaf-aggregate').reduce((s, n) => s + n.cert_count, 0).toLocaleString()} leaf certs
			</span>
		</div>
		<SankeyChart {nodes} {links} onNodeClick={handleNodeClick} />
	{/if}
</div>

<style>
	.chain-flow-tab {
		padding: 1.5rem;
		height: 100%;
		overflow-y: auto;
	}

	.tab-header {
		display: flex;
		align-items: baseline;
		gap: 1rem;
		margin-bottom: 1rem;
	}

	.tab-header h2 {
		margin: 0;
		font-size: 1.1rem;
		font-weight: 700;
		color: var(--cf-text-primary);
	}

	.tab-meta {
		font-size: 0.8rem;
		color: var(--cf-text-muted);
	}

	.tab-loading, .tab-error, .tab-empty {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 50vh;
		color: var(--cf-text-muted);
		font-size: 0.9rem;
	}

	.tab-error { color: var(--cf-risk-critical); }
</style>
```

- [ ] **Step 2: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/lib/components/analytics/ChainFlowTab.svelte
git commit -m "feat(frontend): add ChainFlowTab wrapper component"
```

---

## Task 10: Frontend — OwnershipTreemap Component

**Files:**
- Create: `frontend/src/lib/components/analytics/OwnershipTreemap.svelte`

- [ ] **Step 1: Create OwnershipTreemap.svelte**

```svelte
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { hierarchy, treemap, treemapSquarify } from 'd3-hierarchy';
	import type { OwnershipGroup } from '$lib/api';
	import { gradeColor } from './analytics-types';

	interface Props {
		groups: OwnershipGroup[];
		onGroupClick: (issuerOrg: string, subjectOU: string) => void;
	}

	let { groups, onGroupClick }: Props = $props();

	let containerEl: HTMLDivElement;
	let width = $state(800);
	let height = $state(400);
	let resizeObserver: ResizeObserver;

	interface TreeRect {
		x: number;
		y: number;
		w: number;
		h: number;
		issuerOrg: string;
		subjectOU: string;
		certCount: number;
		expiredCount: number;
		grade: string;
		avgScore: number;
		showLabel: boolean;
	}

	let rects: TreeRect[] = $state([]);
	let hoveredRect: TreeRect | null = $state(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);

	function computeLayout() {
		if (groups.length === 0) { rects = []; return; }

		// Build hierarchy: root → issuer_org → subject_ou
		const byIssuer = new Map<string, OwnershipGroup[]>();
		for (const g of groups) {
			const existing = byIssuer.get(g.issuer_org) ?? [];
			existing.push(g);
			byIssuer.set(g.issuer_org, existing);
		}

		const children = Array.from(byIssuer.entries()).map(([org, items]) => ({
			name: org,
			children: items.map(g => ({
				name: g.subject_ou || 'Unspecified',
				value: g.cert_count,
				issuerOrg: g.issuer_org,
				subjectOU: g.subject_ou,
				expiredCount: g.expired_count,
				grade: g.worst_grade,
				avgScore: g.avg_score,
			})),
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
		const leaves = root.leaves();
		rects = leaves.map(leaf => {
			const d = leaf.data;
			const w = (leaf.x1 ?? 0) - (leaf.x0 ?? 0);
			const h = (leaf.y1 ?? 0) - (leaf.y0 ?? 0);
			const area = w * h;
			return {
				x: leaf.x0 ?? 0,
				y: leaf.y0 ?? 0,
				w,
				h,
				issuerOrg: d.issuerOrg ?? leaf.parent?.data.name ?? '',
				subjectOU: d.subjectOU ?? '',
				certCount: d.value ?? 0,
				expiredCount: d.expiredCount ?? 0,
				grade: d.grade ?? '?',
				avgScore: d.avgScore ?? 0,
				showLabel: area / totalArea > 0.03 && w > 60 && h > 30,
			};
		});
	}

	onMount(() => {
		const rect = containerEl.getBoundingClientRect();
		width = rect.width;
		resizeObserver = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) { width = entry.contentRect.width; computeLayout(); }
		});
		resizeObserver.observe(containerEl);
		computeLayout();
	});

	onDestroy(() => {
		if (resizeObserver) resizeObserver.disconnect();
	});

	$effect(() => {
		if (groups && width > 0) computeLayout();
	});
</script>

<div class="treemap-container" bind:this={containerEl}>
	<svg {width} {height}>
		{#each rects as r, i (i)}
			<g
				transform="translate({r.x},{r.y})"
				onclick={() => onGroupClick(r.issuerOrg, r.subjectOU)}
				onpointerenter={(e) => { hoveredRect = r; tooltipX = e.clientX; tooltipY = e.clientY; }}
				onpointerleave={() => hoveredRect = null}
				role="button"
				tabindex="-1"
			>
				<rect
					width={r.w}
					height={r.h}
					fill={gradeColor(r.grade)}
					fill-opacity={0.2}
					stroke={gradeColor(r.grade)}
					stroke-opacity={0.5}
					stroke-width={1}
					rx={3}
				/>
				{#if r.showLabel}
					<text x={4} y={14} fill="#e2e8f0" font-size="10" font-weight="600">
						{r.issuerOrg.length > r.w / 6 ? r.issuerOrg.slice(0, Math.floor(r.w / 6)) + '...' : r.issuerOrg}
					</text>
					{#if r.subjectOU && r.h > 44}
						<text x={4} y={26} fill="#94a3b8" font-size="9">
							{r.subjectOU === '' ? 'Unspecified' : r.subjectOU}
						</text>
					{/if}
					<text x={4} y={r.h - 6} fill="#64748b" font-size="9">
						{r.certCount.toLocaleString()}
					</text>
				{/if}
			</g>
		{/each}
	</svg>

	{#if hoveredRect}
		<div class="treemap-tooltip" style="left:{tooltipX + 12}px; top:{tooltipY - 8}px">
			<div class="tt-org">{hoveredRect.issuerOrg}</div>
			{#if hoveredRect.subjectOU}
				<div class="tt-ou">OU: {hoveredRect.subjectOU}</div>
			{:else}
				<div class="tt-ou">OU: Unspecified</div>
			{/if}
			<div class="tt-stats">
				<span>{hoveredRect.certCount.toLocaleString()} certs</span>
				{#if hoveredRect.expiredCount > 0}<span class="tt-expired">{hoveredRect.expiredCount} expired</span>{/if}
				<span>Score: {hoveredRect.avgScore.toFixed(0)}</span>
				<span class="tt-grade" style="color:{gradeColor(hoveredRect.grade)}">Grade {hoveredRect.grade}</span>
			</div>
		</div>
	{/if}
</div>

<style>
	.treemap-container { position: relative; width: 100%; }
	svg { display: block; }
	g { cursor: pointer; }
	g rect { transition: fill-opacity 0.15s; }
	g:hover rect { fill-opacity: 0.35; }

	text { pointer-events: none; user-select: none; }

	.treemap-tooltip {
		position: fixed;
		background: rgba(15, 23, 42, 0.95);
		border: 1px solid rgba(56, 189, 248, 0.25);
		border-radius: 8px;
		padding: 0.5rem 0.75rem;
		z-index: 50;
		pointer-events: none;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
	}

	.tt-org { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; }
	.tt-ou { font-size: 0.7rem; color: #64748b; margin-bottom: 0.25rem; }
	.tt-stats { display: flex; gap: 0.75rem; font-size: 0.75rem; color: #94a3b8; }
	.tt-expired { color: #ef4444; }
	.tt-grade { font-weight: 600; }
</style>
```

- [ ] **Step 2: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/lib/components/analytics/OwnershipTreemap.svelte
git commit -m "feat(frontend): add OwnershipTreemap D3 component"
```

---

## Task 11: Frontend — DeploymentChart Component

**Files:**
- Create: `frontend/src/lib/components/analytics/DeploymentChart.svelte`

- [ ] **Step 1: Create DeploymentChart.svelte**

```svelte
<script lang="ts">
	import type { DeploymentGroup } from '$lib/api';
	import { gradeColor } from './analytics-types';

	interface Props {
		groups: DeploymentGroup[];
	}

	let { groups }: Props = $props();

	let maxCount = $derived(Math.max(...groups.map(g => g.cert_count), 1));

	let hoveredGroup: DeploymentGroup | null = $state(null);
</script>

<div class="deployment-chart">
	{#if groups.length === 0}
		<div class="empty-state">
			No deployment data available. Certificates discovered via passive or active scanning will appear here.
		</div>
	{:else}
		{#each groups.slice(0, 20) as group}
			<div
				class="bar-row"
				onpointerenter={() => hoveredGroup = group}
				onpointerleave={() => hoveredGroup = null}
			>
				<span class="bar-domain">{group.domain}</span>
				<div class="bar-track">
					<div
						class="bar-fill"
						style="width: {(group.cert_count / maxCount) * 100}%; background: {gradeColor(group.worst_grade)}"
					></div>
				</div>
				<span class="bar-count">{group.cert_count}</span>
				<span class="bar-ips">{group.unique_ips} IPs</span>
				<span class="bar-grade" style="color: {gradeColor(group.worst_grade)}">{group.worst_grade}</span>
			</div>
		{/each}

		{#if hoveredGroup}
			<div class="bar-detail">
				<span>{hoveredGroup.domain}</span>
				<span>{hoveredGroup.cert_count} certs</span>
				<span>{hoveredGroup.unique_ips} unique IPs</span>
				{#if hoveredGroup.expired_count > 0}
					<span class="detail-expired">{hoveredGroup.expired_count} expired</span>
				{/if}
				<span>Avg score: {hoveredGroup.avg_score.toFixed(0)}</span>
			</div>
		{/if}
	{/if}
</div>

<style>
	.deployment-chart {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}

	.bar-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.25rem 0;
		cursor: default;
	}

	.bar-row:hover { background: rgba(56, 189, 248, 0.03); border-radius: 4px; }

	.bar-domain {
		width: 200px;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.75rem;
		color: #e2e8f0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		flex-shrink: 0;
	}

	.bar-track {
		flex: 1;
		height: 18px;
		background: var(--cf-bg-tertiary, rgba(30, 41, 59, 0.5));
		border-radius: 3px;
		overflow: hidden;
	}

	.bar-fill {
		height: 100%;
		border-radius: 3px;
		opacity: 0.7;
		transition: width 0.3s ease;
	}

	.bar-count {
		width: 36px;
		text-align: right;
		font-size: 0.8rem;
		font-weight: 600;
		color: #cbd5e1;
		font-variant-numeric: tabular-nums;
		flex-shrink: 0;
	}

	.bar-ips {
		width: 48px;
		font-size: 0.7rem;
		color: #64748b;
		flex-shrink: 0;
	}

	.bar-grade {
		width: 24px;
		font-size: 0.75rem;
		font-weight: 700;
		flex-shrink: 0;
		text-align: center;
	}

	.empty-state {
		padding: 2rem;
		text-align: center;
		color: #64748b;
		font-size: 0.85rem;
	}

	.bar-detail {
		display: flex;
		gap: 1rem;
		padding: 0.5rem 0.75rem;
		background: rgba(56, 189, 248, 0.05);
		border-radius: 6px;
		font-size: 0.75rem;
		color: #94a3b8;
		margin-top: 0.25rem;
	}

	.detail-expired { color: #ef4444; }
</style>
```

- [ ] **Step 2: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/lib/components/analytics/DeploymentChart.svelte
git commit -m "feat(frontend): add DeploymentChart horizontal bar component"
```

---

## Task 12: Frontend — OwnershipTab Wrapper

**Files:**
- Create: `frontend/src/lib/components/analytics/OwnershipTab.svelte`

- [ ] **Step 1: Create OwnershipTab.svelte**

```svelte
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api } from '$lib/api';
	import type { OwnershipGroup, DeploymentGroup } from '$lib/api';
	import OwnershipTreemap from './OwnershipTreemap.svelte';
	import DeploymentChart from './DeploymentChart.svelte';

	let ownershipGroups: OwnershipGroup[] = $state([]);
	let deploymentGroups: DeploymentGroup[] = $state([]);
	let totalCerts = $state(0);
	let totalIssuers = $state(0);
	let totalOUs = $state(0);
	let totalObserved = $state(0);
	let totalDomains = $state(0);
	let loading = $state(true);
	let error: string | null = $state(null);

	onMount(async () => {
		try {
			const [ownership, deployment] = await Promise.all([
				api.getOwnership(),
				api.getDeployment(),
			]);
			ownershipGroups = ownership.groups;
			totalCerts = ownership.total_certs;
			totalIssuers = ownership.total_issuers;
			totalOUs = ownership.total_ous;
			deploymentGroups = deployment.groups;
			totalObserved = deployment.total_observed_certs;
			totalDomains = deployment.total_domains;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load ownership data';
		}
		loading = false;
	});

	function handleTreemapClick(issuerOrg: string, subjectOU: string) {
		const params = new URLSearchParams();
		params.set('issuer_cn', issuerOrg);
		if (subjectOU) params.set('subject_ou', subjectOU);
		goto(`/certificates?${params.toString()}`);
	}
</script>

<div class="ownership-tab">
	{#if loading}
		<div class="tab-loading">Loading ownership data...</div>
	{:else if error}
		<div class="tab-error">{error}</div>
	{:else}
		<section class="ownership-section">
			<div class="section-header">
				<h2>By Certificate Metadata</h2>
				<span class="section-meta">
					{totalIssuers} issuers &middot; {totalOUs} OUs &middot; {totalCerts.toLocaleString()} certs
				</span>
			</div>
			<OwnershipTreemap groups={ownershipGroups} onGroupClick={handleTreemapClick} />
		</section>

		<section class="ownership-section">
			<div class="section-header">
				<h2>By Deployment</h2>
				<span class="section-meta">
					{totalDomains} domains &middot; {totalObserved.toLocaleString()} observed certs
				</span>
			</div>
			<DeploymentChart groups={deploymentGroups} />
		</section>
	{/if}
</div>

<style>
	.ownership-tab {
		padding: 1.5rem;
		height: 100%;
		overflow-y: auto;
	}

	.ownership-section {
		margin-bottom: 2rem;
	}

	.section-header {
		display: flex;
		align-items: baseline;
		gap: 1rem;
		margin-bottom: 1rem;
	}

	.section-header h2 {
		margin: 0;
		font-size: 1.1rem;
		font-weight: 700;
		color: var(--cf-text-primary);
	}

	.section-meta {
		font-size: 0.8rem;
		color: var(--cf-text-muted);
	}

	.tab-loading, .tab-error {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 50vh;
		color: var(--cf-text-muted);
		font-size: 0.9rem;
	}

	.tab-error { color: var(--cf-risk-critical); }
</style>
```

- [ ] **Step 2: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/lib/components/analytics/OwnershipTab.svelte
git commit -m "feat(frontend): add OwnershipTab wrapper component"
```

---

## Task 13: Frontend — Analytics Page (Tab Shell)

**Files:**
- Replace: `frontend/src/routes/analytics/+page.svelte`

- [ ] **Step 1: Replace +page.svelte with the tabbed layout**

```svelte
<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import ChainFlowTab from '$lib/components/analytics/ChainFlowTab.svelte';
	import OwnershipTab from '$lib/components/analytics/OwnershipTab.svelte';

	const TABS = [
		{ id: 'chain-flow', label: 'Chain Flow' },
		{ id: 'ownership', label: 'Ownership' },
	] as const;

	type TabId = typeof TABS[number]['id'];

	let activeTab: TabId = $derived(
		(page.url.searchParams.get('tab') as TabId) || 'chain-flow'
	);

	function switchTab(tab: TabId) {
		const url = new URL(page.url);
		url.searchParams.set('tab', tab);
		goto(url.toString(), { replaceState: true, noScroll: true });
	}
</script>

<div class="analytics-page">
	<nav class="tab-bar">
		{#each TABS as tab}
			<button
				class="tab"
				class:active={activeTab === tab.id}
				onclick={() => switchTab(tab.id)}
			>
				{tab.label}
			</button>
		{/each}
	</nav>

	<div class="tab-content">
		{#if activeTab === 'chain-flow'}
			<ChainFlowTab />
		{:else if activeTab === 'ownership'}
			<OwnershipTab />
		{/if}
	</div>
</div>

<style>
	.analytics-page {
		display: flex;
		flex-direction: column;
		height: 100%;
		overflow: hidden;
	}

	.tab-bar {
		display: flex;
		gap: 0;
		border-bottom: 1px solid var(--cf-border);
		background: var(--cf-bg-secondary);
		flex-shrink: 0;
		padding: 0 1.5rem;
	}

	.tab {
		padding: 0.75rem 1.25rem;
		font-size: 0.85rem;
		font-weight: 500;
		color: var(--cf-text-secondary);
		background: none;
		border: none;
		border-bottom: 2px solid transparent;
		cursor: pointer;
		transition: all 0.15s;
	}

	.tab:hover {
		color: var(--cf-text-primary);
	}

	.tab.active {
		color: var(--cf-accent);
		border-bottom-color: var(--cf-accent);
	}

	.tab-content {
		flex: 1;
		overflow: hidden;
	}
</style>
```

- [ ] **Step 2: Verify the full frontend compiles**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check`
Expected: No new errors.

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/routes/analytics/+page.svelte
git commit -m "feat(frontend): replace analytics page with tabbed chain flow + ownership"
```

---

## Task 14: Integration Verification

**Files:** None (verification only)

- [ ] **Step 1: Verify Go backend compiles**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: Clean compile.

- [ ] **Step 2: Verify frontend compiles**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check`
Expected: No new errors (only pre-existing upload page errors).

- [ ] **Step 3: Verify new API endpoints respond**

```bash
curl -s http://localhost:8443/api/v1/stats/chain-flow | python3 -m json.tool | head -20
curl -s http://localhost:8443/api/v1/stats/ownership | python3 -m json.tool | head -20
curl -s http://localhost:8443/api/v1/stats/deployment | python3 -m json.tool | head -20
```

Expected: JSON responses with `nodes`/`links`, `groups`, and `groups` arrays respectively.

- [ ] **Step 4: Final commit if needed**

```bash
cd /Users/Erik/projects/cipherflag && git status
```

If any missed files, stage and commit:

```bash
git commit -m "feat: complete analytics chain flow and ownership implementation"
```
