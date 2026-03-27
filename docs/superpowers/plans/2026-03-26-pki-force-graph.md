# PKI Force-Directed Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `/pki` tree view with a D3-force interactive graph that supports explore, search, and blast radius modes — backed by server-side aggregation for enterprise scale.

**Architecture:** Three new backend store methods + two new API endpoints + one modified endpoint feed a D3-force SVG graph on the frontend. The graph starts with CA-only nodes (aggregated), loads leaf children on demand via API calls, and supports blast radius subgraph queries.

**Tech Stack:** Go (chi router, pgx/PostgreSQL), SvelteKit 5 with Svelte runes, D3 (d3-force, d3-zoom, d3-selection, d3-transition), TypeScript.

**Spec:** `docs/superpowers/specs/2026-03-26-pki-force-graph-design.md`

---

## File Map

### Backend — New/Modified

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/store/store.go` | Modify | Add 3 new methods to `CertStore` interface + new response types |
| `internal/store/postgres.go` | Modify | Implement 3 new store methods |
| `internal/model/chain.go` | Modify | Add aggregated graph node/edge/response types |
| `internal/analysis/landscape.go` | Create | Aggregated landscape builder (separate from existing chain.go) |
| `internal/api/handler/graph.go` | Modify | Add `AggregatedLandscape`, `CAChildren`, `BlastRadius` handlers |
| `internal/api/server.go` | Modify | Register 2 new routes |

### Frontend — New/Modified

| File | Action | Responsibility |
|------|--------|----------------|
| `frontend/src/lib/api.ts` | Modify | Add new types + API methods |
| `frontend/src/lib/components/graph/graph-types.ts` | Create | TypeScript types for D3 graph nodes, edges, state |
| `frontend/src/lib/components/graph/graph-simulation.ts` | Create | D3 force simulation setup, expand/collapse, blast radius |
| `frontend/src/lib/components/graph/ForceGraph.svelte` | Create | SVG rendering, pan/zoom, node/edge drawing |
| `frontend/src/lib/components/graph/GraphTooltip.svelte` | Create | Hover tooltip |
| `frontend/src/lib/components/graph/GraphToolbar.svelte` | Create | Search, filters, zoom controls |
| `frontend/src/lib/components/graph/GraphLegend.svelte` | Create | Bottom-left legend |
| `frontend/src/routes/pki/+page.svelte` | Replace | Page shell, state management, compose components |

---

## Task 1: Backend — Aggregated Graph Types

**Files:**
- Modify: `internal/model/chain.go` (append after existing types)
- Modify: `internal/store/store.go` (add types + interface methods)

- [ ] **Step 1: Add aggregated graph types to model/chain.go**

Append these types after the existing `GraphResponse` struct:

```go
// AggregatedGraphNode represents a CA with aggregate stats for the landscape view.
type AggregatedGraphNode struct {
	Fingerprint      string  `json:"fingerprint"`
	CommonName       string  `json:"common_name"`
	Organization     string  `json:"organization"`
	NodeType         string  `json:"type"`                // "root" or "intermediate"
	CertCount        int     `json:"cert_count"`
	WorstGrade       string  `json:"worst_grade"`
	AvgScore         float64 `json:"avg_score"`
	ExpiredCount     int     `json:"expired_count"`
	Expiring30dCount int     `json:"expiring_30d_count"`
	KeyAlgorithm     string  `json:"key_algorithm"`
	KeySizeBits      int     `json:"key_size_bits"`
}

// AggregatedGraphEdge represents a parent→child CA relationship.
type AggregatedGraphEdge struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	ChildGrade string `json:"child_grade"`
}

// AggregatedLandscapeResponse is the API response for the aggregated landscape.
type AggregatedLandscapeResponse struct {
	Nodes []AggregatedGraphNode `json:"nodes"`
	Edges []AggregatedGraphEdge `json:"edges"`
}

// CAChildrenResponse is the API response for a CA's direct children.
type CAChildrenResponse struct {
	ParentFingerprint string                `json:"parent_fingerprint"`
	Nodes             []AggregatedGraphNode `json:"nodes"`
	Edges             []AggregatedGraphEdge `json:"edges"`
	Total             int                   `json:"total"`
	HasMore           bool                  `json:"has_more"`
}

// BlastRadiusSummary holds aggregate stats for a blast radius query.
type BlastRadiusSummary struct {
	TotalCerts    int `json:"total_certs"`
	Expired       int `json:"expired"`
	Expiring30d   int `json:"expiring_30d"`
	GradeF        int `json:"grade_f"`
	Intermediates int `json:"intermediates"`
}

// BlastRadiusResponse is the API response for a CA's blast radius.
type BlastRadiusResponse struct {
	RootFingerprint string                `json:"root_fingerprint"`
	Nodes           []AggregatedGraphNode `json:"nodes"`
	Edges           []AggregatedGraphEdge `json:"edges"`
	Summary         BlastRadiusSummary    `json:"summary"`
	Truncated       bool                  `json:"truncated"`
}
```

- [ ] **Step 2: Add store interface methods and types to store.go**

Add these 3 methods to the `CertStore` interface, in the `// Graph data` section after `GetAllCertificatesForGraph`:

```go
	GetAggregatedLandscape(ctx context.Context) (*model.AggregatedLandscapeResponse, error)
	GetCAChildren(ctx context.Context, fingerprint string, limit, offset int) (*model.CAChildrenResponse, error)
	GetBlastRadius(ctx context.Context, fingerprint string, limit int) (*model.BlastRadiusResponse, error)
```

- [ ] **Step 3: Verify it compiles**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: Compile error — `PostgresStore` does not implement `CertStore` (missing 3 methods). This confirms the interface change is correct. We'll implement the methods in Task 2.

- [ ] **Step 4: Commit**

```bash
git add internal/model/chain.go internal/store/store.go
git commit -m "feat(model): add aggregated graph types for force-directed landscape"
```

---

## Task 2: Backend — Store Implementation (GetAggregatedLandscape)

**Files:**
- Modify: `internal/store/postgres.go` (add method after `GetAllCertificatesForGraph`)

- [ ] **Step 1: Implement GetAggregatedLandscape**

Add this method to `PostgresStore` after the `GetAllCertificatesForGraph` method (around line 371):

```go
func (s *PostgresStore) GetAggregatedLandscape(ctx context.Context) (*model.AggregatedLandscapeResponse, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			ca.fingerprint_sha256,
			ca.subject_cn,
			ca.subject_org,
			ca.issuer_cn,
			ca.key_algorithm,
			ca.key_size_bits,
			CASE WHEN ca.subject_cn = ca.issuer_cn OR ca.issuer_cn = '' THEN 'root' ELSE 'intermediate' END as node_type,
			COALESCE(h.grade, '?') as ca_grade,
			(SELECT COUNT(*) FROM certificates ch WHERE ch.issuer_cn = ca.subject_cn AND ch.fingerprint_sha256 != ca.fingerprint_sha256) as cert_count,
			COALESCE((
				SELECT MIN(h2.grade) FROM certificates ch2
				JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
				WHERE ch2.issuer_cn = ca.subject_cn AND ch2.fingerprint_sha256 != ca.fingerprint_sha256
			), COALESCE(h.grade, '?')) as worst_grade,
			COALESCE((
				SELECT AVG(h2.score)::numeric(5,1) FROM certificates ch2
				JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
				WHERE ch2.issuer_cn = ca.subject_cn AND ch2.fingerprint_sha256 != ca.fingerprint_sha256
			), COALESCE(h.score, 0)) as avg_score,
			(SELECT COUNT(*) FROM certificates ch3 WHERE ch3.issuer_cn = ca.subject_cn AND ch3.not_after < NOW() AND ch3.fingerprint_sha256 != ca.fingerprint_sha256) as expired_count,
			(SELECT COUNT(*) FROM certificates ch4 WHERE ch4.issuer_cn = ca.subject_cn AND ch4.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days' AND ch4.fingerprint_sha256 != ca.fingerprint_sha256) as expiring_30d_count
		FROM certificates ca
		LEFT JOIN health_reports h ON ca.fingerprint_sha256 = h.cert_fingerprint
		WHERE ca.is_ca = true
		ORDER BY cert_count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.AggregatedLandscapeResponse{
		Nodes: []model.AggregatedGraphNode{},
		Edges: []model.AggregatedGraphEdge{},
	}

	// Track CAs by subject_cn for edge building
	caSubjects := map[string]bool{}

	type caRow struct {
		node     model.AggregatedGraphNode
		issuerCN string
	}
	var cas []caRow

	for rows.Next() {
		var r caRow
		var issuerCN string
		if err := rows.Scan(
			&r.node.Fingerprint, &r.node.CommonName, &r.node.Organization,
			&issuerCN, &r.node.KeyAlgorithm, &r.node.KeySizeBits,
			&r.node.NodeType, new(string), // ca_grade (used in subqueries, not directly)
			&r.node.CertCount, &r.node.WorstGrade, &r.node.AvgScore,
			&r.node.ExpiredCount, &r.node.Expiring30dCount,
		); err != nil {
			return nil, err
		}
		r.issuerCN = issuerCN
		cas = append(cas, r)
		caSubjects[r.node.CommonName] = true
	}

	for _, ca := range cas {
		resp.Nodes = append(resp.Nodes, ca.node)

		// Create edge: this CA → its issuer CA (if issuer is in our CA set and not self)
		if ca.node.NodeType == "intermediate" && caSubjects[ca.issuerCN] && ca.issuerCN != ca.node.CommonName {
			// Find issuer fingerprint
			for _, parent := range cas {
				if parent.node.CommonName == ca.issuerCN {
					resp.Edges = append(resp.Edges, model.AggregatedGraphEdge{
						Source: parent.node.Fingerprint,
						Target: ca.node.Fingerprint,
						ChildGrade: ca.node.WorstGrade,
					})
					break
				}
			}
		}
	}

	return resp, nil
}
```

- [ ] **Step 2: Verify the query compiles**

Run: `cd /Users/Erik/projects/cipherflag && go build ./internal/store/...`
Expected: Still fails (2 missing methods), but no syntax errors in this method.

- [ ] **Step 3: Commit**

```bash
git add internal/store/postgres.go
git commit -m "feat(store): implement GetAggregatedLandscape for CA-only graph"
```

---

## Task 3: Backend — Store Implementation (GetCAChildren)

**Files:**
- Modify: `internal/store/postgres.go`

- [ ] **Step 1: Implement GetCAChildren**

Add after `GetAggregatedLandscape`:

```go
func (s *PostgresStore) GetCAChildren(ctx context.Context, fingerprint string, limit, offset int) (*model.CAChildrenResponse, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Get the parent CA's subject_cn
	var parentCN string
	err := s.pool.QueryRow(ctx, "SELECT subject_cn FROM certificates WHERE fingerprint_sha256 = $1", fingerprint).Scan(&parentCN)
	if err != nil {
		return nil, fmt.Errorf("parent CA not found: %w", err)
	}

	// Count total children
	var total int
	s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM certificates
		WHERE issuer_cn = $1 AND fingerprint_sha256 != $2
	`, parentCN, fingerprint).Scan(&total)

	// Get children — separate CAs (returned as aggregated) from leaves (returned individually)
	rows, err := s.pool.Query(ctx, `
		SELECT
			c.fingerprint_sha256,
			c.subject_cn,
			c.subject_org,
			c.key_algorithm,
			c.key_size_bits,
			c.is_ca,
			c.not_after,
			COALESCE(h.grade, '?') as grade,
			COALESCE(h.score, 0) as score,
			CASE WHEN c.is_ca THEN
				(SELECT COUNT(*) FROM certificates ch WHERE ch.issuer_cn = c.subject_cn AND ch.fingerprint_sha256 != c.fingerprint_sha256)
			ELSE 0 END as child_count,
			CASE WHEN c.is_ca THEN COALESCE((
				SELECT MIN(h2.grade) FROM certificates ch2
				JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
				WHERE ch2.issuer_cn = c.subject_cn AND ch2.fingerprint_sha256 != c.fingerprint_sha256
			), COALESCE(h.grade, '?')) ELSE COALESCE(h.grade, '?') END as worst_grade,
			CASE WHEN c.is_ca THEN COALESCE((
				SELECT AVG(h2.score)::numeric(5,1) FROM certificates ch2
				JOIN health_reports h2 ON ch2.fingerprint_sha256 = h2.cert_fingerprint
				WHERE ch2.issuer_cn = c.subject_cn AND ch2.fingerprint_sha256 != c.fingerprint_sha256
			), COALESCE(h.score, 0)) ELSE COALESCE(h.score, 0) END as avg_score,
			CASE WHEN c.is_ca THEN
				(SELECT COUNT(*) FROM certificates ch3 WHERE ch3.issuer_cn = c.subject_cn AND ch3.not_after < NOW() AND ch3.fingerprint_sha256 != c.fingerprint_sha256)
			ELSE CASE WHEN c.not_after < NOW() THEN 1 ELSE 0 END END as expired_count,
			CASE WHEN c.is_ca THEN
				(SELECT COUNT(*) FROM certificates ch4 WHERE ch4.issuer_cn = c.subject_cn AND ch4.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days' AND ch4.fingerprint_sha256 != c.fingerprint_sha256)
			ELSE CASE WHEN c.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days' THEN 1 ELSE 0 END END as expiring_30d_count
		FROM certificates c
		LEFT JOIN health_reports h ON c.fingerprint_sha256 = h.cert_fingerprint
		WHERE c.issuer_cn = $1 AND c.fingerprint_sha256 != $2
		ORDER BY c.is_ca DESC, c.subject_cn ASC
		LIMIT $3 OFFSET $4
	`, parentCN, fingerprint, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.CAChildrenResponse{
		ParentFingerprint: fingerprint,
		Nodes:             []model.AggregatedGraphNode{},
		Edges:             []model.AggregatedGraphEdge{},
		Total:             total,
		HasMore:           offset+limit < total,
	}

	for rows.Next() {
		var fp, cn, org, keyAlg, grade, worstGrade string
		var keyBits, score, childCount, expiredCount, expiring30d int
		var isCA bool
		var notAfter time.Time
		var avgScore float64

		if err := rows.Scan(
			&fp, &cn, &org, &keyAlg, &keyBits, &isCA, &notAfter,
			&grade, &score, &childCount, &worstGrade, &avgScore,
			&expiredCount, &expiring30d,
		); err != nil {
			return nil, err
		}

		nodeType := "leaf"
		if isCA {
			nodeType = "intermediate"
		}

		node := model.AggregatedGraphNode{
			Fingerprint:      fp,
			CommonName:       cn,
			Organization:     org,
			NodeType:         nodeType,
			CertCount:        childCount,
			WorstGrade:       worstGrade,
			AvgScore:         avgScore,
			ExpiredCount:     expiredCount,
			Expiring30dCount: expiring30d,
			KeyAlgorithm:     keyAlg,
			KeySizeBits:      keyBits,
		}
		resp.Nodes = append(resp.Nodes, node)

		// Edge from parent to this child
		resp.Edges = append(resp.Edges, model.AggregatedGraphEdge{
			Source:     fingerprint,
			Target:     fp,
			ChildGrade: worstGrade,
		})
	}

	return resp, nil
}
```

- [ ] **Step 2: Verify compilation**

Run: `cd /Users/Erik/projects/cipherflag && go build ./internal/store/...`
Expected: Still fails (1 missing method: `GetBlastRadius`).

- [ ] **Step 3: Commit**

```bash
git add internal/store/postgres.go
git commit -m "feat(store): implement GetCAChildren for on-demand child loading"
```

---

## Task 4: Backend — Store Implementation (GetBlastRadius)

**Files:**
- Modify: `internal/store/postgres.go`

- [ ] **Step 1: Implement GetBlastRadius**

Add after `GetCAChildren`:

```go
func (s *PostgresStore) GetBlastRadius(ctx context.Context, fingerprint string, limit int) (*model.BlastRadiusResponse, error) {
	if limit <= 0 {
		limit = 500
	}

	// Recursive CTE: find all descendants of this CA by walking issuer_cn chains
	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE descendants AS (
			-- Base: direct children of the target CA
			SELECT c.fingerprint_sha256, c.subject_cn, c.subject_org,
				c.issuer_cn, c.key_algorithm, c.key_size_bits, c.is_ca, c.not_after,
				1 as depth
			FROM certificates c
			JOIN certificates parent ON parent.fingerprint_sha256 = $1 AND c.issuer_cn = parent.subject_cn
			WHERE c.fingerprint_sha256 != $1

			UNION

			-- Recursive: children of children
			SELECT c.fingerprint_sha256, c.subject_cn, c.subject_org,
				c.issuer_cn, c.key_algorithm, c.key_size_bits, c.is_ca, c.not_after,
				d.depth + 1
			FROM certificates c
			JOIN descendants d ON c.issuer_cn = d.subject_cn AND d.is_ca = true
			WHERE c.fingerprint_sha256 != d.fingerprint_sha256
			AND d.depth < 10
		)
		SELECT DISTINCT ON (d.fingerprint_sha256)
			d.fingerprint_sha256, d.subject_cn, d.subject_org,
			d.issuer_cn, d.key_algorithm, d.key_size_bits, d.is_ca, d.not_after,
			COALESCE(h.grade, '?') as grade,
			COALESCE(h.score, 0) as score
		FROM descendants d
		LEFT JOIN health_reports h ON d.fingerprint_sha256 = h.cert_fingerprint
		ORDER BY d.fingerprint_sha256, d.depth
		LIMIT $2
	`, fingerprint, limit+1) // +1 to detect truncation
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resp := &model.BlastRadiusResponse{
		RootFingerprint: fingerprint,
		Nodes:           []model.AggregatedGraphNode{},
		Edges:           []model.AggregatedGraphEdge{},
	}

	// Track CA subject_cn → fingerprint for edge building
	caFPBySubject := map[string]string{}

	// Also index the root CA
	var rootCN string
	s.pool.QueryRow(ctx, "SELECT subject_cn FROM certificates WHERE fingerprint_sha256 = $1", fingerprint).Scan(&rootCN)
	caFPBySubject[rootCN] = fingerprint

	type row struct {
		fp, cn, org, issuerCN, keyAlg, grade string
		keyBits, score                        int
		isCA                                  bool
		notAfter                              time.Time
	}
	var allRows []row

	for rows.Next() {
		var r row
		if err := rows.Scan(
			&r.fp, &r.cn, &r.org, &r.issuerCN, &r.keyAlg, &r.keyBits,
			&r.isCA, &r.notAfter, &r.grade, &r.score,
		); err != nil {
			return nil, err
		}
		allRows = append(allRows, r)
		if r.isCA {
			caFPBySubject[r.cn] = r.fp
		}
	}

	// Build summary from ALL rows (before truncation) so counts are accurate
	summary := model.BlastRadiusSummary{}
	for _, r := range allRows {
		summary.TotalCerts++
		if r.notAfter.Before(time.Now()) {
			summary.Expired++
		} else if r.notAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
			summary.Expiring30d++
		}
		if r.grade == "F" {
			summary.GradeF++
		}
		if r.isCA {
			summary.Intermediates++
		}
	}
	resp.Summary = summary

	// Truncate after computing summary
	if len(allRows) > limit {
		resp.Truncated = true
		allRows = allRows[:limit]
	}

	// Build nodes + edges
	for _, r := range allRows {
		nodeType := "leaf"
		if r.isCA {
			nodeType = "intermediate"
		}

		resp.Nodes = append(resp.Nodes, model.AggregatedGraphNode{
			Fingerprint:  r.fp,
			CommonName:   r.cn,
			Organization: r.org,
			NodeType:     nodeType,
			WorstGrade:   r.grade,
			AvgScore:     float64(r.score),
			KeyAlgorithm: r.keyAlg,
			KeySizeBits:  r.keyBits,
			ExpiredCount: func() int { if r.notAfter.Before(time.Now()) { return 1 }; return 0 }(),
		})

		// Edge from issuer → this node
		if issuerFP, ok := caFPBySubject[r.issuerCN]; ok {
			resp.Edges = append(resp.Edges, model.AggregatedGraphEdge{
				Source:     issuerFP,
				Target:     r.fp,
				ChildGrade: r.grade,
			})
		}
	}

	return resp, nil
}
```

- [ ] **Step 2: Verify full compilation**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: PASS — all interface methods now implemented. No compile errors.

- [ ] **Step 3: Commit**

```bash
git add internal/store/postgres.go
git commit -m "feat(store): implement GetBlastRadius with recursive CTE"
```

---

## Task 5: Backend — API Handlers & Routes

**Files:**
- Modify: `internal/api/handler/graph.go`
- Modify: `internal/api/server.go`

- [ ] **Step 1: Add three new handlers to graph.go**

Add these methods after the existing `ChainGraph` method:

```go
// AggregatedLandscape returns CAs-only with aggregate stats for the force graph.
func (h *GraphHandler) AggregatedLandscape(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetAggregatedLandscape(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// CAChildren returns the direct children of a CA node.
func (h *GraphHandler) CAChildren(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")

	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	resp, err := h.store.GetCAChildren(r.Context(), fp, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// BlastRadius returns the full downstream subgraph of a CA.
func (h *GraphHandler) BlastRadius(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")

	resp, err := h.store.GetBlastRadius(r.Context(), fp, 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
```

Also add `"strconv"` to the import block in graph.go.

- [ ] **Step 2: Register the new routes in server.go**

In `internal/api/server.go`, add these lines after the existing graph routes (after line 49):

```go
		r.Get("/graph/landscape/aggregated", graphH.AggregatedLandscape)
		r.Get("/graph/ca/{fingerprint}/children", graphH.CAChildren)
		r.Get("/graph/ca/{fingerprint}/blast-radius", graphH.BlastRadius)
```

- [ ] **Step 3: Verify full compilation**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: PASS — clean compile.

- [ ] **Step 4: Commit**

```bash
git add internal/api/handler/graph.go internal/api/server.go
git commit -m "feat(api): add aggregated landscape, CA children, and blast radius endpoints"
```

---

## Task 6: Frontend — Install D3 Packages & Add API Types

**Files:**
- Modify: `frontend/package.json` (via npm install)
- Modify: `frontend/src/lib/api.ts`

- [ ] **Step 1: Install D3 packages**

```bash
cd /Users/Erik/projects/cipherflag/frontend && npm install d3-force d3-zoom d3-selection d3-transition d3-drag && npm install -D @types/d3-force @types/d3-zoom @types/d3-selection @types/d3-transition @types/d3-drag
```

- [ ] **Step 2: Add new types and API methods to api.ts**

Add these types before the `export const api = {` line:

```typescript
export interface AggregatedGraphNode {
	fingerprint: string;
	common_name: string;
	organization: string;
	type: 'root' | 'intermediate' | 'leaf';
	cert_count: number;
	worst_grade: string;
	avg_score: number;
	expired_count: number;
	expiring_30d_count: number;
	key_algorithm: string;
	key_size_bits: number;
}

export interface AggregatedGraphEdge {
	source: string;
	target: string;
	child_grade: string;
}

export interface AggregatedLandscapeResponse {
	nodes: AggregatedGraphNode[];
	edges: AggregatedGraphEdge[];
}

export interface CAChildrenResponse {
	parent_fingerprint: string;
	nodes: AggregatedGraphNode[];
	edges: AggregatedGraphEdge[];
	total: number;
	has_more: boolean;
}

export interface BlastRadiusSummary {
	total_certs: number;
	expired: number;
	expiring_30d: number;
	grade_f: number;
	intermediates: number;
}

export interface BlastRadiusResponse {
	root_fingerprint: string;
	nodes: AggregatedGraphNode[];
	edges: AggregatedGraphEdge[];
	summary: BlastRadiusSummary;
	truncated: boolean;
}
```

Add these methods inside the `api` object:

```typescript
	getAggregatedLandscape: () => fetchJSON<AggregatedLandscapeResponse>('/graph/landscape/aggregated'),
	getCAChildren: (fp: string, limit = 100, offset = 0) =>
		fetchJSON<CAChildrenResponse>(`/graph/ca/${fp}/children?limit=${limit}&offset=${offset}`),
	getBlastRadius: (fp: string) => fetchJSON<BlastRadiusResponse>(`/graph/ca/${fp}/blast-radius`),
```

- [ ] **Step 3: Verify frontend compiles**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check`
Expected: No type errors.

- [ ] **Step 4: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/package.json frontend/package-lock.json frontend/src/lib/api.ts
git commit -m "feat(frontend): add D3 deps and aggregated graph API types"
```

---

## Task 7: Frontend — Graph Types & Simulation Engine

**Files:**
- Create: `frontend/src/lib/components/graph/graph-types.ts`
- Create: `frontend/src/lib/components/graph/graph-simulation.ts`

- [ ] **Step 1: Create graph-types.ts**

```bash
mkdir -p /Users/Erik/projects/cipherflag/frontend/src/lib/components/graph
```

```typescript
// graph-types.ts — D3-compatible types for the force-directed graph

import type { SimulationNodeDatum, SimulationLinkDatum } from 'd3-force';

export interface ForceNode extends SimulationNodeDatum {
	id: string;
	label: string;
	type: 'root' | 'intermediate' | 'leaf';
	grade: string;
	certCount: number;
	avgScore: number;
	expiredCount: number;
	expiring30dCount: number;
	keyAlgorithm: string;
	keySizeBits: number;
	organization: string;
	isExpanded: boolean;
	// Computed visual properties
	radius: number;
	color: string;
	fillOpacity: number;
	pulseRate: number;
}

export interface ForceEdge extends SimulationLinkDatum<ForceNode> {
	id: string;
	sourceId: string;
	targetId: string;
	childGrade: string;
	color: string;
}

export type GraphMode = 'explore' | 'search' | 'blast-radius';

export interface GraphState {
	nodes: ForceNode[];
	edges: ForceEdge[];
	expandedCAs: Set<string>;
	mode: GraphMode;
	searchQuery: string;
	blastRadiusTarget: string | null;
	blastRadiusNodes: Set<string>;
	hoveredNode: ForceNode | null;
	selectedGrades: Set<string>;
	showExpiredOnly: boolean;
}

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

export function nodeRadius(node: ForceNode): number {
	if (node.type === 'root') return 24 + Math.min(node.certCount / 200, 8);
	if (node.type === 'intermediate') return 14 + Math.min(node.certCount / 100, 6);
	return 6;
}

export function nodePulseRate(node: ForceNode): number {
	if (node.grade === 'F') return 2.5;
	if (node.expiredCount > 0) return 2.0;
	if (node.expiring30dCount > 0) return 1.0;
	return 0;
}
```

- [ ] **Step 2: Create graph-simulation.ts**

```typescript
// graph-simulation.ts — D3 force simulation management

import { forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide, type Simulation } from 'd3-force';
import type { ForceNode, ForceEdge } from './graph-types';
import type { AggregatedGraphNode, AggregatedGraphEdge } from '$lib/api';
import { gradeColor, nodeRadius, nodePulseRate } from './graph-types';

export function createSimulation(
	width: number,
	height: number,
	onTick: () => void,
): Simulation<ForceNode, ForceEdge> {
	return forceSimulation<ForceNode>()
		.force('charge', forceManyBody<ForceNode>().strength((d) => {
			if (d.type === 'root') return -300;
			if (d.type === 'intermediate') return -150;
			return -30;
		}))
		.force('link', forceLink<ForceNode, ForceEdge>().id(d => d.id).strength((link) => {
			const target = link.target as ForceNode;
			if (target.type === 'intermediate') return 0.7;
			return 0.3;
		}).distance((link) => {
			const target = link.target as ForceNode;
			if (target.type === 'intermediate') return 120;
			return 60;
		}))
		.force('center', forceCenter(width / 2, height / 2).strength(0.05))
		.force('collision', forceCollide<ForceNode>().radius(d => d.radius + 4))
		.alphaDecay(0.02)
		.on('tick', onTick);
}

export function apiNodeToForceNode(apiNode: AggregatedGraphNode): ForceNode {
	const node: ForceNode = {
		id: apiNode.fingerprint,
		label: apiNode.common_name || apiNode.fingerprint.slice(0, 12),
		type: apiNode.type as ForceNode['type'],
		grade: apiNode.worst_grade,
		certCount: apiNode.cert_count,
		avgScore: apiNode.avg_score,
		expiredCount: apiNode.expired_count,
		expiring30dCount: apiNode.expiring_30d_count,
		keyAlgorithm: apiNode.key_algorithm,
		keySizeBits: apiNode.key_size_bits,
		organization: apiNode.organization,
		isExpanded: false,
		radius: 0,
		color: '',
		fillOpacity: 0.12,
		pulseRate: 0,
	};
	node.radius = nodeRadius(node);
	node.color = gradeColor(node.grade);
	node.pulseRate = nodePulseRate(node);
	return node;
}

export function apiEdgeToForceEdge(apiEdge: AggregatedGraphEdge, index: number): ForceEdge {
	return {
		id: `e-${index}`,
		source: apiEdge.source,
		target: apiEdge.target,
		sourceId: apiEdge.source,
		targetId: apiEdge.target,
		childGrade: apiEdge.child_grade,
		color: gradeColor(apiEdge.child_grade),
	};
}

export function updateSimulation(
	sim: Simulation<ForceNode, ForceEdge>,
	nodes: ForceNode[],
	edges: ForceEdge[],
): void {
	sim.nodes(nodes);
	const linkForce = sim.force('link') as ReturnType<typeof forceLink<ForceNode, ForceEdge>>;
	if (linkForce) {
		linkForce.links(edges);
	}
	sim.alpha(0.8).restart();
}
```

- [ ] **Step 3: Verify types compile**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check`
Expected: No type errors.

- [ ] **Step 4: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/lib/components/graph/
git commit -m "feat(frontend): add D3 graph types and force simulation engine"
```

---

## Task 8: Frontend — ForceGraph Component (SVG Rendering)

**Files:**
- Create: `frontend/src/lib/components/graph/ForceGraph.svelte`

- [ ] **Step 1: Create ForceGraph.svelte**

```svelte
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { zoom, zoomIdentity, type ZoomBehavior } from 'd3-zoom';
	import { select } from 'd3-selection';
	import { drag } from 'd3-drag';
	import type { Simulation } from 'd3-force';
	import type { ForceNode, ForceEdge } from './graph-types';
	import { createSimulation, updateSimulation } from './graph-simulation';
	import 'd3-transition';

	interface Props {
		nodes: ForceNode[];
		edges: ForceEdge[];
		hoveredNode: ForceNode | null;
		dimmedNodes: Set<string>;
		onNodeClick: (node: ForceNode) => void;
		onNodeHover: (node: ForceNode | null, x: number, y: number) => void;
		onNodeRightClick: (node: ForceNode, x: number, y: number) => void;
		onBackgroundClick: () => void;
		onZoomChange: (scale: number) => void;
	}

	let {
		nodes = $bindable(),
		edges = $bindable(),
		hoveredNode,
		dimmedNodes,
		onNodeClick,
		onNodeHover,
		onNodeRightClick,
		onBackgroundClick,
		onZoomChange,
	}: Props = $props();

	let svgEl: SVGSVGElement;
	let width = $state(0);
	let height = $state(0);
	let transform = $state({ x: 0, y: 0, k: 1 });
	let sim: Simulation<ForceNode, ForceEdge>;
	let zoomBehavior: ZoomBehavior<SVGSVGElement, unknown>;
	let resizeObserver: ResizeObserver;
	let animFrame: number;

	onMount(() => {
		const rect = svgEl.parentElement!.getBoundingClientRect();
		width = rect.width;
		height = rect.height;

		sim = createSimulation(width, height, () => {
			// Request animation frame for smooth rendering
			if (animFrame) cancelAnimationFrame(animFrame);
			animFrame = requestAnimationFrame(() => {
				nodes = [...nodes];
				edges = [...edges];
			});
		});

		zoomBehavior = zoom<SVGSVGElement, unknown>()
			.scaleExtent([0.1, 8])
			.on('zoom', (event) => {
				transform = event.transform;
				onZoomChange(event.transform.k);
			});

		select(svgEl).call(zoomBehavior);

		// Click on background
		select(svgEl).on('click', (event) => {
			if (event.target === svgEl) onBackgroundClick();
		});

		resizeObserver = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) {
				width = entry.contentRect.width;
				height = entry.contentRect.height;
			}
		});
		resizeObserver.observe(svgEl.parentElement!);

		updateSimulation(sim, nodes, edges);

		// Setup drag behavior
		setupDrag();
	});

	onDestroy(() => {
		if (sim) sim.stop();
		if (resizeObserver) resizeObserver.disconnect();
		if (animFrame) cancelAnimationFrame(animFrame);
	});

	function setupDrag() {
		const dragBehavior = drag<SVGCircleElement, ForceNode>()
			.on('start', (event, d) => {
				if (!event.active) sim.alphaTarget(0.3).restart();
				d.fx = d.x;
				d.fy = d.y;
			})
			.on('drag', (event, d) => {
				d.fx = event.x;
				d.fy = event.y;
			})
			.on('end', (event, d) => {
				if (!event.active) sim.alphaTarget(0);
				d.fx = null;
				d.fy = null;
			});

		// Apply to all node circles
		select(svgEl).selectAll<SVGCircleElement, ForceNode>('.graph-node').call(dragBehavior);
	}

	$effect(() => {
		if (sim && nodes && edges) {
			updateSimulation(sim, nodes, edges);
			// Re-apply drag after node changes
			requestAnimationFrame(setupDrag);
		}
	});

	export function zoomIn() {
		select(svgEl).transition().duration(300).call(zoomBehavior.scaleBy, 1.4);
	}

	export function zoomOut() {
		select(svgEl).transition().duration(300).call(zoomBehavior.scaleBy, 0.7);
	}

	export function zoomReset() {
		select(svgEl).transition().duration(500).call(zoomBehavior.transform, zoomIdentity);
	}

	function nodeOpacity(node: ForceNode): number {
		if (dimmedNodes.size === 0) return 1;
		return dimmedNodes.has(node.id) ? 0.1 : 1;
	}

	function edgeOpacity(edge: ForceEdge): number {
		if (dimmedNodes.size === 0) return 0.25;
		const src = typeof edge.source === 'object' ? edge.source.id : edge.source;
		const tgt = typeof edge.target === 'object' ? edge.target.id : edge.target;
		if (dimmedNodes.has(src) || dimmedNodes.has(tgt)) return 0.03;
		return 0.25;
	}

	function edgeX1(edge: ForceEdge): number {
		return typeof edge.source === 'object' ? (edge.source.x ?? 0) : 0;
	}
	function edgeY1(edge: ForceEdge): number {
		return typeof edge.source === 'object' ? (edge.source.y ?? 0) : 0;
	}
	function edgeX2(edge: ForceEdge): number {
		return typeof edge.target === 'object' ? (edge.target.x ?? 0) : 0;
	}
	function edgeY2(edge: ForceEdge): number {
		return typeof edge.target === 'object' ? (edge.target.y ?? 0) : 0;
	}
</script>

<svg bind:this={svgEl} class="force-graph-svg" {width} {height}>
	<g transform="translate({transform.x},{transform.y}) scale({transform.k})">
		<!-- Edges -->
		{#each edges as edge (edge.id)}
			<line
				class="graph-edge"
				x1={edgeX1(edge)}
				y1={edgeY1(edge)}
				x2={edgeX2(edge)}
				y2={edgeY2(edge)}
				stroke={edge.color}
				stroke-opacity={edgeOpacity(edge)}
				stroke-width={1.5}
			/>
		{/each}

		<!-- Nodes -->
		{#each nodes as node (node.id)}
			<g
				class="graph-node-group"
				transform="translate({node.x ?? 0},{node.y ?? 0})"
				opacity={nodeOpacity(node)}
				role="button"
				tabindex="-1"
				onclick={() => onNodeClick(node)}
				oncontextmenu={(e) => { e.preventDefault(); onNodeRightClick(node, e.clientX, e.clientY); }}
				onpointerenter={(e) => onNodeHover(node, e.clientX, e.clientY)}
				onpointerleave={() => onNodeHover(null, 0, 0)}
			>
				<circle
					class="graph-node"
					r={node.radius}
					fill={node.color}
					fill-opacity={node.fillOpacity}
					stroke={node.color}
					stroke-width={node.type === 'root' ? 2 : node.type === 'intermediate' ? 1.5 : 1}
				>
					{#if node.pulseRate > 0}
						<animate
							attributeName="stroke-opacity"
							values="1;0.4;1"
							dur="{2 / node.pulseRate}s"
							repeatCount="indefinite"
						/>
					{/if}
				</circle>

				<!-- Labels for CAs only -->
				{#if node.type !== 'leaf'}
					<text
						class="node-label"
						y={-node.radius - 4}
						text-anchor="middle"
						fill="#e2e8f0"
						font-size={node.type === 'root' ? '9' : '7'}
						font-weight="600"
					>
						{node.label.length > 24 ? node.label.slice(0, 22) + '...' : node.label}
					</text>
					<text
						class="node-badge"
						y={4}
						text-anchor="middle"
						fill={node.color}
						font-size={node.type === 'root' ? '8' : '6.5'}
					>
						{node.grade} · {node.certCount.toLocaleString()}
					</text>
				{/if}

				<!-- Expand indicator for CAs -->
				{#if (node.type === 'root' || node.type === 'intermediate') && node.certCount > 0}
					<text
						class="expand-indicator"
						y={node.radius + 10}
						text-anchor="middle"
						fill="#64748b"
						font-size="6"
					>
						{node.isExpanded ? '−' : '+'}
					</text>
				{/if}
			</g>
		{/each}
	</g>
</svg>

<style>
	.force-graph-svg {
		width: 100%;
		height: 100%;
		display: block;
		cursor: grab;
	}

	.force-graph-svg:active {
		cursor: grabbing;
	}

	.graph-node-group {
		cursor: pointer;
		transition: opacity 0.2s;
	}

	.node-label {
		pointer-events: none;
		user-select: none;
	}

	.node-badge {
		pointer-events: none;
		user-select: none;
	}

	.expand-indicator {
		pointer-events: none;
		user-select: none;
	}

	.graph-edge {
		pointer-events: none;
	}
</style>
```

- [ ] **Step 2: Verify compilation**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check`
Expected: No type errors.

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/lib/components/graph/ForceGraph.svelte
git commit -m "feat(frontend): add ForceGraph SVG rendering component"
```

---

## Task 9: Frontend — Tooltip, Toolbar, Legend Components

**Files:**
- Create: `frontend/src/lib/components/graph/GraphTooltip.svelte`
- Create: `frontend/src/lib/components/graph/GraphToolbar.svelte`
- Create: `frontend/src/lib/components/graph/GraphLegend.svelte`

- [ ] **Step 1: Create GraphTooltip.svelte**

```svelte
<script lang="ts">
	import type { ForceNode } from './graph-types';

	interface Props {
		node: ForceNode | null;
		x: number;
		y: number;
	}

	let { node, x, y }: Props = $props();
</script>

{#if node}
	<div class="graph-tooltip" style="left: {x + 12}px; top: {y - 8}px;">
		<div class="tt-name">{node.label}</div>
		{#if node.organization}
			<div class="tt-org">{node.organization}</div>
		{/if}
		<div class="tt-grid">
			<span class="tt-key">Grade</span>
			<span class="tt-val" style="color: {node.color}; font-weight: 600;">{node.grade}</span>
			{#if node.type !== 'leaf'}
				<span class="tt-key">Certificates</span>
				<span class="tt-val">{node.certCount.toLocaleString()}</span>
				<span class="tt-key">Expired</span>
				<span class="tt-val">{node.expiredCount}</span>
				<span class="tt-key">Avg Score</span>
				<span class="tt-val">{node.avgScore.toFixed(1)}</span>
			{/if}
			<span class="tt-key">Key</span>
			<span class="tt-val">{node.keyAlgorithm} {node.keySizeBits}</span>
		</div>
		<div class="tt-hint">
			{#if node.type === 'leaf'}
				Click to view certificate
			{:else if node.isExpanded}
				Click to collapse
			{:else}
				Click to expand · Right-click for actions
			{/if}
		</div>
	</div>
{/if}

<style>
	.graph-tooltip {
		position: fixed;
		background: rgba(15, 23, 42, 0.95);
		border: 1px solid rgba(56, 189, 248, 0.25);
		border-radius: 8px;
		padding: 0.75rem;
		min-width: 200px;
		max-width: 300px;
		z-index: 50;
		pointer-events: none;
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
	}

	.tt-name {
		font-size: 0.8rem;
		font-weight: 600;
		color: #e2e8f0;
		margin-bottom: 0.125rem;
		word-break: break-word;
	}

	.tt-org {
		font-size: 0.7rem;
		color: #64748b;
		margin-bottom: 0.5rem;
	}

	.tt-grid {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: 0.2rem 0.75rem;
		font-size: 0.7rem;
	}

	.tt-key { color: #64748b; }
	.tt-val { color: #cbd5e1; }

	.tt-hint {
		margin-top: 0.5rem;
		font-size: 0.65rem;
		color: #64748b;
	}
</style>
```

- [ ] **Step 2: Create GraphToolbar.svelte**

```svelte
<script lang="ts">
	import type { GraphMode } from './graph-types';

	interface Props {
		searchQuery: string;
		mode: GraphMode;
		selectedGrades: Set<string>;
		showExpiredOnly: boolean;
		nodeCount: number;
		edgeCount: number;
		expandedCount: number;
		onSearchChange: (q: string) => void;
		onGradeToggle: (grade: string) => void;
		onExpiredToggle: () => void;
		onBlastRadiusToggle: () => void;
		onZoomIn: () => void;
		onZoomOut: () => void;
		onZoomReset: () => void;
	}

	let {
		searchQuery,
		mode,
		selectedGrades,
		showExpiredOnly,
		nodeCount,
		edgeCount,
		expandedCount,
		onSearchChange,
		onGradeToggle,
		onExpiredToggle,
		onBlastRadiusToggle,
		onZoomIn,
		onZoomOut,
		onZoomReset,
	}: Props = $props();

	const GRADES = ['A+', 'A', 'B', 'C', 'D', 'F'];
</script>

<div class="graph-toolbar">
	<div class="toolbar-left">
		<div class="search-box">
			<span class="search-icon">&#128269;</span>
			<input
				type="text"
				placeholder="Search CAs or certificates..."
				value={searchQuery}
				oninput={(e) => onSearchChange(e.currentTarget.value)}
			/>
			{#if searchQuery}
				<button class="search-clear" onclick={() => onSearchChange('')}>&times;</button>
			{/if}
		</div>
	</div>

	<div class="toolbar-center">
		<div class="filter-pills">
			{#each GRADES as grade}
				<button
					class="pill"
					class:active={selectedGrades.has(grade)}
					onclick={() => onGradeToggle(grade)}
				>
					{grade}
				</button>
			{/each}
		</div>
		<button
			class="pill pill-expired"
			class:active={showExpiredOnly}
			onclick={onExpiredToggle}
		>
			Expired
		</button>
		<button
			class="pill pill-blast"
			class:active={mode === 'blast-radius'}
			onclick={onBlastRadiusToggle}
		>
			Blast Radius
		</button>
	</div>

	<div class="toolbar-right">
		<button class="zoom-btn" onclick={onZoomIn} title="Zoom in">+</button>
		<button class="zoom-btn" onclick={onZoomOut} title="Zoom out">&minus;</button>
		<button class="zoom-btn" onclick={onZoomReset} title="Reset view">&#8634;</button>
	</div>
</div>

<style>
	.graph-toolbar {
		position: absolute;
		top: 0;
		left: 0;
		right: 0;
		height: 44px;
		background: rgba(15, 23, 42, 0.95);
		border-bottom: 1px solid rgba(56, 189, 248, 0.15);
		display: flex;
		align-items: center;
		padding: 0 1rem;
		gap: 0.75rem;
		z-index: 10;
	}

	.toolbar-left {
		flex: 1;
	}

	.search-box {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		background: rgba(56, 189, 248, 0.08);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px;
		padding: 0.25rem 0.75rem;
		max-width: 280px;
	}

	.search-icon {
		font-size: 0.75rem;
		color: #64748b;
	}

	.search-box input {
		background: none;
		border: none;
		outline: none;
		color: #e2e8f0;
		font-size: 0.8rem;
		width: 100%;
	}

	.search-box input::placeholder {
		color: #64748b;
	}

	.search-clear {
		background: none;
		border: none;
		color: #64748b;
		cursor: pointer;
		font-size: 1rem;
		padding: 0;
		line-height: 1;
	}

	.toolbar-center {
		display: flex;
		gap: 0.375rem;
		align-items: center;
	}

	.filter-pills {
		display: flex;
		gap: 0.25rem;
	}

	.pill {
		background: rgba(56, 189, 248, 0.08);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px;
		padding: 0.2rem 0.5rem;
		font-size: 0.7rem;
		color: #94a3b8;
		cursor: pointer;
		transition: all 0.15s;
	}

	.pill:hover {
		background: rgba(56, 189, 248, 0.15);
		color: #e2e8f0;
	}

	.pill.active {
		background: rgba(56, 189, 248, 0.2);
		border-color: rgba(56, 189, 248, 0.4);
		color: #38bdf8;
	}

	.pill-expired.active {
		background: rgba(239, 68, 68, 0.15);
		border-color: rgba(239, 68, 68, 0.3);
		color: #ef4444;
	}

	.pill-blast.active {
		background: rgba(249, 115, 22, 0.15);
		border-color: rgba(249, 115, 22, 0.3);
		color: #f97316;
	}

	.toolbar-right {
		display: flex;
		gap: 0.25rem;
	}

	.zoom-btn {
		width: 28px;
		height: 28px;
		background: rgba(56, 189, 248, 0.08);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 4px;
		display: flex;
		align-items: center;
		justify-content: center;
		font-size: 0.85rem;
		color: #94a3b8;
		cursor: pointer;
		transition: all 0.15s;
	}

	.zoom-btn:hover {
		background: rgba(56, 189, 248, 0.15);
		color: #e2e8f0;
	}
</style>
```

- [ ] **Step 3: Create GraphLegend.svelte**

```svelte
<script lang="ts">
	interface Props {
		nodeCount: number;
		totalCerts: number;
		expandedCount: number;
	}

	let { nodeCount, totalCerts, expandedCount }: Props = $props();
</script>

<div class="graph-legend">
	<div class="legend-title">Legend</div>
	<div class="legend-items">
		<span class="legend-item">
			<span class="legend-dot root-dot"></span>Root CA
		</span>
		<span class="legend-item">
			<span class="legend-dot int-dot"></span>Intermediate
		</span>
		<span class="legend-item">
			<span class="legend-dot leaf-dot"></span>Leaf
		</span>
		<span class="legend-item">
			<span class="legend-dot risk-dot"></span>At Risk
		</span>
	</div>
</div>

<div class="graph-stats">
	{nodeCount} CAs · {totalCerts.toLocaleString()} certificates · {expandedCount} expanded
</div>

<style>
	.graph-legend {
		position: absolute;
		bottom: 12px;
		left: 12px;
		background: rgba(15, 23, 42, 0.9);
		border: 1px solid rgba(56, 189, 248, 0.1);
		border-radius: 6px;
		padding: 0.5rem 0.75rem;
		z-index: 10;
	}

	.legend-title {
		font-size: 0.65rem;
		color: #64748b;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 0.375rem;
	}

	.legend-items {
		display: flex;
		gap: 1rem;
		font-size: 0.7rem;
		color: #94a3b8;
		align-items: center;
	}

	.legend-item {
		display: flex;
		align-items: center;
		gap: 4px;
	}

	.legend-dot {
		display: inline-block;
		border-radius: 50%;
		vertical-align: middle;
	}

	.root-dot {
		width: 12px;
		height: 12px;
		background: rgba(34, 197, 94, 0.15);
		border: 1.5px solid #22c55e;
	}

	.int-dot {
		width: 9px;
		height: 9px;
		background: rgba(132, 204, 22, 0.12);
		border: 1.5px solid #84cc16;
	}

	.leaf-dot {
		width: 6px;
		height: 6px;
		background: rgba(56, 189, 248, 0.2);
		border: 1px solid #38bdf8;
	}

	.risk-dot {
		width: 8px;
		height: 8px;
		border: 1.5px solid #ef4444;
		animation: pulse 2s infinite;
	}

	@keyframes pulse {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.4; }
	}

	.graph-stats {
		position: absolute;
		bottom: 12px;
		right: 12px;
		background: rgba(15, 23, 42, 0.9);
		border: 1px solid rgba(56, 189, 248, 0.1);
		border-radius: 6px;
		padding: 0.5rem 0.75rem;
		z-index: 10;
		font-size: 0.7rem;
		color: #94a3b8;
	}
</style>
```

- [ ] **Step 4: Verify compilation**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check`
Expected: No type errors.

- [ ] **Step 5: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/lib/components/graph/
git commit -m "feat(frontend): add GraphTooltip, GraphToolbar, and GraphLegend components"
```

---

## Task 10: Frontend — PKI Page (Compose Everything)

**Files:**
- Replace: `frontend/src/routes/pki/+page.svelte`

- [ ] **Step 1: Replace +page.svelte with the new force graph page**

```svelte
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api, type AggregatedGraphNode, type BlastRadiusResponse } from '$lib/api';
	import ForceGraph from '$lib/components/graph/ForceGraph.svelte';
	import GraphTooltip from '$lib/components/graph/GraphTooltip.svelte';
	import GraphToolbar from '$lib/components/graph/GraphToolbar.svelte';
	import GraphLegend from '$lib/components/graph/GraphLegend.svelte';
	import type { ForceNode, ForceEdge, GraphMode } from '$lib/components/graph/graph-types';
	import { apiNodeToForceNode, apiEdgeToForceEdge } from '$lib/components/graph/graph-simulation';

	let nodes: ForceNode[] = $state([]);
	let edges: ForceEdge[] = $state([]);
	let expandedCAs: Set<string> = $state(new Set());
	let mode: GraphMode = $state('explore');
	let searchQuery = $state('');
	let blastRadiusTarget: string | null = $state(null);
	let blastRadiusNodes: Set<string> = $state(new Set());
	let blastRadiusSummary: BlastRadiusResponse['summary'] | null = $state(null);
	let hoveredNode: ForceNode | null = $state(null);
	let tooltipX = $state(0);
	let tooltipY = $state(0);
	let selectedGrades: Set<string> = $state(new Set());
	let showExpiredOnly = $state(false);
	let loading = $state(true);
	let error: string | null = $state(null);
	let totalCerts = $state(0);
	let zoomScale = $state(1);

	let graphComponent: ForceGraph;

	// Compute dimmed nodes based on current mode + filters
	let dimmedNodes: Set<string> = $derived.by(() => {
		const dimmed = new Set<string>();

		if (mode === 'blast-radius' && blastRadiusTarget) {
			for (const n of nodes) {
				if (n.id !== blastRadiusTarget && !blastRadiusNodes.has(n.id)) {
					dimmed.add(n.id);
				}
			}
			return dimmed;
		}

		if (searchQuery) {
			const q = searchQuery.toLowerCase();
			for (const n of nodes) {
				if (!n.label.toLowerCase().includes(q) &&
					!n.organization.toLowerCase().includes(q) &&
					!n.id.toLowerCase().startsWith(q)) {
					dimmed.add(n.id);
				}
			}
			return dimmed;
		}

		if (selectedGrades.size > 0) {
			for (const n of nodes) {
				if (!selectedGrades.has(n.grade)) {
					dimmed.add(n.id);
				}
			}
		}

		if (showExpiredOnly) {
			for (const n of nodes) {
				if (n.expiredCount === 0) {
					dimmed.add(n.id);
				}
			}
		}

		return dimmed;
	});

	onMount(async () => {
		try {
			const resp = await api.getAggregatedLandscape();
			nodes = resp.nodes.map(apiNodeToForceNode);
			edges = resp.edges.map((e, i) => apiEdgeToForceEdge(e, i));
			totalCerts = resp.nodes.reduce((sum, n) => sum + n.cert_count, 0);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load landscape';
		}
		loading = false;
	});

	async function handleNodeClick(node: ForceNode) {
		if (mode === 'blast-radius') {
			if (node.type !== 'leaf') {
				await activateBlastRadius(node.id);
			}
			return;
		}

		if (node.type === 'leaf') {
			goto(`/certificates/${node.id}`);
			return;
		}

		// Toggle expand/collapse
		if (expandedCAs.has(node.id)) {
			collapseCA(node.id);
		} else {
			await expandCA(node.id);
		}
	}

	async function expandCA(fingerprint: string) {
		try {
			const resp = await api.getCAChildren(fingerprint);
			const newNodes = resp.nodes.map(apiNodeToForceNode);
			const edgeOffset = edges.length;
			const newEdges = resp.edges.map((e, i) => apiEdgeToForceEdge(e, edgeOffset + i));

			// Position new nodes near parent
			const parent = nodes.find(n => n.id === fingerprint);
			if (parent) {
				for (const n of newNodes) {
					n.x = (parent.x ?? 0) + (Math.random() - 0.5) * 40;
					n.y = (parent.y ?? 0) + (Math.random() - 0.5) * 40;
				}
			}

			nodes = [...nodes, ...newNodes];
			edges = [...edges, ...newEdges];

			const next = new Set(expandedCAs);
			next.add(fingerprint);
			expandedCAs = next;

			// Mark parent as expanded
			const parentNode = nodes.find(n => n.id === fingerprint);
			if (parentNode) parentNode.isExpanded = true;
		} catch (e) {
			console.error('Failed to expand CA:', e);
		}
	}

	function collapseCA(fingerprint: string) {
		// Find all children (direct edges from this CA)
		const childIds = new Set<string>();
		const collectChildren = (parentId: string) => {
			for (const edge of edges) {
				const srcId = typeof edge.source === 'object' ? edge.source.id : edge.source;
				const tgtId = typeof edge.target === 'object' ? edge.target.id : edge.target;
				if (srcId === parentId && !childIds.has(tgtId)) {
					const childNode = nodes.find(n => n.id === tgtId);
					// Only remove nodes that were added by expansion (not original landscape nodes)
					if (childNode && childNode.type === 'leaf') {
						childIds.add(tgtId);
					} else if (childNode && expandedCAs.has(tgtId)) {
						// Recursively collapse expanded children
						collapseCA(tgtId);
						childIds.add(tgtId);
					} else if (childNode && !childNode.isExpanded) {
						childIds.add(tgtId);
					}
				}
			}
		};
		collectChildren(fingerprint);

		nodes = nodes.filter(n => !childIds.has(n.id));
		edges = edges.filter(e => {
			const srcId = typeof e.source === 'object' ? e.source.id : e.source;
			const tgtId = typeof e.target === 'object' ? e.target.id : e.target;
			return !childIds.has(srcId) && !childIds.has(tgtId);
		});

		const next = new Set(expandedCAs);
		next.delete(fingerprint);
		expandedCAs = next;

		const parentNode = nodes.find(n => n.id === fingerprint);
		if (parentNode) parentNode.isExpanded = false;
	}

	async function activateBlastRadius(fingerprint: string) {
		try {
			const resp = await api.getBlastRadius(fingerprint);
			blastRadiusTarget = fingerprint;
			blastRadiusNodes = new Set(resp.nodes.map(n => n.fingerprint));
			blastRadiusSummary = resp.summary;

			// Add blast radius nodes that aren't already in the graph
			const existingIds = new Set(nodes.map(n => n.id));
			const newNodes = resp.nodes
				.filter(n => !existingIds.has(n.fingerprint))
				.map(apiNodeToForceNode);
			const edgeOffset = edges.length;
			const newEdges = resp.edges
				.filter(e => !edges.some(existing => {
					const eSrc = typeof existing.source === 'object' ? existing.source.id : existing.source;
					const eTgt = typeof existing.target === 'object' ? existing.target.id : existing.target;
					return eSrc === e.source && eTgt === e.target;
				}))
				.map((e, i) => apiEdgeToForceEdge(e, edgeOffset + i));

			if (newNodes.length > 0 || newEdges.length > 0) {
				// Position near the target
				const target = nodes.find(n => n.id === fingerprint);
				if (target) {
					for (const n of newNodes) {
						n.x = (target.x ?? 0) + (Math.random() - 0.5) * 80;
						n.y = (target.y ?? 0) + (Math.random() - 0.5) * 80;
					}
				}
				nodes = [...nodes, ...newNodes];
				edges = [...edges, ...newEdges];
			}
		} catch (e) {
			console.error('Failed to load blast radius:', e);
		}
	}

	function deactivateBlastRadius() {
		blastRadiusTarget = null;
		blastRadiusNodes = new Set();
		blastRadiusSummary = null;
		mode = 'explore';
	}

	function handleBackgroundClick() {
		if (mode === 'blast-radius') {
			deactivateBlastRadius();
		}
		hoveredNode = null;
	}

	function handleNodeHover(node: ForceNode | null, x: number, y: number) {
		hoveredNode = node;
		tooltipX = x;
		tooltipY = y;
	}

	function handleNodeRightClick(node: ForceNode, x: number, y: number) {
		if (node.type !== 'leaf') {
			mode = 'blast-radius';
			activateBlastRadius(node.id);
		}
	}

	function handleSearchChange(q: string) {
		searchQuery = q;
		mode = q ? 'search' : 'explore';
	}

	function handleGradeToggle(grade: string) {
		const next = new Set(selectedGrades);
		if (next.has(grade)) next.delete(grade);
		else next.add(grade);
		selectedGrades = next;
	}

	function handleExpiredToggle() {
		showExpiredOnly = !showExpiredOnly;
	}

	function handleBlastRadiusToggle() {
		if (mode === 'blast-radius') {
			deactivateBlastRadius();
		} else {
			mode = 'blast-radius';
		}
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			if (mode === 'blast-radius') deactivateBlastRadius();
			else if (searchQuery) handleSearchChange('');
		}
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="pki-graph-page">
	{#if loading}
		<div class="loading-overlay">Loading PKI landscape...</div>
	{:else if error}
		<div class="error-overlay">{error}</div>
	{:else}
		<ForceGraph
			bind:this={graphComponent}
			bind:nodes
			bind:edges
			{hoveredNode}
			{dimmedNodes}
			onNodeClick={handleNodeClick}
			onNodeHover={handleNodeHover}
			onNodeRightClick={handleNodeRightClick}
			onBackgroundClick={handleBackgroundClick}
			onZoomChange={(s) => zoomScale = s}
		/>

		<GraphToolbar
			{searchQuery}
			{mode}
			{selectedGrades}
			{showExpiredOnly}
			nodeCount={nodes.filter(n => n.type !== 'leaf').length}
			edgeCount={edges.length}
			expandedCount={expandedCAs.size}
			onSearchChange={handleSearchChange}
			onGradeToggle={handleGradeToggle}
			onExpiredToggle={handleExpiredToggle}
			onBlastRadiusToggle={handleBlastRadiusToggle}
			onZoomIn={() => graphComponent.zoomIn()}
			onZoomOut={() => graphComponent.zoomOut()}
			onZoomReset={() => graphComponent.zoomReset()}
		/>

		<GraphTooltip node={hoveredNode} x={tooltipX} y={tooltipY} />

		<GraphLegend
			nodeCount={nodes.filter(n => n.type !== 'leaf').length}
			{totalCerts}
			expandedCount={expandedCAs.size}
		/>

		{#if mode === 'blast-radius' && blastRadiusSummary}
			<div class="blast-badge">
				<strong>Blast Radius</strong>
				<span>{blastRadiusSummary.total_certs} certs</span>
				{#if blastRadiusSummary.expired > 0}
					<span class="blast-expired">{blastRadiusSummary.expired} expired</span>
				{/if}
				{#if blastRadiusSummary.grade_f > 0}
					<span class="blast-gradef">{blastRadiusSummary.grade_f} grade F</span>
				{/if}
				<button class="blast-close" onclick={deactivateBlastRadius}>Esc to close</button>
			</div>
		{/if}
	{/if}
</div>

<style>
	.pki-graph-page {
		position: relative;
		width: 100%;
		height: 100%;
		background: #0a0e17;
		overflow: hidden;
	}

	.loading-overlay,
	.error-overlay {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
		color: var(--cf-text-muted);
		font-size: 0.9rem;
	}

	.error-overlay {
		color: var(--cf-risk-critical);
	}

	.blast-badge {
		position: absolute;
		top: 56px;
		left: 50%;
		transform: translateX(-50%);
		background: rgba(15, 23, 42, 0.95);
		border: 1px solid rgba(249, 115, 22, 0.3);
		border-radius: 8px;
		padding: 0.5rem 1rem;
		display: flex;
		align-items: center;
		gap: 0.75rem;
		font-size: 0.8rem;
		color: #e2e8f0;
		z-index: 15;
	}

	.blast-badge strong {
		color: #f97316;
	}

	.blast-expired {
		color: #ef4444;
	}

	.blast-gradef {
		color: #ef4444;
	}

	.blast-close {
		background: rgba(249, 115, 22, 0.15);
		border: 1px solid rgba(249, 115, 22, 0.3);
		border-radius: 4px;
		padding: 0.15rem 0.5rem;
		font-size: 0.7rem;
		color: #f97316;
		cursor: pointer;
	}
</style>
```

- [ ] **Step 2: Verify the full frontend compiles**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag && git add frontend/src/routes/pki/+page.svelte
git commit -m "feat(frontend): replace PKI tree view with force-directed graph page"
```

---

## Task 11: Integration Test — Verify End-to-End

**Files:** None (verification only)

- [ ] **Step 1: Verify Go backend compiles and starts**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

Expected: Clean compile, no errors.

- [ ] **Step 2: Verify frontend compiles**

```bash
cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check
```

Expected: No type errors.

- [ ] **Step 3: Verify frontend dev server starts**

```bash
cd /Users/Erik/projects/cipherflag/frontend && npm run dev -- --open &
sleep 3
curl -s http://localhost:5174/pki | head -20
```

Expected: HTML response (SvelteKit renders the page).

- [ ] **Step 4: Verify new API endpoints respond**

```bash
curl -s http://localhost:8443/api/v1/graph/landscape/aggregated | python3 -m json.tool | head -20
```

Expected: JSON response with `nodes` and `edges` arrays.

- [ ] **Step 5: Commit any fixes if needed, then final commit**

```bash
cd /Users/Erik/projects/cipherflag && git add -A && git status
```

If there are any missed files, stage and commit:

```bash
git commit -m "feat: complete PKI force-directed graph implementation"
```

---

## Deferred: Server-Side Search Fallback

The spec calls for server-side search when fewer than 5 client-side matches are found (calling `GET /api/certificates?search=...&limit=10`), with a search dropdown showing "not in graph" indicators and auto-expanding parent CA chains on click. This is deferred to a fast-follow because:

- The existing `searchCerts` API already supports full-text search
- The frontend plumbing (search state, dimming) is in place
- What's needed: a debounced server call, a dropdown results list, and logic to trace a leaf cert back to its CA chain and expand it

The current implementation does client-side filtering on loaded nodes, which covers the primary use case (finding CAs in the landscape view).
