# CipherFlag CE PKI Graph Backend Implementation Plan (Phase 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un-break CipherFlag CE's existing 2D PKI Explorer (and reach full EE parity on the graph API) by restoring the stripped graph backend — porting 2 Go files verbatim from EE and registering 5 `/graph/*` routes.

**Architecture:** CE already ships the PKI Explorer frontend, the `api.ts` client methods, the 6 store methods, and all model types; only `internal/analysis/chain.go` and `internal/api/handler/graph.go` are missing and no `/graph/*` routes are registered, so the page 404s. This plan ports those 2 files (verbatim — EE's import path `github.com/net4n6-dev/cipherflag/...` already matches CE), constructs the handler + registers 5 routes in `server.go`, and adds a route-registration regression test. No new store/SQL/migration/frontend code.

**Tech Stack:** Go 1.25 (chi router), SvelteKit 2 SPA (unchanged this phase), adapter-static embed.

**Spec:** `docs/superpowers/specs/2026-05-31-pki-graph-backend-design.md`
**Branch:** `feat/ce-pki-graph-backend` (already created off `main`; spec already committed at HEAD).

---

## Pre-flight (read once)

- **Repos:** CE = `/Users/Erik/projects/cipherflag` (branch `feat/ce-pki-graph-backend`). EE source-of-truth (read-only) = `/Users/Erik/projects/cipherflag-EE`.
- **Backend is mostly already built.** All 6 store methods, all model types, and the `loadReportsMap`/`writeJSON`/`writeError` helpers already exist in CE and compile. This plan ports 2 files + wiring. Do NOT re-implement store methods or model types.
- **Verbatim port.** EE's `internal/analysis/chain.go` and `internal/api/handler/graph.go` use the import path `github.com/net4n6-dev/cipherflag/...` — identical to CE. The ONLY change when porting is prepending CE's Apache license header (every CE Go file carries it; EE's copies lack it). Do NOT otherwise modify the code.
- **`NewGraphHandler(s store.CertStore)`** takes the narrower `store.CertStore`. CE's `st` (passed to all handlers) is `store.CryptoStore`, which embeds `CertStore`, so `handler.NewGraphHandler(st)` compiles directly.
- **adapter-static / Go embed:** this phase changes only Go; `go build ./...` must stay green (the SPA embed is unaffected).
- **Flaky bash:** this environment's bash output is intermittently empty — if a command returns nothing, re-run it or redirect to a file and read it. Never conclude from one blank result. Quote the real `git log -1 --format='%h %s'` output for SHAs.
- **Do NOT** `git add -A` / `git add .` — untracked `docs/`, `.claude/`, `research/` dirs must not be committed. Stage explicit paths only.
- **Out of scope:** the 3D constellation (Phase 3), the SSE layer (Phase 2), and the EE-only host graphs. This phase is the graph-backend de-moat only.

---

## File manifest

| Path | Action | Responsibility |
|---|---|---|
| `internal/analysis/chain.go` | create (port from EE + header) | BuildGraphData / BuildChainTree / BuildChainGraphData + helpers |
| `internal/api/handler/graph.go` | create (port from EE + header) | GraphHandler + 5 methods |
| `internal/api/handler/graph_test.go` | create | 5-route non-404 regression test |
| `internal/api/server.go` | modify | construct graphH; register 5 routes; update stripped-wiring comment |

Tasks ordered so `go build` + `go test` stay green after each.

---

## Task 1: Port `internal/analysis/chain.go`

**Files:**
- Create: `internal/analysis/chain.go`

This file has no dependency on the handler, so it ports + compiles first on its own.

- [ ] **Step 1: Create the file (CE Apache header + EE content verbatim)**

Create `internal/analysis/chain.go` with the CE Apache header followed by EE's exact content:
```go
// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analysis

import (
	"fmt"
	"math"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// BuildGraphData transforms a slice of certificates and their health reports
// into Cytoscape.js-compatible graph elements for the landscape view.
func BuildGraphData(certs []model.Certificate, reports map[string]*model.HealthReport) *model.GraphResponse {
	resp := &model.GraphResponse{
		Nodes: []model.GraphNode{},
		Edges: []model.GraphEdge{},
	}

	// Index certs by subject CN for parent lookups (more reliable than Full DN)
	certBySubjectCN := make(map[string]*model.Certificate)
	for i := range certs {
		if certs[i].IsCA {
			certBySubjectCN[certs[i].Subject.CommonName] = &certs[i]
		}
	}

	// Track issuer compound groups for Cytoscape compound nodes
	issuerGroups := make(map[string]bool)

	for _, cert := range certs {
		report := reports[cert.FingerprintSHA256]

		nodeType := classifyNode(&cert)
		risk := "low"
		grade := model.GradeAPlus
		score := 100

		if report != nil {
			grade = report.Grade
			score = report.Score
			risk = gradeToRisk(report.Grade)
		}

		days := cert.DaysUntilExpiry()
		pulseRate := calcPulseRate(days)
		sizeWeight := calcSizeWeight(&cert, report)

		// Determine parent compound node (issuer org group)
		parentID := ""
		if cert.Issuer.Organization != "" && !cert.IsSelfSigned() {
			parentID = "group-" + sanitizeID(cert.Issuer.Organization)
			issuerGroups[parentID] = true
		}

		label := cert.Subject.CommonName
		if label == "" {
			label = cert.FingerprintSHA256[:12]
		}

		node := model.GraphNode{
			Data: model.GraphNodeData{
				ID:               cert.FingerprintSHA256,
				Label:            label,
				NodeType:         nodeType,
				Grade:            grade,
				Score:            score,
				Risk:             risk,
				KeyAlgorithm:     string(cert.KeyAlgorithm),
				KeySizeBits:      cert.KeySizeBits,
				DaysUntilExpiry:  days,
				IsCA:             cert.IsCA,
				Parent:           parentID,
				Issuer:           cert.Issuer.Full,
				PulseRate:        pulseRate,
				SizeWeight:       sizeWeight,
			},
		}
		resp.Nodes = append(resp.Nodes, node)

		// Create edge from this cert to its issuer (if issuer exists in our dataset)
		if !cert.IsSelfSigned() {
			issuerCert := certBySubjectCN[cert.Issuer.CommonName]
			if issuerCert != nil {
				edgeRisk := risk
				fresh := time.Since(cert.LastSeen) < 7*24*time.Hour

				edge := model.GraphEdge{
					Data: model.GraphEdgeData{
						ID:     fmt.Sprintf("e-%s-%s", cert.FingerprintSHA256[:8], issuerCert.FingerprintSHA256[:8]),
						Source: cert.FingerprintSHA256,
						Target: issuerCert.FingerprintSHA256,
						Risk:   edgeRisk,
						Weight: edgeWeight(report),
						Fresh:  fresh,
					},
				}
				resp.Edges = append(resp.Edges, edge)
			}
		}
	}

	// Add compound group nodes for issuers
	for groupID := range issuerGroups {
		orgName := groupID[6:] // strip "group-" prefix
		resp.Nodes = append(resp.Nodes, model.GraphNode{
			Data: model.GraphNodeData{
				ID:         groupID,
				Label:      orgName,
				NodeType:   "group",
				SizeWeight: 1,
			},
		})
	}

	return resp
}

// BuildChainTree builds a chain tree starting from a leaf certificate.
func BuildChainTree(leaf *model.Certificate, allCerts []model.Certificate, reports map[string]*model.HealthReport) *model.ChainTree {
	tree := &model.ChainTree{
		Nodes:        []model.ChainNode{},
		Fingerprints: []string{},
		IsComplete:   false,
	}

	visited := make(map[string]bool)
	current := leaf
	depth := 0

	// Build lookup by subject CN (primary) — more reliable than Full DN
	certBySubjectCN := make(map[string][]*model.Certificate)
	for i := range allCerts {
		cn := allCerts[i].Subject.CommonName
		certBySubjectCN[cn] = append(certBySubjectCN[cn], &allCerts[i])
	}

	findIssuer := func(cert *model.Certificate) *model.Certificate {
		candidates := certBySubjectCN[cert.Issuer.CommonName]
		if len(candidates) == 1 {
			return candidates[0]
		}
		// Multiple CAs with same CN — prefer matching org
		for _, c := range candidates {
			if c.IsCA && c.Subject.Organization == cert.Issuer.Organization {
				return c
			}
		}
		// Fallback: any CA with that CN
		for _, c := range candidates {
			if c.IsCA {
				return c
			}
		}
		if len(candidates) > 0 {
			return candidates[0]
		}
		return nil
	}

	for current != nil && !visited[current.FingerprintSHA256] {
		visited[current.FingerprintSHA256] = true

		level := "End Entity"
		if current.IsCA && current.IsSelfSigned() {
			level = "Root"
		} else if current.IsCA {
			level = "Intermediate"
		}

		node := model.ChainNode{
			Certificate:  current,
			HealthReport: reports[current.FingerprintSHA256],
			Level:        level,
			Depth:        depth,
		}
		tree.Nodes = append(tree.Nodes, node)
		tree.Fingerprints = append(tree.Fingerprints, current.FingerprintSHA256)

		if current.IsSelfSigned() {
			tree.IsComplete = true
			break
		}

		current = findIssuer(current)
		depth++
	}

	return tree
}

// BuildChainGraphData converts a ChainTree into Cytoscape.js elements for the chain view.
// Unlike BuildGraphData, this creates direct edges based on the chain walk order
// and omits compound group nodes.
func BuildChainGraphData(tree *model.ChainTree) *model.GraphResponse {
	resp := &model.GraphResponse{
		Nodes: []model.GraphNode{},
		Edges: []model.GraphEdge{},
	}

	for _, cn := range tree.Nodes {
		cert := cn.Certificate
		report := cn.HealthReport

		nodeType := classifyNode(cert)
		risk := "low"
		grade := model.GradeAPlus
		score := 100

		if report != nil {
			grade = report.Grade
			score = report.Score
			risk = gradeToRisk(report.Grade)
		}

		label := cert.Subject.CommonName
		if label == "" {
			label = cert.FingerprintSHA256[:12]
		}

		resp.Nodes = append(resp.Nodes, model.GraphNode{
			Data: model.GraphNodeData{
				ID:              cert.FingerprintSHA256,
				Label:           label,
				NodeType:        nodeType,
				Grade:           grade,
				Score:           score,
				Risk:            risk,
				KeyAlgorithm:    string(cert.KeyAlgorithm),
				KeySizeBits:     cert.KeySizeBits,
				DaysUntilExpiry: cert.DaysUntilExpiry(),
				IsCA:            cert.IsCA,
				Issuer:          cert.Issuer.CommonName,
				SizeWeight:      calcSizeWeight(cert, report),
			},
		})
	}

	// Create edges between consecutive chain nodes (child → parent)
	for i := 0; i < len(tree.Fingerprints)-1; i++ {
		resp.Edges = append(resp.Edges, model.GraphEdge{
			Data: model.GraphEdgeData{
				ID:     fmt.Sprintf("chain-%d", i),
				Source: tree.Fingerprints[i],
				Target: tree.Fingerprints[i+1],
				Risk:   "low",
				Weight: 2,
				Fresh:  true,
			},
		})
	}

	return resp
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func classifyNode(cert *model.Certificate) string {
	if cert.IsCA && cert.IsSelfSigned() {
		return "root"
	}
	if cert.IsCA {
		return "intermediate"
	}
	return "leaf"
}

func gradeToRisk(grade model.Grade) string {
	switch grade {
	case model.GradeF:
		return "critical"
	case model.GradeD:
		return "high"
	case model.GradeC:
		return "medium"
	default:
		return "low"
	}
}

func calcPulseRate(daysUntilExpiry int) float64 {
	if daysUntilExpiry < 0 {
		return 3.0 // Expired: fast pulse
	}
	if daysUntilExpiry < 7 {
		return 2.5
	}
	if daysUntilExpiry < 30 {
		return 1.5
	}
	if daysUntilExpiry < 90 {
		return 0.8
	}
	return 0.0 // Healthy: no pulse
}

func calcSizeWeight(cert *model.Certificate, report *model.HealthReport) float64 {
	base := 1.0
	if cert.IsCA {
		base = 2.0
		if cert.IsSelfSigned() {
			base = 3.0
		}
	}
	// Boost for poor health
	if report != nil && report.Score < 50 {
		base *= 1.5
	}
	return math.Min(base, 4.0)
}

func edgeWeight(report *model.HealthReport) float64 {
	if report == nil {
		return 1.0
	}
	if report.Score < 50 {
		return 3.0
	}
	if report.Score < 70 {
		return 2.0
	}
	return 1.0
}

func sanitizeID(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			out = append(out, byte(c))
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}
```

- [ ] **Step 2: Verify it compiles + gofmt-clean**

Run: `cd /Users/Erik/projects/cipherflag && go build ./internal/analysis/ 2>&1 | tail -15 && echo ANALYSIS-BUILD-OK`
Expected: ANALYSIS-BUILD-OK. If a `model` type/field is reported missing, STOP and report (the spec verified all are present in `internal/model/chain.go` + `health.go` — a failure means something diverged).
Run: `gofmt -l internal/analysis/chain.go`
Expected: NO output (empty = already formatted). If it prints the filename, run `gofmt -w internal/analysis/chain.go`.

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add internal/analysis/chain.go
git commit -m "feat(analysis): port chain graph builders (BuildGraphData/BuildChainTree)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 2: Port `internal/api/handler/graph.go`

**Files:**
- Create: `internal/api/handler/graph.go`

Depends on Task 1 (`analysis.BuildGraphData` etc.) + CE's existing `loadReportsMap`/`writeJSON`/`writeError` + the 6 store methods.

- [ ] **Step 1: Create the file (CE Apache header + EE content verbatim)**

Create `internal/api/handler/graph.go`:
```go
// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/analysis"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type GraphHandler struct {
	store store.CertStore
}

func NewGraphHandler(s store.CertStore) *GraphHandler {
	return &GraphHandler{store: s}
}

// Landscape returns all certificates as Cytoscape.js-compatible graph elements.
func (h *GraphHandler) Landscape(w http.ResponseWriter, r *http.Request) {
	certs, err := h.store.GetAllCertificatesForGraph(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	reports := loadReportsMap(h.store, r)
	graph := analysis.BuildGraphData(certs, reports)
	writeJSON(w, http.StatusOK, graph)
}

// ChainGraph returns a chain-specific graph starting from a fingerprint.
func (h *GraphHandler) ChainGraph(w http.ResponseWriter, r *http.Request) {
	fp := chi.URLParam(r, "fingerprint")

	cert, err := h.store.GetCertificate(r.Context(), fp)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}

	allCerts, err := h.store.GetAllCertificatesForGraph(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	reports := loadReportsMap(h.store, r)
	tree := analysis.BuildChainTree(cert, allCerts, reports)
	graph := analysis.BuildChainGraphData(tree)
	writeJSON(w, http.StatusOK, graph)
}

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

- [ ] **Step 2: Verify it compiles + gofmt-clean**

Run: `cd /Users/Erik/projects/cipherflag && go build ./... 2>&1 | tail -15 && echo GO-BUILD-OK`
Expected: GO-BUILD-OK. (The handler isn't wired into the router yet — that's Task 3 — but the package must compile.) If `loadReportsMap`/`writeJSON`/`writeError` are reported undefined, they live in `internal/api/handler/certificates.go` (same package) — confirm they exist; do NOT redefine them.
Run: `gofmt -l internal/api/handler/graph.go`
Expected: NO output. If it prints the filename, run `gofmt -w internal/api/handler/graph.go`.

- [ ] **Step 3: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add internal/api/handler/graph.go
git commit -m "feat(api): port graph handler (landscape/chain/aggregated/children/blast-radius)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 3: Register the 5 routes + regression test

**Files:**
- Modify: `internal/api/server.go`
- Create: `internal/api/handler/graph_test.go`

- [ ] **Step 1: Write the regression test FIRST**

Create `internal/api/handler/graph_test.go`:
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

// fakeGraphStore embeds store.CertStore (nil) so it satisfies NewGraphHandler's
// parameter type without implementing every method. We override only the six
// methods the five graph routes invoke; GetCertificate returns a non-nil cert
// so ChainGraph exercises its success path (not the 404 branch).
type fakeGraphStore struct {
	store.CertStore
}

func (f *fakeGraphStore) GetAllCertificatesForGraph(ctx context.Context) ([]model.Certificate, error) {
	return []model.Certificate{}, nil
}
func (f *fakeGraphStore) GetCertificate(ctx context.Context, fingerprint string) (*model.Certificate, error) {
	return &model.Certificate{FingerprintSHA256: fingerprint}, nil
}
func (f *fakeGraphStore) GetAllHealthReports(ctx context.Context) ([]model.HealthReport, error) {
	return []model.HealthReport{}, nil
}
func (f *fakeGraphStore) GetAggregatedLandscape(ctx context.Context) (*model.AggregatedLandscapeResponse, error) {
	return &model.AggregatedLandscapeResponse{}, nil
}
func (f *fakeGraphStore) GetCAChildren(ctx context.Context, fingerprint string, limit, offset int) (*model.CAChildrenResponse, error) {
	return &model.CAChildrenResponse{}, nil
}
func (f *fakeGraphStore) GetBlastRadius(ctx context.Context, fingerprint string, limit int) (*model.BlastRadiusResponse, error) {
	return &model.BlastRadiusResponse{}, nil
}

func newGraphRouter(t *testing.T, s store.CertStore) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	h := NewGraphHandler(s)
	r.Get("/graph/landscape", h.Landscape)
	r.Get("/graph/chain/{fingerprint}", h.ChainGraph)
	r.Get("/graph/landscape/aggregated", h.AggregatedLandscape)
	r.Get("/graph/ca/{fingerprint}/children", h.CAChildren)
	r.Get("/graph/ca/{fingerprint}/blast-radius", h.BlastRadius)
	return r
}

func TestGraphHandler_RoutesRegistered(t *testing.T) {
	r := newGraphRouter(t, &fakeGraphStore{})

	for _, path := range []string{
		"/graph/landscape",
		"/graph/chain/abc123",
		"/graph/landscape/aggregated",
		"/graph/ca/abc123/children",
		"/graph/ca/abc123/blast-radius",
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
NOTE: this test is in package `handler` alongside `stats_test.go` / `lineage_test.go` — do NOT redefine the package-level helpers `contains`/`indexOf` (they live in `lineage_test.go`); this test doesn't need them. Before finalizing, VERIFY the 6 store-method signatures against `internal/store/store.go` (the spec lists them: `GetAllCertificatesForGraph(ctx) ([]model.Certificate, error)`, `GetCertificate(ctx, string) (*model.Certificate, error)`, `GetAllHealthReports(ctx) ([]model.HealthReport, error)`, `GetAggregatedLandscape(ctx) (*model.AggregatedLandscapeResponse, error)`, `GetCAChildren(ctx, string, int, int) (*model.CAChildrenResponse, error)`, `GetBlastRadius(ctx, string, int) (*model.BlastRadiusResponse, error)`). If any signature differs, fix the fake's override to match (the override must match the interface method exactly or it won't satisfy it / the embedded interface's method will be called and panic on nil).

- [ ] **Step 2: Run the test — expect it to PASS (handler + analysis already exist from Tasks 1-2)**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/api/handler/ -run TestGraphHandler_RoutesRegistered -v 2>&1 | tail -20`
Expected: PASS. (The handler exists from Task 2; this test builds its own router, so it passes independent of server.go wiring — it locks the route→handler contract. If it FAILS to compile because the fake doesn't satisfy `store.CertStore`, a store-method signature differs from Step 1's assumption — fix the override to match `internal/store/store.go`. If a route returns non-200, read that handler to see which store method it calls and ensure the fake overrides it.)

- [ ] **Step 3: Register the handler + 5 routes in server.go**

In `internal/api/server.go`:

(a) In the handler-construction block (1-tab indent), add a line after the `venafiH := handler.NewVenafiHandler(st, cfg, cfgPath)` line:
```go
	graphH := handler.NewGraphHandler(st)
```
(If `venafiH` isn't the last construction line in your file, add `graphH` anywhere in that `certH := ...` / `statsH := ...` construction block — order doesn't matter, it just must be before the route group.)

(b) In the authenticated route group (3-tab indent), find the PKI tree block:
```go
			// PKI tree
			r.Get("/pki/tree", statsH.PKITree)
```
Add immediately after it:
```go

			// Graph / PKI landscape (Cytoscape.js views)
			r.Get("/graph/landscape", graphH.Landscape)
			r.Get("/graph/chain/{fingerprint}", graphH.ChainGraph)
			r.Get("/graph/landscape/aggregated", graphH.AggregatedLandscape)
			r.Get("/graph/ca/{fingerprint}/children", graphH.CAChildren)
			r.Get("/graph/ca/{fingerprint}/blast-radius", graphH.BlastRadius)
```

(c) Update the stripped-wiring comment. Find (around lines 39-43):
```go
// EE-only handler wiring (risk, blast-radius, host-dependencies, host
// subgraph, host trust store, AI usage, briefing, container images,
// network targets, teams, external sources, rank review, PQC migration
// planner, evidence export, agency OMB, SSE event stream) has been
// stripped. The Layer 0/1/2/4/5/6.1a-c surface remains.
```
Change the parenthetical so the cert-graph landscape views are no longer listed as stripped (the host dependency/blast-radius graphs ARE still stripped — keep those). Replace with:
```go
// EE-only handler wiring (risk, host blast-radius, host-dependencies, host
// subgraph, host trust store, AI usage, briefing, container images,
// network targets, teams, external sources, rank review, PQC migration
// planner, evidence export, agency OMB, SSE event stream) has been
// stripped. The Layer 0/1/2/4/5/6.1a-c surface remains, including the
// PKI cert-graph landscape views (/graph/*).
```
(The key change: "blast-radius" → "host blast-radius" to disambiguate from the now-present cert blast-radius, and a note that `/graph/*` is restored.)

- [ ] **Step 4: Build + verify routes registered + full test run**

Run: `cd /Users/Erik/projects/cipherflag && go build ./... 2>&1 | tail -10 && echo GO-BUILD-OK`
Expected: GO-BUILD-OK.
Run: `grep -nE 'r.Get\("/graph/' internal/api/server.go`
Expected: 5 lines.
Run: `go test ./internal/api/... 2>&1 | tail -15`
Expected: all pass (the new graph test + the existing stats/lineage/etc. tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/Erik/projects/cipherflag
git add internal/api/server.go internal/api/handler/graph_test.go
git commit -m "feat(api): register 5 /graph/* routes — restores CE PKI Explorer backend

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
git log -1 --format='%h %s'
```

---

## Task 4: Rebuild container + verify PKI Explorer un-broken (dark + light)

**Files:** none (verification only — no commit unless a defect fix is warranted)

- [ ] **Step 1: Rebuild the image + recreate the stack**

Run:
```bash
cd /Users/Erik/projects/cipherflag
docker compose build cipherflag 2>&1 | tail -6
docker compose up -d 2>&1 | tail -5
docker compose ps --format '{{.Service}}={{.State}}'
```
Expected: image builds; both services running. (Docker build takes minutes — generous timeout; re-check `docker compose ps` rather than concluding failure from an empty result. If a port conflict appears, report it + `docker compose ps`.)

- [ ] **Step 2: Confirm the 5 graph routes no longer 404**

Run:
```bash
for p in "graph/landscape" "graph/landscape/aggregated" "graph/ca/abc123/children" "graph/ca/abc123/blast-radius" "graph/chain/abc123"; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' "http://localhost:8443/api/v1/$p")
  echo "$p -> $code"
done
```
Expected: NONE returns `404`. 200 (no auth at that layer) or 401 (auth required) are both acceptable — the de-moat goal is "not 404, route is registered". `graph/chain/abc123` may return 404 with body `"certificate not found"` — that's the HANDLER's not-found (route resolved, cert absent), which is correct; distinguish it from a routing 404 by checking the body (a routing 404 has chi's default `404 page not found`, the handler returns `{"error":"certificate not found"}`). Report the exact codes + the chain body.

- [ ] **Step 3: Screenshot /pki in dark + light (auth-mocked headless)**

Use the auth-mocked headless-Chrome / Playwright approach used previously: intercept `GET /api/v1/auth/me` → `{ "user": { "id":"preview-admin","email":"p@e.com","display_name":"Preview Admin","role":"admin" } }` and `GET /api/v1/auth/status` → `{ "has_users": true }` (registered on the browser CONTEXT before navigation, 200 + `application/json`); let the `/graph/*` calls hit the real backend (they now exist) or stub them with sample nodes/edges. Navigate to `http://localhost:8443/pki`, wait for networkidle, screenshot `/tmp/pki_dark.png`. Then `localStorage.setItem('cf-theme','light')`, reload, screenshot `/tmp/pki_light.png`. Capture console messages.

- [ ] **Step 4: READ the screenshots + judge**

READ `/tmp/pki_dark.png` and `/tmp/pki_light.png`. Confirm:
- The force-directed graph canvas renders (nodes/edges, the GraphToolbar, the legend) — OR a coherent empty-graph state if the dev DB has no certs — NOT the "Failed to load landscape" error.
- No `/graph/*` 404 in the console (the de-moat worked).
- Dark = navy palette; light = readable light palette.
Report per-theme: renders? error gone? console 404s? Note: the dev DB likely has certs from Zeek ingest, so expect actual nodes. If a real visual defect is found (e.g. the graph throws, or light-mode unreadable), describe it precisely; fix only if it's a trivial token swap, else report for the controller to decide.

- [ ] **Step 5: Report (no commit)**

Report: docker build + ps state; the Step 2 curl codes (+ chain body); per-theme screenshot judgment; overall PASS/FAIL for "PKI Explorer renders, no graph 404s". Leave the container running for smoke-test.

---

## Notes for the implementer

- **Verbatim port + header only.** chain.go and graph.go are EE's exact code; the ONLY edit is prepending CE's Apache header. Do not refactor, rename, or "improve" — byte-parity with EE is intended (and the import path already matches).
- **Backend-only phase.** No frontend edits. Once the routes exist, CE's existing `/pki` page works unchanged.
- **`store.CertStore` vs `CryptoStore`:** the handler takes the narrower `CertStore`; `st` (CryptoStore) satisfies it via embedding. The test fake embeds `CertStore`.
- **Build gate after every task:** `go build ./...` green; Task 3 ends with `go test ./internal/api/...` green.
- **No push, no merge** without explicit user approval (per `docs/CLAUDE.md`). Branch is local.
- **Flaky bash:** redirect to a file and Read it if output is empty; never conclude from one blank result. Quote real `git log -1` output for SHAs.
```
