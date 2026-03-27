# Analytics: Chain Flow & Ownership

Replaces the current analytics page with a tabbed layout. First two tabs: a D3 Sankey diagram showing certificate chain flow (Root → Intermediate → Leaf), and an ownership view combining certificate metadata (Issuer Org × Subject OU) with deployment-based grouping (from observations).

## Scope

**In scope (this spec):**
- Sankey: Certificate Chain Flow tab
- Ownership: Org Distribution + Deployment tab
- Tabbed page structure with URL-synced tab selection

**Deferred to future specs:**
- Crypto Posture tab
- Expiry Forecast tab (richer version)
- Discovery Source Lineage tab

## Architecture

### New API Endpoints

**`GET /api/v1/stats/chain-flow`**

Returns Sankey-compatible flow data: Root CAs → Intermediate CAs → leaf aggregates.

Leaf certificates are aggregated into one synthetic node per intermediate CA (not individual certs). This keeps the Sankey readable at enterprise scale.

Response shape:
```json
{
  "nodes": [
    {
      "id": "fp-abc123",
      "label": "DigiCert Global Root G2",
      "type": "root",
      "cert_count": 1247,
      "grade": "A",
      "expired_count": 4
    },
    {
      "id": "fp-def456",
      "label": "GeoTrust RSA CA 2018",
      "type": "intermediate",
      "cert_count": 342,
      "grade": "B",
      "expired_count": 12
    },
    {
      "id": "leaves-fp-def456",
      "label": "342 leaf certificates",
      "type": "leaf-aggregate",
      "cert_count": 342,
      "grade": "B",
      "expired_count": 12
    }
  ],
  "links": [
    {
      "source": "fp-abc123",
      "target": "fp-def456",
      "value": 342,
      "worst_grade": "B",
      "expired_count": 4
    },
    {
      "source": "fp-def456",
      "target": "leaves-fp-def456",
      "value": 342,
      "worst_grade": "B",
      "expired_count": 12
    }
  ]
}
```

Node IDs: CA nodes use their fingerprint prefixed with `fp-`. Leaf aggregate nodes use `leaves-` + the parent intermediate's fingerprint.

Root CAs that directly issue leaf certs (no intermediate) get a direct Root → leaf-aggregate link.

**`GET /api/v1/stats/ownership`**

Groups certificates by issuer organization and subject organizational unit.

Response shape:
```json
{
  "groups": [
    {
      "issuer_org": "DigiCert Inc",
      "subject_ou": "Platform Engineering",
      "cert_count": 87,
      "expired_count": 3,
      "expiring_30d_count": 5,
      "worst_grade": "B",
      "avg_score": 82.4
    },
    {
      "issuer_org": "DigiCert Inc",
      "subject_ou": "",
      "cert_count": 142,
      "expired_count": 8,
      "worst_grade": "D",
      "avg_score": 61.2
    }
  ],
  "total_certs": 1090,
  "total_issuers": 12,
  "total_ous": 8
}
```

Empty `subject_ou` values are returned as empty string — the frontend renders these as "Unspecified".

**`GET /api/v1/stats/deployment`**

Groups certificates by deployment location, derived from the observations table. Extracts the base domain from `server_name` (e.g., `api.payments.acme.com` → `payments.acme.com`) and groups by it.

Response shape:
```json
{
  "groups": [
    {
      "domain": "payments.acme.com",
      "cert_count": 23,
      "unique_ips": 8,
      "expired_count": 1,
      "worst_grade": "A",
      "avg_score": 94.2
    },
    {
      "domain": "api.acme.com",
      "cert_count": 15,
      "unique_ips": 4,
      "expired_count": 0,
      "worst_grade": "A+",
      "avg_score": 98.1
    }
  ],
  "total_observed_certs": 412,
  "total_domains": 34
}
```

Only certificates with at least one observation appear. Certs from manual upload without observations are excluded from this view. Domain extraction: strip the leftmost subdomain label if 3+ labels exist, otherwise use the full server_name.

### Backend Implementation

All three endpoints are served from `internal/api/handler/stats.go`. New store methods:

- `GetChainFlow(ctx) (*model.ChainFlowResponse, error)` — queries all CAs, builds root→intermediate links and intermediate→leaf-aggregate links with cert counts and grade data.
- `GetOwnershipStats(ctx) (*model.OwnershipResponse, error)` — `GROUP BY issuer_org, subject_ou` with aggregate stats joined to health_reports.
- `GetDeploymentStats(ctx) (*model.DeploymentResponse, error)` — joins certificates → observations, groups by extracted domain from server_name, counts unique IPs.

### New Model Types

Added to `internal/model/` (new file `analytics.go`):

```go
// ChainFlowNode represents a node in the Sankey chain flow diagram.
type ChainFlowNode struct {
    ID           string `json:"id"`
    Label        string `json:"label"`
    NodeType     string `json:"type"` // "root", "intermediate", "leaf-aggregate"
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

## Frontend Design

### Page Structure

The `/analytics` route is replaced entirely. The new page uses a tabbed layout.

**Tab bar:** "Chain Flow" | "Ownership"

Tab selection syncs to the URL via query parameter (`/analytics?tab=chain-flow`). Default tab: Chain Flow.

### Tab 1: Chain Flow (Sankey)

Full-width D3 Sankey diagram. Three columns left to right:

**Columns:**
1. Root CAs (left)
2. Intermediate CAs (middle)
3. Leaf aggregates (right) — one node per intermediate, labeled "{count} leaf certificates"

**Visual encoding:**
- Link width = cert count (proportional)
- Link color = worst grade in that flow path, using the existing grade color palette (A+/A green, B lime, C yellow, D orange, F red)
- Link opacity = 0.5 default, 0.8 on hover
- Node height = proportional to total cert flow through that node
- Node color = grade color, filled at 20% opacity with grade-colored left border

**Interactions:**
- Hover link → tooltip: source label, target label, cert count, expired count, worst grade
- Hover node → tooltip: CA name, total cert count, grade, expired count
- Click CA node → navigates to PKI Explorer with that node selected (opens detail panel)
- Click leaf-aggregate node → navigates to certificates list filtered by that intermediate's issuer_cn

**Layout:** `d3-sankey` handles positioning. Minimum node padding of 8px. Diagram fills available width with 60px left/right padding. Height auto-scales based on node count, minimum 400px, maximum 700px.

### Tab 2: Ownership

Two stacked sections within the tab.

**Section A: "By Certificate Metadata" — Treemap**

A D3 treemap visualization using `d3-hierarchy` + `d3-treemap`.

- **Root level:** Issuer Organization
- **Nested level:** Subject OU (where populated)
- Rectangle size = cert count
- Rectangle color = worst grade color
- Label inside rectangle: org/OU name + cert count
- Small rectangles (< 3% of total area) get no label, only tooltip
- Hover → tooltip: full org name, OU name, cert count, expired count, avg score
- Click → navigates to certificates list filtered by that issuer_org (and subject_ou if clicking a nested rect)

Groups with empty Subject OU render as "Unspecified" within their issuer org rectangle.

**Section B: "By Deployment" — Bar Chart**

Horizontal bar chart showing top 20 domains by cert count.

- Bar length = cert count
- Bar color = worst grade color for that domain
- Each bar shows: domain name, cert count, unique IP count, worst grade badge
- Sorted by cert count descending
- If no observation data exists, shows a message: "No deployment data available. Certificates discovered via passive or active scanning will appear here."
- Hover → tooltip: domain, cert count, unique IPs, expired count, avg score

### Component Structure

```
frontend/src/routes/analytics/
  +page.svelte                    — tab shell, URL sync, data loading

frontend/src/lib/components/analytics/
  ChainFlowTab.svelte             — Sankey wrapper, loads chain-flow data
  SankeyChart.svelte              — D3 sankey rendering
  OwnershipTab.svelte             — Ownership wrapper, loads both datasets
  OwnershipTreemap.svelte         — D3 treemap rendering
  DeploymentChart.svelte          — D3 horizontal bar chart
  analytics-types.ts              — TypeScript types
```

### Frontend API Types & Methods

Added to `frontend/src/lib/api.ts`:

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

API methods:
```typescript
getChainFlow: () => fetchJSON<ChainFlowResponse>('/stats/chain-flow'),
getOwnership: () => fetchJSON<OwnershipResponse>('/stats/ownership'),
getDeployment: () => fetchJSON<DeploymentResponse>('/stats/deployment'),
```

## Dependencies

New npm packages:
- `d3-sankey` — Sankey layout algorithm
- `@types/d3-sankey` — TypeScript types
- `d3-hierarchy` — treemap layout (may already be available via d3-force transitive deps, verify before installing)

D3 packages already installed: d3-force, d3-zoom, d3-selection, d3-transition, d3-drag.

No new Go dependencies.

## What Gets Removed

- The current analytics page content (summary cards, grade distribution bar, source list) is replaced entirely
- The dashboard (`/`) retains its own summary stats — no changes to the dashboard

## Out of Scope

- Crypto Posture tab (future spec)
- Expiry Forecast tab (future spec)
- Discovery Source Lineage tab (future spec)
- Manual ownership tagging / stakeholder assignment
- Geographic distribution
- Certificates list page changes (stays as-is — it's a useful drill-down target)
