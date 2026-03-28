# Core Reports Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Reports page with four report types (Domain, CA, Compliance, Expiry Risk) backed by dedicated API endpoints, with print and CSV export.

**Architecture:** Report-specific store queries in a new `reports.go` file (keeps `postgres.go` from growing further). Report response types in `model/reports.go`. Four handler methods in `handler/reports.go`. Frontend renders reports as styled HTML tables with a shared toolbar for print/CSV. Reports page uses URL params to select report type and input.

**Tech Stack:** Go (pgx/PostgreSQL), SvelteKit 5, client-side CSV generation via Blob/download

**Spec:** `docs/superpowers/specs/2026-03-28-core-reports-design.md`

---

## File Map

### Backend

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/model/reports.go` | Create | Report response types for all 4 reports |
| `internal/store/store.go` | Modify | Add 4 report methods to CertStore interface |
| `internal/store/reports.go` | Create | Report query implementations |
| `internal/api/handler/reports.go` | Create | 4 report endpoint handlers |
| `internal/api/server.go` | Modify | Register report routes |

### Frontend

| File | Action | Responsibility |
|------|--------|----------------|
| `frontend/src/lib/api.ts` | Modify | Report types + API methods |
| `frontend/src/lib/components/reports/report-types.ts` | Create | Shared report constants |
| `frontend/src/lib/components/reports/ReportToolbar.svelte` | Create | Print + CSV buttons |
| `frontend/src/lib/components/reports/DomainReport.svelte` | Create | Domain report renderer |
| `frontend/src/lib/components/reports/CAReport.svelte` | Create | CA report renderer |
| `frontend/src/lib/components/reports/ComplianceReport.svelte` | Create | Compliance report renderer |
| `frontend/src/lib/components/reports/ExpiryReport.svelte` | Create | Expiry risk report renderer |
| `frontend/src/routes/reports/+page.svelte` | Create | Reports landing + report display |
| `frontend/src/routes/+layout.svelte` | Modify | Add Reports to nav |

---

## Task 1: Backend — Report Model Types

**Files:**
- Create: `internal/model/reports.go`

- [ ] **Step 1: Create reports.go with all response types**

```go
package model

// ── Domain Report ───────────────────────────────────────────────────────────

type DomainReportSummary struct {
	Domain        string `json:"domain"`
	TotalCerts    int    `json:"total_certs"`
	WorstGrade    string `json:"worst_grade"`
	Expired       int    `json:"expired"`
	Expiring30d   int    `json:"expiring_30d"`
	WildcardCount int    `json:"wildcard_count"`
}

type DomainReportCert struct {
	Fingerprint  string `json:"fingerprint"`
	SubjectCN    string `json:"subject_cn"`
	IssuerCN     string `json:"issuer_cn"`
	Grade        string `json:"grade"`
	KeyAlgorithm string `json:"key_algorithm"`
	KeySizeBits  int    `json:"key_size_bits"`
	NotAfter     string `json:"not_after"`
	DaysRemaining int   `json:"days_remaining"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	MatchType    string `json:"match_type"`
	Source       string `json:"source"`
}

type DomainReportDeployment struct {
	CertFingerprint string `json:"cert_fingerprint"`
	ServerName      string `json:"server_name"`
	ServerIP        string `json:"server_ip"`
	ServerPort      int    `json:"server_port"`
	TLSVersion      string `json:"tls_version"`
	Cipher          string `json:"cipher"`
	LastObserved    string `json:"last_observed"`
}

type DomainReportFinding struct {
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	Category      string `json:"category"`
	AffectedCount int    `json:"affected_count"`
	TotalDeduction int   `json:"total_deduction"`
}

type DomainReportWildcard struct {
	Fingerprint string   `json:"fingerprint"`
	SubjectCN   string   `json:"subject_cn"`
	SANs        []string `json:"sans"`
	Grade       string   `json:"grade"`
	NotAfter    string   `json:"not_after"`
}

type DomainReport struct {
	Summary     DomainReportSummary      `json:"summary"`
	Certificates []DomainReportCert      `json:"certificates"`
	Deployments  []DomainReportDeployment `json:"deployments"`
	Findings     []DomainReportFinding    `json:"findings"`
	Wildcards    []DomainReportWildcard   `json:"wildcards"`
}

// ── CA Report ───────────────────────────────────────────────────────────────

type CAReportIdentity struct {
	Fingerprint   string `json:"fingerprint"`
	SubjectCN     string `json:"subject_cn"`
	Organization  string `json:"organization"`
	KeyAlgorithm  string `json:"key_algorithm"`
	KeySizeBits   int    `json:"key_size_bits"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	Grade         string `json:"grade"`
	IsSelfSigned  bool   `json:"is_self_signed"`
	ChainPosition string `json:"chain_position"`
}

type CAReportSummary struct {
	TotalIssued       int            `json:"total_issued"`
	GradeDistribution map[string]int `json:"grade_distribution"`
	Expired           int            `json:"expired"`
	Expiring30d       int            `json:"expiring_30d"`
	Expiring90d       int            `json:"expiring_90d"`
	WildcardCount     int            `json:"wildcard_count"`
}

type CAReportCert struct {
	Fingerprint   string `json:"fingerprint"`
	SubjectCN     string `json:"subject_cn"`
	Grade         string `json:"grade"`
	KeyAlgorithm  string `json:"key_algorithm"`
	KeySizeBits   int    `json:"key_size_bits"`
	NotAfter      string `json:"not_after"`
	DaysRemaining int    `json:"days_remaining"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	Source        string `json:"source"`
	IsWildcard    bool   `json:"is_wildcard"`
}

type CAReportCrypto struct {
	KeyAlgorithms      map[string]int `json:"key_algorithms"`
	SignatureAlgorithms map[string]int `json:"signature_algorithms"`
	KeySizes           map[string]int `json:"key_sizes"`
}

type CAReportChainEntry struct {
	Fingerprint string `json:"fingerprint"`
	SubjectCN   string `json:"subject_cn"`
	NodeType    string `json:"type"`
}

type CAReportChain struct {
	IssuedBy  *CAReportChainEntry  `json:"issued_by"`
	IssuesTo  []CAReportChainEntry `json:"issues_to"`
}

type CAReport struct {
	CA           CAReportIdentity    `json:"ca"`
	Summary      CAReportSummary     `json:"summary"`
	Certificates []CAReportCert      `json:"certificates"`
	Crypto       CAReportCrypto      `json:"crypto"`
	Chain        CAReportChain       `json:"chain"`
	Findings     []DomainReportFinding `json:"findings"`
}

// ── Compliance Report ───────────────────────────────────────────────────────

type ComplianceReportIssue struct {
	Fingerprint string `json:"fingerprint"`
	SubjectCN   string `json:"subject_cn"`
	Grade       string `json:"grade"`
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Remediation string `json:"remediation"`
}

type ComplianceReportPriority struct {
	RuleID        string `json:"rule_id"`
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	AffectedCount int    `json:"affected_count"`
	TotalDeduction int   `json:"total_deduction"`
	Remediation   string `json:"remediation"`
}

type ComplianceReportNonAgile struct {
	Fingerprint  string `json:"fingerprint"`
	SubjectCN    string `json:"subject_cn"`
	IssuerCN     string `json:"issuer_cn"`
	ValidityDays int    `json:"validity_days"`
	KeyAlgorithm string `json:"key_algorithm"`
	Source       string `json:"source"`
}

type ComplianceReportWildcard struct {
	Fingerprint string `json:"fingerprint"`
	SubjectCN   string `json:"subject_cn"`
	SANCount    int    `json:"san_count"`
	Grade       string `json:"grade"`
	NotAfter    string `json:"not_after"`
	IssuerCN    string `json:"issuer_cn"`
}

type ComplianceReport struct {
	ComplianceScore float64                    `json:"compliance_score"`
	TotalCerts      int                        `json:"total_certs"`
	Compliant       int                        `json:"compliant"`
	NonCompliant    int                        `json:"non_compliant"`
	CriticalIssues  []ComplianceReportIssue    `json:"critical_issues"`
	Priorities      []ComplianceReportPriority `json:"remediation_priorities"`
	NonAgile        []ComplianceReportNonAgile `json:"non_agile"`
	Wildcards       []ComplianceReportWildcard `json:"wildcards"`
	ByCategory      map[string]int             `json:"by_category"`
}

// ── Expiry Risk Report ──────────────────────────────────────────────────────

type ExpiryReportCert struct {
	Fingerprint   string `json:"fingerprint"`
	SubjectCN     string `json:"subject_cn"`
	IssuerCN      string `json:"issuer_cn"`
	Grade         string `json:"grade"`
	DaysRemaining int    `json:"days_remaining"`
	SubjectOrg    string `json:"subject_org"`
	SubjectOU     string `json:"subject_ou"`
	KeyAlgorithm  string `json:"key_algorithm"`
	Source        string `json:"source"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
}

type ExpiryReportByIssuer struct {
	IssuerOrg  string `json:"issuer_org"`
	Count      int    `json:"count"`
	WorstGrade string `json:"worst_grade"`
}

type ExpiryReportByOwner struct {
	SubjectOrg string `json:"subject_org"`
	SubjectOU  string `json:"subject_ou"`
	Count      int    `json:"count"`
}

type ExpiryReportGhost struct {
	Fingerprint    string `json:"fingerprint"`
	SubjectCN      string `json:"subject_cn"`
	IssuerCN       string `json:"issuer_cn"`
	ExpiredDaysAgo int    `json:"expired_days_ago"`
	LastObserved   string `json:"last_observed"`
	ServerName     string `json:"server_name"`
	ServerIP       string `json:"server_ip"`
}

type ExpiryReportDeployment struct {
	ServerName    string `json:"server_name"`
	ServerIP      string `json:"server_ip"`
	ServerPort    int    `json:"server_port"`
	CertCN        string `json:"cert_cn"`
	DaysRemaining int    `json:"days_remaining"`
}

type ExpiryReport struct {
	Days            int                      `json:"days"`
	TotalExpiring   int                      `json:"total_expiring"`
	Certificates    []ExpiryReportCert       `json:"certificates"`
	ByIssuer        []ExpiryReportByIssuer   `json:"by_issuer"`
	ByOwner         []ExpiryReportByOwner    `json:"by_owner"`
	AlreadyExpired  []ExpiryReportGhost      `json:"already_expired"`
	DeploymentsAtRisk []ExpiryReportDeployment `json:"deployments_at_risk"`
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/model/reports.go
git commit -m "feat(model): add report response types for domain, CA, compliance, expiry"
```

---

## Task 2: Backend — Store Interface + Report Queries

**Files:**
- Modify: `internal/store/store.go`
- Create: `internal/store/reports.go`

- [ ] **Step 1: Add 4 report methods to CertStore interface in store.go**

Add in a new `// Reports` section:

```go
	// Reports
	GetDomainReport(ctx context.Context, domain string) (*model.DomainReport, error)
	GetCAReport(ctx context.Context, fingerprint string, issuerCN string) (*model.CAReport, error)
	GetComplianceReport(ctx context.Context) (*model.ComplianceReport, error)
	GetExpiryReport(ctx context.Context, days int) (*model.ExpiryReport, error)
```

- [ ] **Step 2: Create reports.go with all 4 query implementations**

Create `internal/store/reports.go`. This file holds all report queries on `PostgresStore`. The file needs these imports: `context`, `encoding/json`, `fmt`, `strings`, `time`, `github.com/cyberflag-ai/cipherflag/internal/model`.

The implementations use the same pgx patterns as the rest of the store — `s.pool.Query()`, `rows.Scan()`, etc.

Due to the size of this file (4 report queries, each with multiple sub-queries), the implementer should write each report method following these patterns:

**GetDomainReport:**
- Query certs where `subject_cn = domain` OR `subject_cn LIKE '*.{parent}'` OR SAN JSONB contains domain (using `EXISTS (SELECT 1 FROM jsonb_array_elements_text(subject_alt_names) san WHERE san ILIKE '%{domain}%')`)
- For each matched cert, join health_reports for grade
- Separate query for deployments: join observations on matched cert fingerprints
- Aggregate findings from health_reports JSONB
- Filter wildcards from matched certs

**GetCAReport:**
- Look up the CA cert by fingerprint or issuer_cn
- Query all certs where `issuer_cn = ca.subject_cn`
- Aggregate grade distribution, expiry counts, crypto breakdown
- Chain: find who issued this CA (by issuer_cn match), find what it issues to

**GetComplianceReport:**
- Query all health_reports with findings
- Parse findings JSONB to extract critical/high issues
- Aggregate by rule_id for priority list
- Query certs with AGI-001 findings for non-agile list
- Query wildcard certs (CN starts with `*.`)

**GetExpiryReport:**
- Query certs where `not_after BETWEEN NOW() AND NOW() + interval '{days} days'`
- Group by issuer_org and subject_org/ou
- Ghost certs: expired but observed within last 30 days
- Deployments at risk: join observations for expiring certs

Each method returns initialized empty slices (not nil) for JSON serialization.

Use `to_char(date, 'YYYY-MM-DD')` for date formatting in SQL (same pattern as expiry forecast).

- [ ] **Step 3: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add internal/store/store.go internal/store/reports.go
git commit -m "feat(store): implement domain, CA, compliance, and expiry report queries"
```

---

## Task 3: Backend — Report Handlers + Routes

**Files:**
- Create: `internal/api/handler/reports.go`
- Modify: `internal/api/server.go`

- [ ] **Step 1: Create reports.go handler**

```go
package handler

import (
	"net/http"
	"strconv"

	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type ReportsHandler struct {
	store store.CertStore
}

func NewReportsHandler(s store.CertStore) *ReportsHandler {
	return &ReportsHandler{store: s}
}

func (h *ReportsHandler) DomainReport(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("q")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'q' is required")
		return
	}

	report, err := h.store.GetDomainReport(r.Context(), domain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *ReportsHandler) CAReport(w http.ResponseWriter, r *http.Request) {
	fp := r.URL.Query().Get("fingerprint")
	issuerCN := r.URL.Query().Get("issuer_cn")
	if fp == "" && issuerCN == "" {
		writeError(w, http.StatusBadRequest, "either 'fingerprint' or 'issuer_cn' parameter is required")
		return
	}

	report, err := h.store.GetCAReport(r.Context(), fp, issuerCN)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *ReportsHandler) ComplianceReport(w http.ResponseWriter, r *http.Request) {
	report, err := h.store.GetComplianceReport(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *ReportsHandler) ExpiryReport(w http.ResponseWriter, r *http.Request) {
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}

	report, err := h.store.GetExpiryReport(r.Context(), days)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}
```

- [ ] **Step 2: Register routes in server.go**

Create the handler and add routes inside the `r.Route("/api/v1", ...)` block:

```go
	reportsH := handler.NewReportsHandler(st)
```

```go
		// Reports
		r.Get("/reports/domain", reportsH.DomainReport)
		r.Get("/reports/ca", reportsH.CAReport)
		r.Get("/reports/compliance", reportsH.ComplianceReport)
		r.Get("/reports/expiry", reportsH.ExpiryReport)
```

- [ ] **Step 3: Verify compilation**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add internal/api/handler/reports.go internal/api/server.go
git commit -m "feat(api): add domain, CA, compliance, and expiry report endpoints"
```

---

## Task 4: Frontend — API Types + Report Types + Toolbar

**Files:**
- Modify: `frontend/src/lib/api.ts`
- Create: `frontend/src/lib/components/reports/report-types.ts`
- Create: `frontend/src/lib/components/reports/ReportToolbar.svelte`

- [ ] **Step 1: Add report types and API methods to api.ts**

Add report response types before the `export const api = {` line. These mirror the Go types. Due to the number of types, the implementer should add interfaces for: `DomainReport`, `DomainReportSummary`, `DomainReportCert`, `DomainReportDeployment`, `DomainReportFinding`, `DomainReportWildcard`, `CAReport`, `CAReportIdentity`, `CAReportSummary`, `CAReportCert`, `CAReportCrypto`, `CAReportChain`, `CAReportChainEntry`, `ComplianceReport`, `ComplianceReportIssue`, `ComplianceReportPriority`, `ComplianceReportNonAgile`, `ComplianceReportWildcard`, `ExpiryReport`, `ExpiryReportCert`, `ExpiryReportByIssuer`, `ExpiryReportByOwner`, `ExpiryReportGhost`, `ExpiryReportDeployment`.

Add 4 API methods:
```typescript
	getDomainReport: (domain: string) => fetchJSON<DomainReport>(`/reports/domain?q=${encodeURIComponent(domain)}`),
	getCAReport: (params: string) => fetchJSON<CAReport>(`/reports/ca?${params}`),
	getComplianceReport: () => fetchJSON<ComplianceReport>('/reports/compliance'),
	getExpiryReport: (days: number) => fetchJSON<ExpiryReport>(`/reports/expiry?days=${days}`),
```

- [ ] **Step 2: Create report-types.ts**

```typescript
export const GRADE_COLORS: Record<string, string> = {
	'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
	'C': '#eab308', 'D': '#f97316', 'F': '#ef4444', '?': '#64748b',
};

export const SEVERITY_COLORS: Record<string, string> = {
	'Critical': '#ef4444', 'High': '#f97316', 'Medium': '#eab308',
	'Low': '#64748b', 'Info': '#94a3b8',
};

export function gradeColor(grade: string): string {
	return GRADE_COLORS[grade] ?? '#64748b';
}

export function severityColor(severity: string): string {
	return SEVERITY_COLORS[severity] ?? '#64748b';
}

export function exportCSV(headers: string[], rows: string[][], filename: string): void {
	const csvContent = [
		headers.join(','),
		...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
	].join('\n');

	const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
	const link = document.createElement('a');
	link.href = URL.createObjectURL(blob);
	link.download = filename;
	link.click();
	URL.revokeObjectURL(link.href);
}
```

- [ ] **Step 3: Create ReportToolbar.svelte**

```svelte
<script lang="ts">
	interface Props {
		title: string;
		onPrint: () => void;
		onExportCSV: () => void;
	}

	let { title, onPrint, onExportCSV }: Props = $props();
</script>

<div class="report-toolbar">
	<div class="toolbar-left">
		<a href="/reports" class="back-link">&larr; Reports</a>
		<h2>{title}</h2>
	</div>
	<div class="toolbar-right">
		<button class="toolbar-btn" onclick={onExportCSV}>Download CSV</button>
		<button class="toolbar-btn" onclick={onPrint}>Print</button>
	</div>
</div>

<style>
	.report-toolbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0.75rem 1.5rem;
		border-bottom: 1px solid var(--cf-border);
		background: var(--cf-bg-secondary);
		flex-shrink: 0;
	}

	.toolbar-left { display: flex; align-items: center; gap: 1rem; }

	.back-link {
		font-size: 0.8rem;
		color: var(--cf-accent);
		text-decoration: none;
	}

	.back-link:hover { text-decoration: underline; }

	h2 { margin: 0; font-size: 1rem; font-weight: 700; color: var(--cf-text-primary); }

	.toolbar-right { display: flex; gap: 0.5rem; }

	.toolbar-btn {
		padding: 0.375rem 0.75rem;
		font-size: 0.8rem;
		font-weight: 500;
		background: rgba(56, 189, 248, 0.1);
		border: 1px solid rgba(56, 189, 248, 0.2);
		border-radius: 6px;
		color: var(--cf-accent);
		cursor: pointer;
		transition: all 0.15s;
	}

	.toolbar-btn:hover { background: rgba(56, 189, 248, 0.2); }

	@media print {
		.report-toolbar { display: none; }
	}
</style>
```

- [ ] **Step 4: Commit**

```bash
mkdir -p frontend/src/lib/components/reports
git add frontend/src/lib/api.ts frontend/src/lib/components/reports/
git commit -m "feat(frontend): add report API types, shared utilities, and toolbar component"
```

---

## Task 5: Frontend — Domain Report Component

**Files:**
- Create: `frontend/src/lib/components/reports/DomainReport.svelte`

- [ ] **Step 1: Create DomainReport.svelte**

The component receives a domain string prop, loads data via `api.getDomainReport(domain)`, and renders 5 sections: summary header, certificates table, deployments table, findings list, and wildcard coverage. Each section has a heading and a data table. Uses `gradeColor()` and `severityColor()` from report-types.ts. The `onExportCSV` callback builds CSV from the certificates array.

Key sections:
- Summary: domain, total certs, worst grade, expired, expiring <30d, wildcard count
- Certificates table: sortable by days_remaining, shows match_type badge
- Deployments: grouped by cert fingerprint, shows server details
- Findings: severity-colored rows with affected count
- Wildcards: CN, SAN list, grade, expiry

Print styles: hide nav, show all sections. Tables get `page-break-inside: avoid`.

- [ ] **Step 2: Commit**

```bash
git add frontend/src/lib/components/reports/DomainReport.svelte
git commit -m "feat(frontend): add Domain Certificate Report component"
```

---

## Task 6: Frontend — CA Report Component

**Files:**
- Create: `frontend/src/lib/components/reports/CAReport.svelte`

- [ ] **Step 1: Create CAReport.svelte**

Similar pattern to DomainReport. Receives `fingerprint` or `issuerCN` prop. Loads via `api.getCAReport(params)`. Renders: CA identity card, summary stats, certificates table, crypto breakdown (3 mini-tables for key algo / sig algo / key size), chain context, and findings.

- [ ] **Step 2: Commit**

```bash
git add frontend/src/lib/components/reports/CAReport.svelte
git commit -m "feat(frontend): add CA Authority Report component"
```

---

## Task 7: Frontend — Compliance Report Component

**Files:**
- Create: `frontend/src/lib/components/reports/ComplianceReport.svelte`

- [ ] **Step 1: Create ComplianceReport.svelte**

No input needed. Loads via `api.getComplianceReport()`. Renders: compliance score banner (X% compliant), critical issues table, remediation priority list, non-agile certificates table, wildcard inventory, category breakdown.

The compliance score banner should be color-coded: green (>90%), yellow (70-90%), orange (50-70%), red (<50%).

- [ ] **Step 2: Commit**

```bash
git add frontend/src/lib/components/reports/ComplianceReport.svelte
git commit -m "feat(frontend): add Crypto Compliance Report component"
```

---

## Task 8: Frontend — Expiry Risk Report Component

**Files:**
- Create: `frontend/src/lib/components/reports/ExpiryReport.svelte`

- [ ] **Step 1: Create ExpiryReport.svelte**

Receives `days` prop (default 30). Loads via `api.getExpiryReport(days)`. Renders: urgency banner, expiry table sorted by days_remaining ascending, by-issuer grouped counts, by-owner grouped counts, already-expired ghost certs section, deployments at risk.

Days selector: 3 buttons (30/60/90) that reload the report.

- [ ] **Step 2: Commit**

```bash
git add frontend/src/lib/components/reports/ExpiryReport.svelte
git commit -m "feat(frontend): add Expiry Risk Report component"
```

---

## Task 9: Frontend — Reports Page + Nav

**Files:**
- Create: `frontend/src/routes/reports/+page.svelte`
- Modify: `frontend/src/routes/+layout.svelte`

- [ ] **Step 1: Create reports page**

The page reads `?type=` and `?q=`/`?days=`/`?fp=` from the URL. If no type is set, show the landing page with 4 report cards. If a type is set, show the corresponding report component with the toolbar.

Landing page cards:
- Domain Certificate Report — text input for domain, "Generate" button
- CA Authority Report — dropdown of known CAs (fetched from `/stats/issuers`), "Generate" button
- Crypto Compliance Report — no input, just "Generate" button
- Expiry Risk Report — 30/60/90 day buttons

Clicking "Generate" updates the URL params and renders the report.

- [ ] **Step 2: Add Reports to nav in layout.svelte**

Add between Upload and Analytics:
```svelte
<a href="/reports" class="nav-link" class:active={isActive('/reports')}>Reports</a>
```

- [ ] **Step 3: Verify frontend compiles**

```bash
cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/routes/reports/ frontend/src/routes/+layout.svelte
git commit -m "feat(frontend): add Reports page with landing cards and 4 report types"
```

---

## Task 10: Integration Verification

**Files:** None

- [ ] **Step 1: Verify Go build**

```bash
cd /Users/Erik/projects/cipherflag && go build ./...
```

- [ ] **Step 2: Verify frontend**

```bash
cd /Users/Erik/projects/cipherflag/frontend && npx svelte-check
```

- [ ] **Step 3: Test report endpoints**

```bash
curl -s "http://localhost:8443/api/v1/reports/domain?q=amazon" | python3 -m json.tool | head -20
curl -s "http://localhost:8443/api/v1/reports/compliance" | python3 -m json.tool | head -20
curl -s "http://localhost:8443/api/v1/reports/expiry?days=90" | python3 -m json.tool | head -20
```

- [ ] **Step 4: Final commit**

```bash
git status
```
