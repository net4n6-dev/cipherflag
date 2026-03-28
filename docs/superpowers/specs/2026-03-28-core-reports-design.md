# Core Reports

A dedicated Reports page with four report types: Domain Certificate, CA Authority, Crypto Compliance, and Expiry Risk. Reports render as interactive HTML pages with Print and Download CSV buttons. Each report is URL-addressable for sharing.

## Scope

**In scope:**
- Reports landing page with 4 report cards
- Domain Certificate Report (domain input, wildcard resolution, observations)
- CA Authority Report (CA selection, issued cert inventory, crypto breakdown)
- Crypto Compliance Report (full inventory scan, remediation priority)
- Expiry Risk Report (time window, by issuer/owner, ghost certs)
- Print and CSV download for each report
- Current snapshot + first_seen/last_seen timeline context

**Out of scope (Sub-project B):**
- Cloud Provider / Infrastructure reports
- Network Segment / CIDR reports
- Endpoint reports
- Issuer concentration / key reuse fleet-level findings
- Printable analytics summaries

## Page Structure

New "Reports" nav item in the top bar.

**URL structure:** `/reports?type={type}&q={query}`
- `/reports` — landing page with 4 report cards
- `/reports?type=domain&q=acme.com`
- `/reports?type=ca&q=DigiCert+Global+Root+G2` or `/reports?type=ca&fp={fingerprint}`
- `/reports?type=compliance`
- `/reports?type=expiry&days=30`

Reports are rendered in-page below a toolbar with Print and Download CSV buttons.

## Report 1: Domain Certificate Report

**Input:** Domain name (e.g., `acme.com` or `api.payments.acme.com`)

**Matching logic:**
- Exact CN match
- SAN match (ILIKE `%{domain}%` on the subject_alt_names JSONB array)
- Wildcard resolution: if domain is `api.acme.com`, match certs with CN/SAN `*.acme.com`
- Subdomain discovery: if domain is `acme.com`, also match `*.acme.com`, `api.acme.com`, `payments.acme.com`, etc.

**Report sections:**

1. **Summary header** — domain queried, total certs found, worst grade, expired count, expiring <30d count

2. **Matching certificates table** — sortable columns:
   - CN, Issuer, Grade, Key Algorithm, Key Size, Not After, Days Remaining, First Seen, Last Seen, Match Type (exact/wildcard/SAN/subdomain), Source

3. **Deployment map** — servers where these certs were observed:
   - Server Name, Server IP, Port, TLS Version, Cipher, Last Observed
   - Grouped by cert fingerprint

4. **Health findings** — aggregate findings across all matched certs, sorted by severity:
   - Finding title, severity, category, affected cert count, deduction

5. **Wildcard coverage** — wildcard certs that cover this domain:
   - CN, full SAN list, grade, expiry

**API endpoint:** `GET /api/v1/reports/domain?q={domain}`

Response:
```json
{
  "domain": "acme.com",
  "summary": {
    "total_certs": 12,
    "worst_grade": "C",
    "expired": 2,
    "expiring_30d": 1,
    "wildcard_count": 3
  },
  "certificates": [
    {
      "fingerprint": "abc...",
      "subject_cn": "api.acme.com",
      "issuer_cn": "DigiCert SHA2",
      "grade": "A",
      "key_algorithm": "RSA",
      "key_size_bits": 2048,
      "not_after": "2026-09-15",
      "days_remaining": 171,
      "first_seen": "2026-01-10",
      "last_seen": "2026-03-28",
      "match_type": "subdomain",
      "source": "zeek_passive"
    }
  ],
  "deployments": [
    {
      "cert_fingerprint": "abc...",
      "server_name": "api.acme.com",
      "server_ip": "10.0.1.42",
      "server_port": 443,
      "tls_version": "TLS 1.2",
      "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "last_observed": "2026-03-28T10:00:00Z"
    }
  ],
  "findings": [
    {
      "title": "RSA key is 2048 bits",
      "severity": "Low",
      "category": "key_strength",
      "affected_count": 8,
      "total_deduction": 24
    }
  ],
  "wildcards": [
    {
      "fingerprint": "def...",
      "subject_cn": "*.acme.com",
      "sans": ["*.acme.com", "acme.com"],
      "grade": "A",
      "not_after": "2026-12-01"
    }
  ]
}
```

## Report 2: CA Authority Report

**Input:** CA fingerprint or issuer CN (frontend provides a dropdown of known CAs)

**Report sections:**

1. **CA identity** — CN, organization, country, key algorithm/size, validity dates, grade, self-signed status, chain position (root/intermediate)

2. **Issued certificates summary** — total count, grade distribution (A+/A/B/C/D/F), expired count, expiring <30d, expiring <90d

3. **Certificate table** — all certs issued by this CA:
   - CN, Grade, Key Algo, Key Size, Not After, Days Remaining, First Seen, Last Seen, Source, Wildcard (yes/no)

4. **Crypto breakdown** — for certs issued by this CA:
   - Key algorithm distribution (RSA/ECDSA/Ed25519 with counts)
   - Signature algorithm distribution
   - Key size distribution

5. **Chain context** — who issued this CA, what intermediates/leaves it issues to (fingerprints + CNs)

6. **Health findings** — aggregate findings for all certs issued by this CA, sorted by severity

**API endpoint:** `GET /api/v1/reports/ca?issuer_cn={cn}` or `GET /api/v1/reports/ca?fingerprint={fp}`

Response:
```json
{
  "ca": {
    "fingerprint": "abc...",
    "subject_cn": "DigiCert Global Root G2",
    "organization": "DigiCert Inc",
    "key_algorithm": "RSA",
    "key_size_bits": 2048,
    "not_before": "2013-08-01",
    "not_after": "2038-01-15",
    "grade": "A+",
    "is_self_signed": true,
    "chain_position": "root"
  },
  "summary": {
    "total_issued": 342,
    "grade_distribution": {"A+": 100, "A": 150, "B": 60, "C": 20, "D": 8, "F": 4},
    "expired": 12,
    "expiring_30d": 5,
    "expiring_90d": 18,
    "wildcard_count": 15
  },
  "certificates": [ ... ],
  "crypto": {
    "key_algorithms": {"RSA": 280, "ECDSA": 62},
    "signature_algorithms": {"SHA256WithRSA": 290, "ECDSAWithSHA256": 52},
    "key_sizes": {"2048": 200, "4096": 80, "256": 62}
  },
  "chain": {
    "issued_by": { "fingerprint": "...", "subject_cn": "..." },
    "issues_to": [
      { "fingerprint": "...", "subject_cn": "...", "type": "intermediate" }
    ]
  },
  "findings": [ ... ]
}
```

## Report 3: Crypto Compliance Report

**Input:** None (runs against full inventory)

**Report sections:**

1. **Compliance score** — percentage of certs with zero critical/high findings in key_strength, signature, wildcard, and agility categories. "82% compliant (934 of 1,136 certs)"

2. **Critical issues table** — all certs with critical or high findings, columns:
   - CN, Fingerprint, Grade, Finding, Severity, Category, Remediation

3. **Remediation priority list** — findings aggregated by rule, sorted by severity then affected count:
   - Rule ID, Title, Severity, Affected Certs, Total Deduction, Remediation

4. **Non-agile certificates** — certs flagged AGI-001 (manual issuance, >1yr validity):
   - CN, Issuer, Validity Days, Key Algo, Source

5. **Wildcard inventory** — all wildcard certs:
   - CN, SAN Count, Grade, Expiry, Issuer

6. **Summary metrics** — total certs, compliant count, non-compliant count, breakdown by category (key_strength, signature, wildcard, agility, chain, revocation, transparency)

**API endpoint:** `GET /api/v1/reports/compliance`

Response:
```json
{
  "compliance_score": 82.3,
  "total_certs": 1136,
  "compliant": 934,
  "non_compliant": 202,
  "critical_issues": [ ... ],
  "remediation_priorities": [
    {
      "rule_id": "SIG-001",
      "title": "Certificate uses SHA-1 signature",
      "severity": "Critical",
      "affected_count": 3,
      "total_deduction": 150,
      "remediation": "Reissue certificate with SHA-256 or stronger signature."
    }
  ],
  "non_agile": [ ... ],
  "wildcards": [ ... ],
  "by_category": {
    "key_strength": 45,
    "signature": 3,
    "wildcard": 28,
    "agility": 120,
    "chain": 6,
    "revocation": 15,
    "transparency": 42
  }
}
```

## Report 4: Expiry Risk Report

**Input:** Time window in days (default 30, options: 30/60/90)

**Report sections:**

1. **Urgency banner** — "47 certificates expiring in the next 30 days"

2. **Expiry table** — sorted by not_after ascending:
   - CN, Issuer, Grade, Days Remaining, Subject Org, Subject OU, Key Algo, Source, First Seen, Last Seen

3. **By issuer** — grouped count per issuer organization:
   - Issuer Org, Expiring Count, Worst Grade

4. **By owner** — grouped count per subject org/OU:
   - Subject Org, Subject OU, Expiring Count

5. **Already expired** — certs past not_after that were observed within the last 30 days (ghost certs still in use):
   - CN, Issuer, Expired Since, Last Observed, Server Name, Server IP

6. **Deployment at risk** — servers hosting expiring certs:
   - Server Name, Server IP, Port, Cert CN, Days Remaining

**API endpoint:** `GET /api/v1/reports/expiry?days=30`

Response:
```json
{
  "days": 30,
  "total_expiring": 47,
  "certificates": [ ... ],
  "by_issuer": [
    { "issuer_org": "DigiCert Inc", "count": 12, "worst_grade": "B" }
  ],
  "by_owner": [
    { "subject_org": "Acme Corp", "subject_ou": "Engineering", "count": 8 }
  ],
  "already_expired": [
    {
      "fingerprint": "...",
      "subject_cn": "old.acme.com",
      "issuer_cn": "DigiCert SHA2",
      "expired_days_ago": 15,
      "last_observed": "2026-03-25T14:00:00Z",
      "server_name": "old.acme.com",
      "server_ip": "10.0.1.99"
    }
  ],
  "deployments_at_risk": [
    {
      "server_name": "api.acme.com",
      "server_ip": "10.0.1.42",
      "server_port": 443,
      "cert_cn": "api.acme.com",
      "days_remaining": 12
    }
  ]
}
```

## Frontend

### Component Structure

```
frontend/src/routes/reports/
  +page.svelte                    — report landing page + report rendering

frontend/src/lib/components/reports/
  ReportLanding.svelte            — 4 report cards with input fields
  DomainReport.svelte             — domain report renderer
  CAReport.svelte                 — CA report renderer
  ComplianceReport.svelte         — compliance report renderer
  ExpiryReport.svelte             — expiry risk report renderer
  ReportToolbar.svelte            — print + CSV download buttons
  report-types.ts                 — TypeScript types for report data
```

### Report Toolbar

Each report has a toolbar with:
- "Print" button — calls `window.print()`, CSS `@media print` styles ensure clean output
- "Download CSV" button — client-side CSV generation from the report data
- "Back to Reports" link

### Print Styles

`@media print` CSS hides navigation, toolbar buttons, and input fields. Report content fills the page with appropriate margins, page breaks between sections, and monochrome-safe styling.

## Backend

### New Files

| File | Responsibility |
|------|----------------|
| `internal/api/handler/reports.go` | 4 report endpoint handlers |
| `internal/store/reports.go` | Report-specific queries (separate from postgres.go to avoid bloating it) |
| `internal/model/reports.go` | Report response types |

### Store Methods

```go
GetDomainReport(ctx context.Context, domain string) (*model.DomainReport, error)
GetCAReport(ctx context.Context, fingerprint string, issuerCN string) (*model.CAReport, error)
GetComplianceReport(ctx context.Context) (*model.ComplianceReport, error)
GetExpiryReport(ctx context.Context, days int) (*model.ExpiryReport, error)
```

### Routes

```
GET /api/v1/reports/domain?q={domain}
GET /api/v1/reports/ca?fingerprint={fp}&issuer_cn={cn}
GET /api/v1/reports/compliance
GET /api/v1/reports/expiry?days={30|60|90}
```

## Dependencies

No new Go or npm dependencies. Uses existing D3 packages for any charts, `window.print()` for printing, and client-side CSV generation.

## Out of Scope

- Server-side PDF generation
- Scheduled/emailed reports
- Report history/archiving
- Infrastructure reports (Sub-project B)
- Custom report builder
