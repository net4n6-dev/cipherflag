# Changelog

All notable changes to CipherFlag are documented in this file.

## [2.0.0] - 2026-05-26

### Major release: EE→CE port (Phase 1)

This release is a fundamental expansion of CipherFlag CE. The feature
set grows from v1.x's certificate-inventory demo into a working
post-quantum migration inventory + CycloneDX 1.6 CBOM toolkit for
budget-constrained federal/state government and developer audiences.

The release vendors a curated subset of features from the proprietary
**CipherFlag EE** product under Apache 2.0. EE remains a separate
product with additional capabilities — see the README §"What's NOT
included" for the moat list.

### Added

**Foundation (Layer 0)**
- Unified crypto asset model with multi-source ingestion
  (`POST /api/v1/ingest`)
- Host identity resolution with deduplication and provenance tracking
- Agent-token auth for unattended ingest

**Endpoint discovery (Layer 1)**
- osquery webhook adapter (`POST /api/v1/ingest/osquery`)
- 4 bash + 4 PowerShell discovery scripts under `discovery-packs/scripts/`
- Script-output parser that auto-classifies output into the unified
  asset model

**Native scanners (Layer 2)**
- SSH key scanner (system + user `~/.ssh/`)
- Crypto-library scanner (OpenSSL, libgcrypt, BoringSSL, mbedTLS,
  GnuTLS, NSS, wolfSSL, language-runtime crypto stdlibs)
- Cert-file scanner (PEM/DER/PKCS12/JKS on disk; matches private
  keys to certs by SPKI fingerprint)
- Config-file scanner (sshd, openssl.cnf, nginx, apache, envoy,
  haproxy)
- Truststore scanner (OS bundles, JVM cacerts, language-runtime CA
  stores)

**Scoring (Layer 4.1 + 4.1b)**
- 47-rule scoring catalog (CE subset: SSH-001..008, LIB-003..005,
  CFG-001..004, and PQC-relevant certificate rules)
- CVE-based library scoring against open NVD/OSV data (LIB-001 +
  LIB-002); 37 seed CVEs covering known crypto-library
  vulnerabilities

**PQC taxonomy (Layer 4.2)**
- 122 recognized algorithm spellings across 8 categories
- Vulnerable, weakened, hybrid, and quantum-safe classification

**Compliance evaluation (Layer 4.3)**
- NIST SP 800-131A Rev 2
- NSA CNSA 2.0
- FIPS 140-3 (algorithm allowlist)
- EU NIS2

**CBOM (Layer 5.1 + 5.2 + 5.3)**
- CycloneDX 1.6 CBOM generation (`GET /api/v1/export/cbom`)
- CBOM import endpoint (`POST /api/v1/import/cbom`)
- Scheduled push with file sink + HTTP sink
- Export sinks: S3 (AWS or S3-compatible), Splunk HEC, Syslog
  (RFC 5424 + CEF)

**Git repository scanner (Layer 6.1a–c)**
- Block 1: PEM/DER/SSH/PKCS12/JKS file parsing
- Block 3: tree-sitter Python + Java parsers, Go AST parser
- Block 4: server config file parsing (nginx/apache/envoy/haproxy/
  openssl.cnf)
- Per-repo CBOM export endpoint

**Performance**
- In-process observation cache for intake dedup
  (`internal/ingest/observcache/`)

### Changed

- **Schema baseline.** Replaced incremental v1.x migrations 001-005
  with single `internal/store/migrations/v2.0_baseline.sql` (24
  tables). Future CE migrations start at `v2.0.1_*.sql` (see
  `internal/store/migrations/README.md`).
- **Repository structure.** `internal/` packages now mirror the
  layered architecture documented in CipherFlag EE
  (analysis/compliance/, analysis/pqc/, analysis/scoring/,
  export/cbom/, ingest/, scanner/, etc.).
- **CryptoStore interface trimmed** — `internal/store/store.go` no
  longer declares risk-engine, blast-radius, host-dependency edge,
  PQC-migration-planner, protocol-endpoint, external-source
  registry, AD CS event, briefing cache, AI ledger, or multi-tenant
  teams methods. Those are EE-only.
- **HTTP API surface** reduced to CE-bound routes. EE-only routes
  (`/risk/*`, `/blast-radius/*`, `/hosts/{id}/dependencies`,
  `/hosts/{id}/subgraph`, `/hosts/{id}/blast-radius`,
  `/hosts/{id}/trust-store`, `/briefing`, `/events/stream`,
  `/teams`, `/external-sources/*`, `/pqc-migration/*`, `/risk/*`,
  `/repo/ai/*`, `/repo/images/*`, `/network/targets/*`, `/venafi/*`,
  `/ad-cs-events`, `/evidence-pack`, `/agency/omb`) are not wired.
  Five application-management routes from `applications.go` (List,
  Get, History, ExportCBOM, ExportOMB, OwnershipRollup) are also
  dropped in CE v2.0 — that handler was excluded from the manifest.
  The single `/applications/{tag}/metadata` endpoint (GET/PUT/DELETE)
  IS wired via `appMetaH` and remains CE-bound.

### Removed

- v1.x seed-data fixtures (replaced by real ingest paths from osquery
  webhook + Layer 2 scanners + git repo scanner)
- v1.x install script (`scripts/install.sh`) — superseded by
  `docker-compose up -d`
- Legacy CE v1 exports (`internal/export/csv.go`,
  `internal/export/json.go`) — superseded by CBOM
- Legacy Zeek file poller — `cipherflag serve` now relies on the
  osquery webhook and Layer 2 scanners for live evidence. The Zeek
  log poller may be re-introduced in a follow-up minor.

### Known limitations

- **Frontend.** CE v2.0 retains the v1.x demo frontend in
  `frontend/`. The production operator UI (Layer 8) is part of
  CipherFlag EE. The v1 frontend was preserved so the upgrade
  doesn't leave CE with no UI at all; it does not surface the v2
  feature set.
- **Certificate Transparency.** CT ingestion (ct_crtsh + ct_static +
  ct_certspotter + ct_multi) is deferred to v2.1 (Phase 2). The
  underlying external-source registry is also deferred.
- **No AI-enriched scanning.** Git-scan modes `triage`, `enrichment`,
  and `deep` return 409 Conflict — only `deterministic_only` is
  accepted in CE. AI-enriched modes are EE-only.
- **No per-asset risk prioritization.** Asset health reports include
  4-framework compliance grades but no risk score / blast-radius
  fan-out. Layer 4.4 is EE-only.
- **No container image scanning.** Layer 6.2 is EE-only.
- **No active network scanning.** Layer 6.3 is EE-only.
- **No PCI DSS 4.0 evaluator.** Layer 4.3 ships with 4 of 5
  compliance frameworks; PCI DSS is EE-only (private-sector
  commerce focus).
- **No Venafi / Thales CipherTrust push.** Layer 5.4 is EE-only.
- **No endpoint adapters beyond osquery.** Layer 3 (Velociraptor,
  Wazuh, Defender, SentinelOne, Tanium, Absolute, Netwrix) is
  EE-only.

### Compatibility

**v2.0.0 is a breaking change from v1.x.** There is no automated
upgrade path for v1.x deployments. The schema baseline is option (ii)
from the port design spec: existing v1.x users must reinitialize
their database. v1.x users with valuable data should export it
(`/api/v1/export/certificates` on v1) before upgrading.

### Acknowledgments

This release vendors features from CipherFlag EE under Apache 2.0.
EE source SHA is referenced in the squashed port commit. Manifest +
extraction tooling lives at `docs/superpowers/ce-port/` (in the EE
repository).

Third-party software acknowledgments: see `NOTICE`.

---

## [1.1] - 2026-03-31

### Added
- **Deployment guide** in how-to documentation covering on-prem (SPAN/TAP), AWS (VPC Traffic Mirroring with dual ENI), and Azure (vTAP + Network Watcher PCAP fallback)
- **Dual NIC architecture** documented: management NIC for SSH/web/API + capture NIC for traffic mirror target
- **Network interface selector** in Settings > Sources — dropdown populated from host interfaces with name, IP, MAC, and status
- **Network interface config API** — `GET /api/v1/config/interfaces` lists available network interfaces
- **Deployment comparison table** — traffic source, encapsulation, NIC requirements, live capture support, and cost per platform

### Changed
- How-to guide expanded from 10 to 11 sections with new Deployment Guide as section 2
- Prerequisites section updated to specify dual NIC requirement for live capture deployments
- User guide, quickstart, and README updated with deployment and network interface information

## [1.0] - 2026-03-29

### Added
- **Settings page** with tabbed layout:
  - Users: list, create, delete, toggle roles (admin only)
  - Sources: Zeek poller, Corelight, PCAP config with guardrails
  - Venafi: config management with platform/region dropdowns, masked credentials, test connection, push interval (5-1440 min)
  - System: cert counts, grade distribution, sources overview
  - Profile: view profile, change password
- **Venafi config API** — GET/PUT with validation, test connection endpoint
- **Sources config API** — GET/PUT with guardrails (poll interval 5-300s, PCAP size 1-5000MB)
- **Docker containerization** — optimized 40MB image, docker-compose with pre-built GHCR images, Docker-specific config template
- Settings link (gear icon) and profile link in nav bar

### Changed
- NewRouter accepts config pointer for live config management
- Venafi handler uses config reference instead of static values

## [0.9] - 2026-03-28

### Added
- **Authentication system** — JWT tokens in HTTP-only cookies, bcrypt password hashing, admin/viewer roles
- **Login page** (`/login`) — email + password authentication
- **First-visit admin setup** (`/setup-admin`) — creates initial admin account when no users exist
- **Auth middleware** — protects all API endpoints, backward compatible (no users = no auth)
- **User management API** — admin-only CRUD for users (list, create, update, delete)
- **Password change** — authenticated users can change their own password
- **User menu in nav** — display name, role badge (admin/viewer), logout button
- **Dashboard redesign** — command center layout with compliance gauge, grade donut, algorithm landscape, priority actions, radial PKI tree
- **Compliance report visual layer** — category donut, severity distribution, expandable category cards before raw tables

### Changed
- All API endpoints now require authentication when users exist
- Setup wizard creates first admin account
- Reports landing uses treemap for domain overview

## [0.36] - 2026-03-28

### Added
- **Reports visual dashboard** — treemap domain overview, CA concentration bars, compliance gauge, and expiry timeline replace the old card-based landing
- **Drillable analytics** across all tabs:
  - Crypto Posture: click any key algorithm, key size, signature algorithm, or TLS heatmap cell to see matching certificates
  - Expiry Forecast: click any weekly bar to drill into expiring certificates for that week
  - Deployment chart: click any domain bar to expand and see deployed certificates
- **TLS version and cipher strength filters** on certificate search API (`tls_version`, `cipher_strength`)
- **Domain report charts** — grade distribution donut, key algorithm bars, and match type breakdown
- **Reports drill-down flow** — visual dashboard → click chart element → detailed report

### Fixed
- Bar track elements absorbing click events in crypto posture (pointer-events: none)
- Drilldown panels rendering below fold (moved above strength summary, auto-scroll)
- Compliance score rounded to 1 decimal place
- CA report partial name matching (ILIKE)
- Replaced unreadable bubble chart with treemap for domain overview

## [0.35] - 2026-03-28

### Added
- **Reports page** with 4 report types: Domain Certificate, CA Authority, Crypto Compliance, Expiry Risk
- **Domain Report** — enter a domain, see all certs (exact, wildcard, SAN, subdomain matches), deployments, findings, wildcard coverage
- **CA Report** — select a CA (partial name match), see issued certs, grade distribution, crypto breakdown, chain context
- **Crypto Compliance Report** — compliance score, critical issues, remediation priorities, non-agile certs, wildcard inventory
- **Expiry Risk Report** — 30/60/90 day window, grouped by issuer and owner, ghost certs, deployments at risk
- Report toolbar with Print and Download CSV on every report
- **8 new health scoring rules** (24 total, up from 16):
  - WLD-001/002: Wildcard certificate detection (medium/high/critical)
  - EXP-006: Validity >200 days (2026 industry direction)
  - KEY-002 updated: RSA 2048 below 3072 recommendation
  - KEY-005: RSA 3072 info acknowledgment
  - AGI-001/002/003: Crypto agility (non-ACME, unusual ACME validity, FIPS readiness)

### Fixed
- Compliance score rounded to 1 decimal place
- CA report supports partial name matching (ILIKE)
- NULL raw_pem no longer crashes certificate scans

## [0.34] - 2026-03-28

### Added
- **Global search bar** — searches across certificate names, organizations, fingerprints, serial numbers, SANs, server names, and IPs from the top nav on every page
- **New search filters** — `subject_ou`, `issuer_org`, `key_algorithm`, `signature_algorithm`, `server_name` parameters on the certificate search API
- **Global search API** — `GET /api/v1/search?q=...` with four search strategies: full-text, fingerprint prefix, SAN match, and observation match
- **Comprehensive user guide** — rewritten to cover setup wizard, analytics tabs, PKI explorer, global search, Venafi Cloud/TPP, and all API endpoints

### Fixed
- NULL `raw_pem` crashes on certificate detail and list pages
- Certificate search now works with all key algorithm and signature algorithm filters

## [0.33] - 2026-03-28

### Added
- **Setup wizard** (`cipherflag setup`) — interactive CLI that walks through network interface selection, Venafi credential validation, config file generation, Docker image pull, and service startup
- **Install script** — `curl -fsSL .../install.sh | sh` one-liner that downloads the right binary for your platform
- **CI/CD pipeline** — GitHub Actions workflow builds Docker images (cipherflag + zeek) and CLI binaries (linux/darwin × amd64/arm64), publishes to GHCR, creates GitHub Release on tag push
- **Venafi Cloud support** — API key auth against `api.venafi.cloud` (US) and `api.venafi.eu` (EU) via unified `VenafiClient` interface
- **Venafi push scheduler** — background goroutine batches certificates into Discovery/Import API calls with per-cert failure tracking, exponential backoff, and dead-lettering
- **Push status API** — `GET /api/v1/venafi/status` returns pending, pushed, failed, and dead-lettered counts
- **Pre-built Docker images** — `ghcr.io/net4n6-dev/cipherflag` and `ghcr.io/net4n6-dev/cipherflag-zeek`

### Changed
- Venafi config adds `platform` (cloud/tpp), `api_key`, and `region` fields
- Dockerfile updated to Go 1.25
- README Quick Start now recommends install script + setup wizard

## [0.32] - 2026-03-28

### Added
- Venafi Cloud client with API key authentication and batch import
- Unified `VenafiClient` interface (Cloud + TPP behind same API)
- Push scheduler with exponential backoff and dead-lettering after 5 failures
- `GET /api/v1/venafi/status` endpoint
- Venafi integration guide rewritten for both Cloud and TPP

## [0.3] - 2026-03-27

### Added
- **PKI Explorer** — D3 force-directed graph replacing tree view, with detail side panel, blast radius analysis, and server-side search
- **Analytics dashboard** with 5 tabs:
  - Chain Flow (Sankey diagram colored by CA family)
  - Ownership (treemap by issuer org × subject OU + deployment bar chart)
  - Crypto Posture (key algorithm donut, key size bars, TLS × cipher heatmap, signature algorithm bars)
  - Expiry Forecast (52-week stacked bar chart by issuer)
  - Source Lineage (discovery source cards with category icons)
- Server-side aggregation for enterprise-scale graph rendering
- 10 new API endpoints for graph and analytics data
- Search dropdown with client-side and server-side fallback

## [0.1] - 2026-03-19

### Added
- Initial open-source release
- Passive TLS certificate discovery via Zeek
- PCAP upload and analysis
- Health scoring engine (16 rules, grades A+ through F)
- Certificate chain validation
- Venafi TPP export (OAuth2)
- CSV/JSON export
- Docker Compose deployment
