# Changelog

All notable changes to CipherFlag are documented in this file.

## [0.33] - 2026-03-28

### Added
- **Setup wizard** (`cipherflag setup`) — interactive CLI that walks through network interface selection, Venafi credential validation, config file generation, Docker image pull, and service startup
- **Install script** — `curl -fsSL .../install.sh | sh` one-liner that downloads the right binary for your platform
- **CI/CD pipeline** — GitHub Actions workflow builds Docker images (cipherflag + zeek) and CLI binaries (linux/darwin × amd64/arm64), publishes to GHCR, creates GitHub Release on tag push
- **Venafi Cloud support** — API key auth against `api.venafi.cloud` (US) and `api.venafi.eu` (EU) via unified `VenafiClient` interface
- **Venafi push scheduler** — background goroutine batches certificates into Discovery/Import API calls with per-cert failure tracking, exponential backoff, and dead-lettering
- **Push status API** — `GET /api/v1/venafi/status` returns pending, pushed, failed, and dead-lettered counts
- **Pre-built Docker images** — `ghcr.io/cyberflag-ai/cipherflag` and `ghcr.io/cyberflag-ai/cipherflag-zeek`

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
