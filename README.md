# CipherFlag

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Release](https://img.shields.io/github/v/release/cyberflag-ai/cipherflag)](https://github.com/cyberflag-ai/cipherflag/releases)

CipherFlag is an open-source certificate intelligence platform that discovers TLS certificates from network traffic, scores their health, and provides interactive analytics for enterprise PKI management. It uses [Zeek](https://zeek.org/) for passive discovery, grades certificates A+ through F against 16 security rules, and visualizes certificate chains, ownership, and crypto posture with D3.js.

---

## Quick Start

### Option 1: Install Script (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/cyberflag-ai/cipherflag/main/scripts/install.sh | sh
cipherflag setup
```

The setup wizard walks you through network interface selection, Venafi integration, and starts the platform.

### Option 2: Manual Setup

```bash
git clone https://github.com/cyberflag-ai/cipherflag.git
cd cipherflag
cp .env.example .env          # edit to set NETWORK_INTERFACE for live capture
docker-compose up -d
```

Open [http://localhost:8443](http://localhost:8443) to access the dashboard.

---

## Features

### Discovery & Ingestion

- **Passive network discovery** -- Zeek monitors a network interface (SPAN port or tap) and extracts TLS certificates without disrupting traffic
- **PCAP upload** -- Upload .pcap/.pcapng files for offline certificate analysis with drag-and-drop UI
- **Active scanning** -- Discover certificates via active reconnaissance
- **Corelight integration** -- Ingest from Corelight appliances

### Analysis & Scoring

- **Health scoring** -- 24 rules covering expiration, key strength, signature algorithm, chain trust, revocation, CT compliance, wildcard detection, and crypto agility. Grades from A+ (95+) to F
- **Certificate chain validation** -- Walks issuer chains from leaf to root, identifies orphaned and incomplete chains
- **Blast radius analysis** -- Select any CA to see every certificate it signed, recursively, with aggregate risk stats

### Visualization

- **PKI Explorer** -- Interactive D3.js force-directed graph of the entire CA hierarchy. Click nodes to inspect, right-click for blast radius, search across loaded and server-side certificates
- **Certificate Chain Flow** -- Sankey diagram showing trust flow from Root CAs through Intermediates to leaf certificates, colored by CA family
- **Ownership Treemap** -- Certificates grouped by issuer organization and subject OU, sized by count, colored by health grade
- **Deployment Map** -- Horizontal bar chart showing certificates by deployment domain (derived from network observations)
- **Crypto Posture** -- Key algorithm donut, key size distribution, TLS version x cipher strength heatmap, signature algorithm breakdown
- **Expiry Forecast** -- 52-week stacked bar chart of upcoming expirations, broken down by issuer organization
- **Source Lineage** -- Discovery source cards with per-source grade distribution, key algorithm breakdown, and observation timeline
- **Global Search** -- Search bar in the top nav searches across certificate names, fingerprints, SANs, serial numbers, server names, and IPs

### Reports

Visual dashboard with drill-down to detailed reports:

- **Reports Dashboard** -- Treemap domain overview (sized by cert count, colored by grade), CA concentration bars, compliance gauge, and expiry timeline. Click any element to drill into a detailed report.
- **Domain Certificate Report** -- Grade distribution donut, key algorithm bars, match type breakdown, certificates table, deployments, health findings, and wildcard coverage
- **CA Authority Report** -- CA identity, issued cert inventory, crypto breakdown, chain context, and findings
- **Crypto Compliance Report** -- Compliance score gauge, critical issues, remediation priorities, non-agile certs, wildcard inventory
- **Expiry Risk Report** -- Certificates expiring in 30/60/90 days, grouped by issuer and owner, with ghost certs and deployments at risk

All analytics tabs are drillable — click any chart element to see matching certificates. Reports include Print and Download CSV.

### Export & Integration

- **Venafi Cloud** -- Automated push of discovered certificates to Venafi TLS Protect Cloud (SaaS) via API key authentication. Batch import with endpoint metadata.
- **Venafi TPP** -- Automated push to on-prem Venafi Trust Protection Platform via OAuth2 and the Discovery/Import API. Includes host, IP, port, and TLS version from network observations.
- **Unified push scheduler** -- Background goroutine pushes new/updated certificates on a configurable interval (default 60 min). Per-certificate failure tracking with exponential backoff and dead-lettering after 5 failures.
- **Push status API** -- `GET /api/v1/venafi/status` shows pending, pushed, failed, and dead-lettered counts.
- **CSV/JSON export** -- Manual download of certificate inventory in formats compatible with Venafi bulk import

---

## Analytics Dashboard

CipherFlag v0.3 includes five analytics tabs:

| Tab | Visualization | Answers |
|-----|--------------|---------|
| **Chain Flow** | D3 Sankey diagram | How does trust flow through my PKI? |
| **Ownership** | Treemap + deployment bars | Who owns what? Where are certs deployed? |
| **Crypto Posture** | Donut, bars, heatmap | Are we crypto-modern? Where's the weak crypto? |
| **Expiry Forecast** | Stacked timeline | What's about to expire, and who's affected? |
| **Source Lineage** | Source cards with icons | Where do we discover certs? What quality per source? |

---

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Zeek/PCAP  │────▶│  CipherFlag  │────▶│  PostgreSQL   │
│   Sensor     │     │  API Server  │     │  Database     │
└──────────────┘     └──────┬───────┘     └──────────────┘
                            │
                     ┌──────┴───────┐
                     │  SvelteKit   │
                     │  Frontend    │
                     └──────────────┘
```

**Tech Stack:**
- **Backend:** Go 1.24, chi router, pgx/PostgreSQL
- **Frontend:** SvelteKit 2, Svelte 5, Tailwind CSS
- **Visualizations:** D3.js (force, sankey, hierarchy, zoom), Cytoscape.js
- **Network Sensor:** Zeek 7.x
- **Database:** PostgreSQL 15
- **Deployment:** Docker Compose (3 services)

---

## Configuration

CipherFlag uses two configuration layers:

| File | Purpose |
|------|---------|
| `.env` | Docker Compose environment variables (network interface, database password, Venafi credentials) |
| `config/cipherflag.toml` | Application configuration (analysis rules, polling intervals, export settings) |

See [docs/configuration.md](docs/configuration.md) for a complete reference of all options.

---

## Documentation

| Document | Description |
|----------|-------------|
| [User Guide](docs/cipherflag-user-guide.md) | Comprehensive usage and operations guide |
| [Quick Start Guide](docs/quickstart.md) | Step-by-step Docker Compose deployment |
| [Configuration Reference](docs/configuration.md) | All config options for `.env` and `cipherflag.toml` |
| [Venafi Integration Guide](docs/venafi-export.md) | Setting up Venafi Cloud or TPP integration |
| [Architecture](docs/architecture.md) | System design, data flow, and data model |
| [Changelog](CHANGELOG.md) | Release history and version notes |

---

## Project Structure

```
cipherflag/
├── cmd/cipherflag/          # CLI entrypoint (serve, migrate, seed, setup)
├── config/                  # Runtime configuration (cipherflag.toml)
├── docker/zeek/             # Zeek sensor container
├── frontend/
│   ├── src/routes/          # SvelteKit pages (dashboard, PKI, analytics, certificates)
│   └── src/lib/components/  # D3 graph + analytics components
├── internal/
│   ├── analysis/            # Health scoring engine (16 rules) + chain builder
│   ├── api/                 # HTTP server, handlers, middleware
│   ├── certparse/           # X.509 PEM/DER parser
│   ├── config/              # TOML config loader
│   ├── export/              # CSV, JSON, and Venafi TPP export
│   ├── ingest/              # Zeek log poller and PCAP job manager
│   ├── model/               # Domain types (certificate, chain, analytics)
│   └── store/               # PostgreSQL store and migrations
├── docker-compose.yml       # 3-service deployment (Zeek + CipherFlag + PostgreSQL)
└── docs/                    # Documentation and design specs
```

---

## API Endpoints

### Certificates
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/certificates` | Search and filter certificates |
| GET | `/api/v1/certificates/{fp}` | Certificate detail + health report |
| GET | `/api/v1/certificates/{fp}/chain` | Certificate chain (leaf to root) |
| GET | `/api/v1/certificates/{fp}/health` | Health findings |
| GET | `/api/v1/certificates/{fp}/observations` | TLS observation history |
| GET | `/api/v1/search?q=...` | Global search (certs, SANs, fingerprints, IPs) |

### PKI Graph
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/graph/landscape/aggregated` | CA-only graph with aggregate stats |
| GET | `/api/v1/graph/ca/{fp}/children` | On-demand children of a CA |
| GET | `/api/v1/graph/ca/{fp}/blast-radius` | Full downstream subgraph of a CA |

### Reports
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/reports/domain?q=...` | Domain certificate report |
| GET | `/api/v1/reports/ca?issuer_cn=...` | CA authority report (supports partial match) |
| GET | `/api/v1/reports/compliance` | Crypto compliance report |
| GET | `/api/v1/reports/expiry?days=30` | Expiry risk report |

### Venafi Integration
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/venafi/status` | Push scheduler status (pending, pushed, failed, dead-lettered) |

### Analytics
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/stats/summary` | Dashboard summary stats |
| GET | `/api/v1/stats/chain-flow` | Sankey chain flow data |
| GET | `/api/v1/stats/ownership` | Issuer org x subject OU groupings |
| GET | `/api/v1/stats/deployment` | Certificates by deployment domain |
| GET | `/api/v1/stats/crypto-posture` | Key/signature algorithm distribution |
| GET | `/api/v1/stats/expiry-forecast` | Weekly expiry buckets by issuer |
| GET | `/api/v1/stats/source-lineage` | Per-source discovery breakdowns |
| GET | `/api/v1/stats/ciphers` | TLS cipher suite analytics |

---

## Security

CipherFlag includes built-in authentication with JWT tokens, bcrypt password hashing, and role-based access control (admin/viewer). On first visit, you'll be prompted to create an admin account.

For production deployments, also consider:
- Network segmentation (management VLAN only)
- Reverse proxy with TLS termination (nginx, Caddy)
- Host firewall rules restricting access to port 8443

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code structure, and PR process.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for the full text.
