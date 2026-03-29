# CipherFlag User Guide

## What is CipherFlag?

CipherFlag is an open-source certificate intelligence platform that discovers TLS certificates from network traffic, scores their health, and provides interactive analytics for enterprise PKI management. It passively monitors traffic via Zeek, analyzes packet captures, and pushes discovered certificates to Venafi (Cloud or on-prem TPP) for lifecycle management.

This guide walks you through installation, configuration, and daily use.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [The Setup Wizard](#3-the-setup-wizard)
4. [Manual Configuration](#4-manual-configuration)
5. [Verifying Your Deployment](#5-verifying-your-deployment)
6. [Authentication](#6-authentication)
7. [Network Capture](#7-network-capture)
8. [Uploading PCAP Files](#8-uploading-pcap-files)
9. [The Dashboard](#9-the-dashboard)
10. [PKI Explorer](#10-pki-explorer)
11. [Analytics](#11-analytics)
12. [Reports](#12-reports)
13. [Global Search](#13-global-search)
14. [Certificate Detail](#14-certificate-detail)
15. [Settings](#15-settings)
16. [Venafi Integration](#16-venafi-integration)
17. [Exporting Data](#17-exporting-data)
18. [API Reference](#18-api-reference)
19. [Ongoing Operations](#19-ongoing-operations)
20. [Troubleshooting](#20-troubleshooting)

---

## 1. Prerequisites

### Required Software

| Software | Minimum Version | Purpose |
|----------|----------------|---------|
| Docker | 20.10+ | Runs the CipherFlag containers |
| Docker Compose | v2+ | Orchestrates the three services |
| A web browser | Any modern browser | Access the CipherFlag dashboard |

**Installing Docker:** Follow the official guide for your OS:
- Linux: https://docs.docker.com/engine/install/
- macOS: https://docs.docker.com/desktop/install/mac-install/
- Windows: https://docs.docker.com/desktop/install/windows-install/ (WSL2 backend recommended)

### Network Requirements

- **Port 8443** must be accessible from your browser
- For live capture: access to a SPAN port, mirror port, or network TAP
- For PCAP-only analysis: no special network access needed

### Hardware Recommendations

| Deployment | CPU | RAM | Disk |
|------------|-----|-----|------|
| Evaluation / PCAP-only | 2 cores | 4 GB | 20 GB |
| Small network (< 1 Gbps) | 4 cores | 8 GB | 50 GB |
| Medium network (1-10 Gbps) | 8 cores | 16 GB | 100 GB |

---

## 2. Installation

### Option A: Install Script (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/cyberflag-ai/cipherflag/main/scripts/install.sh | sh
```

This downloads the `cipherflag` CLI binary for your platform (Linux or macOS, amd64 or arm64) and installs it to `/usr/local/bin`.

Then run the setup wizard:

```bash
cipherflag setup
```

### Option B: Clone and Build

```bash
git clone https://github.com/cyberflag-ai/cipherflag.git
cd cipherflag
docker-compose up -d
```

---

## 3. The Setup Wizard

The setup wizard (`cipherflag setup`) is the easiest way to get started. It walks through four steps:

### Step 1: Installation Directory

Choose where CipherFlag writes its configuration files. Default: `./cipherflag`.

```
Step 1/4: Installation Directory
Directory [./cipherflag]:
```

### Step 2: Network Interface

The wizard lists available network interfaces with their IP addresses. Select the one connected to your SPAN port or mirror.

```
Step 2/4: Network Capture
Available interfaces:
  1. eth0        10.0.1.5       up
  2. ens192      172.16.0.10    up
  3. lo          127.0.0.1      up (loopback)
Select interface [1]: 2
```

### Step 3: Venafi Integration

Choose your Venafi platform or skip for now.

```
Step 3/4: Venafi Integration
  1. Venafi Cloud (SaaS)
  2. Venafi TPP (on-prem)
  3. Skip (configure later)
```

For Venafi Cloud, you'll need your API key (from Venafi Cloud > Preferences > API Keys). For TPP, you'll need the server URL, OAuth2 client ID, and refresh token. The wizard validates your credentials before proceeding.

### Step 4: Deploy

The wizard generates configuration files, pulls Docker images, and optionally starts the services.

```
Start services now? [Y/n]: Y
✓ Services started

══════════════════════════════════════
Dashboard:  http://10.0.1.5:8443
Venafi:     Cloud (us) — push every 60 min
Interface:  ens192 (172.16.0.10)
══════════════════════════════════════
```

---

## 4. Manual Configuration

If you prefer manual setup, CipherFlag uses two configuration files:

### `.env` — Docker Compose variables

```bash
NETWORK_INTERFACE=ens192
POSTGRES_PASSWORD=your-secure-password
VENAFI_ENABLED=true
VENAFI_PLATFORM=cloud
VENAFI_API_KEY=your-api-key
VENAFI_REGION=us
```

### `config/cipherflag.toml` — Application settings

See [Configuration Reference](configuration.md) for all options.

Key sections:
- `[server]` — listen address
- `[storage]` — PostgreSQL connection
- `[analysis]` — health scoring rules and thresholds
- `[sources.zeek_file]` — Zeek log polling
- `[export.venafi]` — Venafi Cloud or TPP integration
- `[pcap]` — PCAP upload limits

---

## 5. Verifying Your Deployment

After starting services, verify everything is running:

```bash
docker compose ps
```

All three services should show "Up":
- `postgres` — database
- `zeek` — network sensor
- `cipherflag` — API server and dashboard

Check the Venafi push status:

```bash
curl -s http://localhost:8443/api/v1/venafi/status | python3 -m json.tool
```

Open the dashboard in your browser: `http://<your-ip>:8443`

---

## 6. Authentication

CipherFlag includes built-in authentication with JWT tokens and role-based access control.

### First-Time Setup

On first visit (or after a fresh install), you'll see the **Create Admin Account** page. Enter your email, password (min 8 characters), and display name. This creates the first admin user and logs you in.

### Roles

| Role | Capabilities |
|------|-------------|
| **Admin** | Full access: manage users, edit settings, configure Venafi and sources |
| **Viewer** | Read-only: view dashboard, analytics, reports, certificates |

### Login

Navigate to any page — if not authenticated, you'll be redirected to `/login`. Enter your email and password. Sessions last 24 hours.

### User Management

Admins can manage users at **Settings > Users**:
- Create new users with email, password, display name, and role
- Toggle roles between admin and viewer (click the role badge)
- Delete users (cannot delete your own account)

### Backward Compatibility

If no users have been created, CipherFlag runs without authentication — all endpoints are open. This preserves backward compatibility with existing deployments. Authentication enforcement begins when the first user is created.

---

## 7. Network Capture

CipherFlag uses Zeek to passively extract certificates from TLS handshakes. No traffic is modified or interrupted.

### Setting Up a SPAN Port

Connect the capture interface to a SPAN/mirror port on your switch or a network TAP. CipherFlag sees a copy of all traffic on that segment and extracts TLS certificates from the handshakes.

### What Gets Captured

For each TLS connection, CipherFlag records:
- The complete X.509 certificate chain (leaf + intermediates + root)
- Server hostname (SNI), IP address, and port
- Negotiated TLS version and cipher suite
- JA3/JA3S fingerprints

### Monitoring Capture Activity

Watch the logs for certificate discovery:

```bash
docker compose logs -f cipherflag | grep -i "cert\|ingest"
```

---

## 8. Uploading PCAP Files

For offline analysis, upload packet captures via the **Upload** page or API.

### Via the UI

Navigate to the **Upload** tab in the dashboard. Drag and drop a `.pcap` or `.pcapng` file (up to 500 MB by default).

### Via the API

```bash
curl -X POST http://localhost:8443/api/v1/pcap/upload \
  -F "file=@capture.pcap"
```

Check job status:

```bash
curl http://localhost:8443/api/v1/pcap/jobs
```

---

## 9. The Dashboard

The dashboard (`/`) shows a high-level overview:

- **Risk signal cards** — expired, expiring within 30/90 days, grade F, total findings
- **Grade distribution** — donut chart showing A+ through F breakdown
- **Expiry timeline** — 52-week forecast of upcoming expirations
- **Issuer treemap** — certificates by issuer, sized by count
- **Discovery sources** — where certificates were found

Click any risk card to navigate to filtered certificate views.

---

## 10. PKI Explorer

The PKI Explorer (`/pki`) is an interactive force-directed graph showing your entire CA hierarchy.

### Navigating the Graph

- **Pan:** Click and drag the background
- **Zoom:** Scroll wheel
- **Hover:** Tooltip with CA name, grade, cert count, expiry stats

### Inspecting a Node

Click any node to open the **detail panel** on the right:
- Grade, cert count, expired/expiring stats, avg score
- Overview tab: key algorithm, fingerprint, validity dates, issuer
- Findings tab: health findings with severity and remediation
- Children tab: child certificates issued by this CA
- Action buttons: "Expand in Graph" and "Blast Radius"

### Blast Radius

Right-click a CA node (or click "Blast Radius" in the detail panel) to see every certificate that CA signed, recursively. The graph dims non-affected nodes and shows a summary badge with total certs, expired count, and grade F count.

### Search

The toolbar search bar finds nodes in the graph (client-side) and certificates not yet loaded (server-side fallback). Click a result to open its detail panel.

---

## 11. Analytics

The Analytics page (`/analytics`) has five tabs:

### Chain Flow

A Sankey diagram showing certificate trust flow: Root CAs → Intermediates → Leaf certificates. Each flow is colored by its root CA family. Link width represents certificate count.

- Hover a link to see cert count, expired count, and worst grade
- Click a CA node to navigate to the PKI Explorer
- Click a leaf aggregate to see those certificates

### Ownership

Two views of certificate ownership:

**By Certificate Metadata** — A treemap grouping certificates by issuer organization and subject organizational unit. Rectangle size = cert count, color = health grade.

**By Deployment** — A horizontal bar chart showing the top 20 domains where certificates are observed (from network traffic). Each bar shows cert count, unique IPs, and worst grade.

### Crypto Posture

Four panels showing cryptographic health:

- **Key Algorithm** — donut chart (RSA vs ECDSA vs Ed25519)
- **Key Size Distribution** — bars by key size (RSA 2048, ECDSA 256, etc.)
- **TLS Version x Cipher Strength** — heatmap showing where weak crypto exists
- **Signature Algorithm** — bars with weak algorithms (SHA1, MD5) highlighted in red
- **Cipher Strength Overview** — Best/Strong/Acceptable/Weak/Insecure distribution

### Expiry Forecast

A 52-week stacked bar chart showing upcoming certificate expirations, broken down by issuer organization. Hover any bar for a per-issuer and per-grade breakdown. An alert banner shows already-expired certificate count.

### Source Lineage

Cards for each discovery source (Zeek passive, active scan, manual upload, Corelight, etc.) with:
- Category icon (network, upload, scan, cloud, repository)
- Cert count, expired count, expiring <30d, average score
- Grade distribution mini-bar
- Key algorithm pills
- First/last seen dates

---

## 12. Reports

The Reports page (`/reports`) provides a visual dashboard and detailed report generation.

### Reports Dashboard

The landing page shows four visual panels:
- **Domain Overview** — treemap of domains sized by cert count, colored by grade
- **CA Concentration** — horizontal bars showing top CAs
- **Compliance Posture** — arc gauge with compliance percentage
- **Expiry Timeline** — monthly bar chart of upcoming expirations

Click any element to drill into a detailed report.

### Report Types

| Report | Input | What it shows |
|--------|-------|---------------|
| Domain Certificate | Domain name | Certs, deployments, findings, wildcards, D3 charts |
| CA Authority | CA name | Issued certs, crypto breakdown, chain context |
| Crypto Compliance | None (full scan) | Compliance score, critical issues, remediation priorities |
| Expiry Risk | Time window | Expiring certs, by issuer/owner, ghost certs |

All reports include **Print** and **Download CSV** buttons.

---

## 13. Global Search

The search bar in the top navigation searches across the entire CipherFlag dataset:

- **Certificate names and organizations** — subject CN, subject org, issuer CN, issuer org
- **Fingerprints** — SHA-256 fingerprint prefix matching
- **Serial numbers** — exact or partial match
- **Subject Alternative Names** — domain names in the SAN extension
- **Server names and IPs** — from network observations

Type 2+ characters to see results. Results are categorized:

- **Certificates** — shows grade, CN, issuer, key algorithm, expiry, and which field matched
- **Endpoints** — shows server name, IP:port, TLS version, and associated certificate

Click any result to navigate to the certificate detail page.

---

## 14. Certificate Detail

The certificate detail page (`/certificates/{fingerprint}`) shows:

- Full certificate metadata (subject, issuer, validity, key info, extensions)
- Health report with grade, score, and detailed findings
- Certificate chain visualization (Cytoscape.js breadthfirst layout)
- TLS observation history (server IP, port, cipher, TLS version, timestamps)

Each health finding shows:
- Severity (critical, high, medium, low)
- Category (expiration, key_strength, signature, chain, revocation, transparency)
- Point deduction
- Remediation guidance

---

## 15. Settings

The Settings page (`/settings`) is accessible via the gear icon in the nav bar.

### Users (Admin only)

Manage user accounts: create, delete, and toggle roles between admin and viewer.

### Sources

Configure certificate discovery sources:
- **Zeek File Poller** — enable/disable, log directory, poll interval (5-300 seconds)
- **Corelight** — enable/disable, API URL, API token
- **PCAP Upload** — max file size (1-5000 MB), retention (1-720 hours)

### Venafi

Configure the Venafi push integration:
- Platform selection (Cloud or TPP)
- Credentials (API key for Cloud, OAuth2 for TPP) — masked in the UI
- Region (US/EU for Cloud)
- Push interval (5-1440 minutes)
- **Test Connection** button validates credentials
- Push status: pending, pushed, failed, dead-lettered counts

### System

Read-only overview: total certs, observations, grade distribution, discovery sources.

### Profile

View your account details and change your password.

---

## 16. Venafi Integration

CipherFlag pushes discovered certificates to Venafi automatically. See the [Venafi Integration Guide](venafi-export.md) for setup instructions.

### How It Works

1. CipherFlag discovers certificates via Zeek or PCAP upload
2. The push scheduler runs every 60 minutes (configurable)
3. New/updated certificates are batched (up to 100 per API call) and pushed to Venafi
4. Per-certificate failure tracking with exponential backoff prevents hammering Venafi with consistently failing certs
5. After 5 consecutive failures, a certificate is dead-lettered

### Monitoring Push Status

```bash
curl http://localhost:8443/api/v1/venafi/status
```

| Field | Meaning |
|-------|---------|
| `pending` | Certificates not yet pushed |
| `pushed` | Successfully pushed and up to date |
| `failed` | 1-4 failures, will retry with backoff |
| `dead_lettered` | 5+ failures, excluded from push |

### Supported Platforms

| Platform | Auth Method | API |
|----------|-------------|-----|
| Venafi Cloud (SaaS) | API key | `POST /outagedetection/v1/certificates` |
| Venafi TPP (on-prem) | OAuth2 refresh token | `POST /vedsdk/Discovery/Import` |

---

## 17. Exporting Data

### CSV Export

```bash
curl -o certificates.csv "http://localhost:8443/api/v1/export/certificates?format=csv"
```

### JSON Export

```bash
curl -o certificates.json "http://localhost:8443/api/v1/export/certificates?format=json"
```

### Filtered Exports

```bash
# Only grade F certificates
curl -o failing.csv "http://localhost:8443/api/v1/export/certificates?format=csv&grade=F"

# Expiring within 30 days
curl -o expiring.csv "http://localhost:8443/api/v1/export/certificates?format=csv&expiring_within_days=30"

# ECDSA certificates only
curl -o ecdsa.json "http://localhost:8443/api/v1/export/certificates?format=json&key_algorithm=ECDSA"

# Certificates from a specific issuer
curl -o digicert.csv "http://localhost:8443/api/v1/export/certificates?format=csv&issuer_org=DigiCert+Inc"
```

---

## 18. API Reference

All endpoints are under `/api/v1/`.

### Certificates

| Method | Path | Description |
|--------|------|-------------|
| GET | `/certificates` | Search/filter certificates |
| GET | `/certificates/{fp}` | Certificate detail + health |
| GET | `/certificates/{fp}/chain` | Chain (leaf → root) |
| GET | `/certificates/{fp}/health` | Health findings |
| GET | `/certificates/{fp}/observations` | TLS observations |
| GET | `/search?q=...` | Global search (certs, SANs, IPs, fingerprints) |

### Certificate Search Parameters

| Parameter | Example | Description |
|-----------|---------|-------------|
| `search` | `?search=acme` | Full-text search |
| `grade` | `?grade=D,F` | Filter by grade (comma-separated) |
| `source` | `?source=zeek_passive` | Filter by discovery source |
| `issuer_cn` | `?issuer_cn=DigiCert` | Filter by issuer CN |
| `issuer_org` | `?issuer_org=Amazon` | Filter by issuer organization |
| `subject_ou` | `?subject_ou=Engineering` | Filter by subject OU |
| `key_algorithm` | `?key_algorithm=ECDSA` | Filter by key algorithm |
| `signature_algorithm` | `?signature_algorithm=SHA256WithRSA` | Filter by signature |
| `server_name` | `?server_name=payments` | Filter by observed server (partial) |
| `expired` | `?expired=true` | Only expired certs |
| `expiring_within_days` | `?expiring_within_days=30` | Expiring within N days |
| `is_ca` | `?is_ca=true` | Only CA certs |
| `sort_by` | `?sort_by=expiry` | Sort: expiry, grade, cn, last_seen |
| `sort_dir` | `?sort_dir=desc` | Sort direction: asc, desc |

### PKI Graph

| Method | Path | Description |
|--------|------|-------------|
| GET | `/graph/landscape/aggregated` | CA-only graph with stats |
| GET | `/graph/ca/{fp}/children` | Children of a CA |
| GET | `/graph/ca/{fp}/blast-radius` | Full downstream subgraph |

### Analytics

| Method | Path | Description |
|--------|------|-------------|
| GET | `/stats/summary` | Dashboard stats |
| GET | `/stats/chain-flow` | Sankey flow data |
| GET | `/stats/ownership` | Issuer org x subject OU |
| GET | `/stats/deployment` | Certs by deployment domain |
| GET | `/stats/crypto-posture` | Key/sig algorithm stats |
| GET | `/stats/expiry-forecast` | Weekly expiry by issuer |
| GET | `/stats/source-lineage` | Per-source breakdowns |
| GET | `/stats/ciphers` | TLS cipher analytics |

### Venafi

| Method | Path | Description |
|--------|------|-------------|
| GET | `/venafi/status` | Push scheduler status |

### Export

| Method | Path | Description |
|--------|------|-------------|
| GET | `/export/certificates?format=csv` | CSV download |
| GET | `/export/certificates?format=json` | JSON download |

---

## 19. Ongoing Operations

### Checking Health

```bash
# Service status
docker compose ps

# CipherFlag logs
docker compose logs -f cipherflag

# Venafi push status
curl http://localhost:8443/api/v1/venafi/status
```

### Updating CipherFlag

```bash
docker compose pull
docker compose up -d
```

### Backing Up the Database

```bash
docker compose exec postgres pg_dump -U cipherflag cipherflag > backup.sql
```

### Resetting Dead-Lettered Certificates

If certificates are stuck in dead-letter (5+ Venafi push failures):

```sql
docker compose exec postgres psql -U cipherflag -c \
  "UPDATE certificates SET venafi_push_failures = 0, venafi_last_push_attempt = NULL WHERE venafi_push_failures >= 5;"
```

---

## 20. Troubleshooting

### Dashboard not loading

- Verify services are running: `docker compose ps`
- Check port 8443 is accessible: `curl http://localhost:8443/healthz`
- Check logs: `docker compose logs cipherflag`

### No certificates appearing

- Verify Zeek is running: `docker compose logs zeek`
- Confirm the network interface is correct and receiving traffic
- For PCAP uploads, check job status: `curl http://localhost:8443/api/v1/pcap/jobs`

### Venafi push not working

- Check status: `curl http://localhost:8443/api/v1/venafi/status`
- Look for errors: `docker compose logs cipherflag | grep venafi`
- For Cloud: verify API key and region match your Venafi Cloud account
- For TPP: verify the refresh token hasn't expired
- See the [Venafi Integration Guide](venafi-export.md) for detailed troubleshooting

### Search returns no results

- The global search requires at least 2 characters
- Full-text search indexes: subject CN, org, issuer CN, org, fingerprint, serial number
- SAN search uses partial matching (ILIKE)
- Server name search requires observation data (from network capture, not manual upload)

### High memory usage

- Check PostgreSQL: `docker compose exec postgres psql -U cipherflag -c "SELECT pg_size_pretty(pg_database_size('cipherflag'));"`
- Zeek logs accumulate — adjust retention in the Zeek container
- PCAP files are retained for 24 hours by default (configurable in `cipherflag.toml`)
