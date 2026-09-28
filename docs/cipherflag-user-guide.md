# CipherFlag User Guide

## What is CipherFlag?

CipherFlag is an open-source certificate intelligence platform that discovers TLS certificates from network traffic, scores their health, and provides interactive analytics for enterprise PKI management. It passively monitors traffic via Zeek, analyzes packet captures, and pushes discovered certificates to Venafi (Cloud or on-prem TPP) for lifecycle management.

This guide walks you through installation, configuration, and daily use.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [First Run](#3-first-run)
4. [Manual Configuration](#4-manual-configuration)
5. [Verifying Your Deployment](#5-verifying-your-deployment)
6. [Authentication](#6-authentication)
7. [Network Capture](#7-network-capture)
8. [Processing PCAP Files](#8-processing-pcap-files)
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
| Docker Compose | v2+ | Orchestrates the services (two, three with the Zeek sensor) |
| A web browser | Any modern browser | Access the CipherFlag dashboard |

**Installing Docker:** Follow the official guide for your OS:
- Linux: https://docs.docker.com/engine/install/
- macOS: https://docs.docker.com/desktop/install/mac-install/
- Windows: https://docs.docker.com/desktop/install/windows-install/ (WSL2 backend recommended)

### Network Requirements

- **Port 8443** must be accessible from your browser
- For live capture: a **Linux** host with **two network interfaces**:
  - **Management NIC** — SSH access, web UI (:8443), Venafi push (standard IP, routable)
  - **Capture NIC** — Receives mirrored/tapped traffic (connected to SPAN port, TAP, or cloud traffic mirror)

  On Docker Desktop (macOS, Windows) the sensor's host network is the
  Docker VM's, so it cannot capture the machine's traffic.
- For PCAP-only analysis: single NIC, no special network access needed, any platform

### Deployment Platforms

| Platform | Traffic Source | Capture Method |
|----------|---------------|----------------|
| **On-prem** | SPAN port / network TAP | Dual NIC, Zeek on capture interface |
| **AWS** | VPC Traffic Mirroring | EC2 with 2 ENIs, mirror target on capture ENI |
| **Azure** | Virtual Network TAP | VM with 2 NICs, TAP destination on capture NIC |
| **Azure (fallback)** | Network Watcher | PCAP capture to storage, copied into `./pcap-input/` |
| **PCAP-only** | Any | Copy `.pcap` files into `./pcap-input/<job>/` |

See the [How-To Deployment Guide](https://cipherflag.com/howto.html#deployment) for step-by-step platform instructions.

### Hardware Recommendations

| Deployment | CPU | RAM | Disk |
|------------|-----|-----|------|
| Evaluation / PCAP-only | 2 cores | 4 GB | 20 GB |
| Small network (< 1 Gbps) | 4 cores | 8 GB | 50 GB |
| Medium network (1-10 Gbps) | 8 cores | 16 GB | 100 GB |

---

## 2. Installation

```bash
git clone https://github.com/net4n6-dev/cipherflag.git
cd cipherflag
cp .env.example .env              # see section 4
docker compose up -d              # CipherFlag and Postgres
docker compose --profile zeek up -d   # add the Zeek network sensor
```

The [Quick Start Guide](quickstart.md) covers the same steps with a test
PCAP.

---

## 3. First Run

CE has no interactive setup wizard; it is configured through `.env`,
`config/cipherflag.toml` and the web UI's Settings (`cipherflag setup` only
prints a short summary).

1. Open `http://<your-ip>:8443`. The first visit shows the **Create Admin
   Account** page (see [section 6](#6-authentication)).
2. Choose discovery sources: the Zeek sensor (sections 7 and 8), the osquery
   webhook, the scanners, and the connectors in `config/cipherflag.toml`.
3. Optionally connect Venafi in **Settings > Venafi** (section 16).

---

## 4. Manual Configuration

CipherFlag uses two configuration files:

### `.env` — Docker Compose variables

```bash
NETWORK_INTERFACE=ens192        # interface the Zeek sensor captures on; empty = PCAP files only
ZEEK_PCAP_DIR=./pcap-input      # where the sensor takes PCAP files from (default)
POSTGRES_PASSWORD=changeme      # see below
```

`.env` configures the containers only; CipherFlag itself reads no
environment variables. If you change `POSTGRES_PASSWORD`, change the
password in `[storage] postgres_url` in `config/cipherflag.toml` to match,
or CipherFlag cannot connect to the database. Venafi is configured in
`config/cipherflag.toml` or Settings, not in `.env`.

### `config/cipherflag.toml` — Application settings

See [Configuration Reference](configuration.md) for all options.

Key sections:
- `[server]` — listen address
- `[storage]` — PostgreSQL connection
- `[analysis]` — health scoring rules and thresholds
- `[sources.zeek_file]`: Zeek log polling (`log_dir` is where the Compose
  sensor's logs are mounted, `/var/log/zeek/current`)
- `[export.venafi]` — Venafi Cloud or TPP integration

---

## 5. Verifying Your Deployment

After starting services, verify everything is running:

```bash
docker compose ps
```

These services should show "Up":
- `postgres` — database
- `cipherflag` — API server and dashboard
- `zeek`: network sensor (only when started with `--profile zeek`)

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

### Starting the Sensor

The Zeek sensor is an opt-in Compose service. Set the capture interface in
`.env` and start it with the `zeek` profile:

```bash
echo 'NETWORK_INTERFACE=ens192' >> .env
docker compose --profile zeek up -d
```

The sensor uses the host's network (and the `NET_RAW`/`NET_ADMIN`
capabilities) to capture, so live capture needs a Linux host. It writes JSON
logs to the `zeek-logs` volume, rotated hourly; CipherFlag reads them from
`[sources.zeek_file] log_dir`, polling every 30 seconds by default.

The **network interface** field in Settings > Sources is saved to
`config/cipherflag.toml` but does not choose the capture interface; the
Compose sensor captures on `NETWORK_INTERFACE`.

Any other Zeek sensor works too, as long as it writes JSON logs with the
certificates in them (`@load policy/tuning/json-logs` and
`@load policy/protocols/ssl/log-certs-base64`) to a directory CipherFlag can
read; point `log_dir` at it.

### Setting Up a SPAN Port

Connect the capture interface to a SPAN/mirror port on your switch or a network TAP. CipherFlag sees a copy of all traffic on that segment and extracts TLS certificates from the handshakes.

### What Gets Captured

For each TLS connection whose certificates Zeek can see, CipherFlag records:
- The certificate chain the server sent (leaf, intermediates, and a root if sent), each stored in full
- Server hostname (SNI), IP address, and port
- Negotiated TLS version and cipher suite
- JA3/JA3S fingerprints

Zeek sees certificates in TLS 1.2 and earlier handshakes. TLS 1.3 encrypts
the server's certificate, so TLS 1.3 sessions yield no certificate.

### Monitoring Capture Activity

After each poll that found something, CipherFlag logs what it ingested:

```bash
docker compose logs -f cipherflag | grep 'zeek:'
# zeek: ingested logs certificates=12 observations=40 observations_unknown_cert=0 ...
```

`observations_unknown_cert` counts sessions whose certificate was not in
the logs read so far; `unparseable_lines` counts log lines that were not
valid Zeek JSON.

---

## 8. Processing PCAP Files

For offline analysis, hand packet captures to the Zeek sensor through a
directory (there is no upload page or API in CE). With the `zeek` profile
running, give each capture its own job directory under `./pcap-input/` (or
`ZEEK_PCAP_DIR`):

```bash
mkdir -p pcap-input/branch-office-2026-09
cp capture.pcap pcap-input/branch-office-2026-09/
```

The sensor checks for new files every 5 seconds, runs Zeek over each, and
marks the job:

```bash
docker compose exec zeek ls -a /zeek-logs/branch-office-2026-09
# .done     processed: CipherFlag reads the job's logs on its next poll
# .failed   Zeek could not process it (the reason is in: docker compose logs zeek)
```

A job is processed once. To process a capture again, copy it into a new job
directory; certificates already stored are updated, not duplicated.

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
- **Zeek File Poller**: enable/disable, log directory, poll interval (5-300 seconds), and a network interface field. The interface list shows the interfaces of the machine CipherFlag runs on (inside Docker, its container's); the saved value is not used for capture, which the sensor's `NETWORK_INTERFACE` controls.
- **Corelight** — enable/disable, API URL, API token

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

1. CipherFlag discovers certificates via Zeek (live or from PCAP files) or any other source
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

- Verify Zeek is running: `docker compose --profile zeek ps` and `docker compose logs zeek`
- Confirm `NETWORK_INTERFACE` is correct and receiving traffic (TLS 1.3-only traffic yields no certificates)
- For PCAP files, check the job's marker: `docker compose exec zeek ls -a /zeek-logs/<job>` (`.done` or `.failed`)
- Check that CipherFlag reads the logs: `docker compose logs cipherflag | grep 'zeek:'` shows what each poll ingested, or warns that `log_dir` does not exist

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
- Zeek logs accumulate: the sensor rotates them hourly but does not delete old ones. Remove rotated logs (`<log>.<time>.log`) and finished job directories from the `zeek-logs` volume once CipherFlag has read them
- PCAP files in `./pcap-input/` are not removed after processing; delete them when no longer needed
