# CipherFlag User Guide

## What is CipherFlag?

CipherFlag is a free, open-source tool that discovers TLS/SSL certificates on your network and builds an inventory of them. It works by passively watching network traffic -- it does not scan or probe your systems. You can also feed it packet capture (PCAP) files for offline analysis.

CipherFlag scores each certificate against 16 industry-standard rules (expiration, key strength, signature algorithm, chain trust, revocation, and Certificate Transparency compliance) and assigns a health grade from A+ to F. The results are available in an interactive dashboard and can be exported to Venafi Trust Protection Platform or downloaded as CSV/JSON files.

This guide walks you through the complete process: from downloading CipherFlag to having a working certificate inventory with Venafi integration.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Download CipherFlag](#2-download-cipherflag)
3. [Initial Configuration](#3-initial-configuration)
4. [Deploy CipherFlag](#4-deploy-cipherflag)
5. [Verify the Deployment](#5-verify-the-deployment)
6. [Collect Network Traffic](#6-collect-network-traffic)
7. [Upload PCAP Files for Offline Analysis](#7-upload-pcap-files-for-offline-analysis)
8. [Explore the Dashboard](#8-explore-the-dashboard)
9. [Export Certificate Inventory](#9-export-certificate-inventory)
10. [Integrate with Venafi TPP](#10-integrate-with-venafi-tpp)
11. [Generate Reports](#11-generate-reports)
12. [Ongoing Operations](#12-ongoing-operations)
13. [Troubleshooting](#13-troubleshooting)
14. [Appendix: Configuration Reference](#appendix-configuration-reference)

---

## 1. Prerequisites

Before you begin, make sure you have the following on the machine where you will run CipherFlag.

### Required Software

| Software | Minimum Version | Purpose |
|----------|----------------|---------|
| Docker | 20.10+ | Runs the CipherFlag containers |
| Docker Compose | v2+ | Orchestrates the three services |
| A web browser | Any modern browser | Access the CipherFlag dashboard |

**Installing Docker:** If Docker is not installed, follow the official guide for your operating system:
- Linux: https://docs.docker.com/engine/install/
- macOS: https://docs.docker.com/desktop/install/mac-install/
- Windows: https://docs.docker.com/desktop/install/windows-install/ (WSL2 backend recommended)

After installation, verify Docker is working:

```bash
docker --version
docker compose version
```

### Network Requirements

- **Port 8443** must be accessible from your browser (this is the CipherFlag web interface)
- If using live network capture: the machine needs access to a **SPAN port**, **mirror port**, or **network TAP** that copies traffic to a network interface
- If using PCAP upload only: no special network access is needed

### Hardware Recommendations

| Deployment | CPU | RAM | Disk |
|------------|-----|-----|------|
| Evaluation / PCAP-only | 2 cores | 4 GB | 20 GB |
| Small network (< 1 Gbps) | 4 cores | 8 GB | 50 GB |
| Medium network (1-10 Gbps) | 8 cores | 16 GB | 100 GB |

Disk usage depends on traffic volume and certificate diversity. Zeek logs and the PostgreSQL database are the primary consumers.

---

## 2. Download CipherFlag

### Option A: Download from cyberflag.ai

Go to [https://cyberflag.ai/download](https://cyberflag.ai/download) and download the latest release archive.

Extract the archive:

```bash
tar xzf cipherflag-v1.0.0.tar.gz
cd cipherflag
```

### Option B: Clone from GitHub

```bash
git clone https://github.com/cipherflag/cipherflag.git
cd cipherflag
```

### What You Get

After downloading, the `cipherflag/` directory contains:

```
cipherflag/
├── docker-compose.yml     # Deployment orchestration
├── .env.example           # Environment variable template
├── config/
│   └── cipherflag.toml    # Application configuration
├── docker/
│   └── zeek/              # Zeek sensor container files
├── Dockerfile             # CipherFlag container build
├── docs/                  # Additional documentation
└── LICENSE                # Apache 2.0 license
```

---

## 3. Initial Configuration

CipherFlag uses an environment file (`.env`) for deployment settings. Start by creating your configuration:

```bash
cp .env.example .env
```

Open `.env` in a text editor. Here are the settings you need to decide on:

### Database Password

Change the default password for any deployment beyond local evaluation:

```bash
POSTGRES_PASSWORD=your-secure-password-here
```

### Network Interface (Optional)

If you have a SPAN port or mirror port available, set the network interface that receives the mirrored traffic:

```bash
NETWORK_INTERFACE=eth1
```

To find available interfaces on Linux:
```bash
ip link show
```

On macOS:
```bash
ifconfig -l
```

**Leave this blank** if you plan to use PCAP upload only. You can always add live capture later.

### Venafi Integration (Optional)

Leave the Venafi settings at their defaults for now. We will configure them in [Section 10](#10-integrate-with-venafi-tpp) after CipherFlag is running and collecting data.

Your `.env` file should look something like this:

```bash
# Network capture
NETWORK_INTERFACE=eth1          # or leave empty for PCAP-only mode

# Database
POSTGRES_PASSWORD=MySecurePass123

# Venafi (configure later)
VENAFI_ENABLED=false
VENAFI_BASE_URL=
VENAFI_CLIENT_ID=
VENAFI_REFRESH_TOKEN=
VENAFI_FOLDER=\VED\Policy\Discovered\CipherFlag
```

---

## 4. Deploy CipherFlag

Start all three services with a single command:

```bash
docker compose up -d
```

This downloads the required container images and starts:

| Container | What It Does |
|-----------|-------------|
| **postgres** | Stores all certificate data, observations, and health reports |
| **zeek** | Network sensor that watches for TLS handshakes and extracts certificate data |
| **cipherflag** | The API server and web dashboard |

The first startup takes 1-2 minutes while containers are downloaded and the database is initialized. On subsequent starts, it takes a few seconds.

Watch the startup progress:

```bash
docker compose logs -f
```

You will see messages like:
```
cipherflag  | CipherFlag API server starting addr=0.0.0.0:8443
zeek        | Starting live capture on interface: eth1
```

Press `Ctrl+C` to stop watching logs (the containers continue running).

---

## 5. Verify the Deployment

### Check that all containers are running

```bash
docker compose ps
```

All three services should show `Up` status. The postgres service should show `(healthy)`.

### Test the API

```bash
curl http://localhost:8443/healthz
```

Expected response:
```json
{"status":"ok"}
```

### Open the Dashboard

Open [http://localhost:8443](http://localhost:8443) in your web browser.

You will see the CipherFlag dashboard. If you configured a network interface, certificates will begin appearing within seconds as Zeek detects TLS handshakes on the monitored traffic. If no interface is configured, the dashboard will be empty -- proceed to the next section to upload a PCAP file.

---

## 6. Collect Network Traffic

CipherFlag collects certificate data in two ways: live passive capture and PCAP file upload. You can use either or both.

### Live Passive Capture

If you set `NETWORK_INTERFACE` in your `.env` file, CipherFlag is already collecting data. Zeek passively monitors the specified interface for TLS handshakes and extracts certificate information without affecting traffic flow.

**How to set up a SPAN port:**

Most managed switches support port mirroring (also called SPAN). The general process is:

1. Log into your switch management interface
2. Configure a SPAN session that mirrors traffic from source ports (the ports carrying traffic you want to monitor) to a destination port
3. Connect the destination port to a network interface on the CipherFlag host
4. Set `NETWORK_INTERFACE` in `.env` to that interface name

Consult your switch vendor's documentation for specific steps. Common platforms:
- Cisco: `monitor session` commands
- Juniper: Port mirroring configuration
- Arista: `monitor session` commands
- VMware vSwitch: Promiscuous mode on port group

**What gets collected:**

CipherFlag extracts the following from every observed TLS handshake:
- The server certificate and any intermediate certificates in the chain
- The TLS version and cipher suite negotiated
- Server IP address and port
- Server Name Indication (SNI)
- JA3/JA3S fingerprints
- Connection metadata (client IP, duration)

No application payload data is captured or stored.

### Verifying Collection

After a few minutes of live capture, check the dashboard:
- The **certificate count** on the dashboard should be increasing
- The **PKI Explorer** page shows the certificate authority hierarchy
- The **Analytics** page shows cipher suite and TLS version distributions

You can also check Zeek's output directly:

```bash
docker compose exec zeek ls -la /zeek-logs/
```

You should see `x509.log`, `ssl.log`, and `conn.log` files.

---

## 7. Upload PCAP Files for Offline Analysis

PCAP upload is useful for:
- Evaluating CipherFlag before setting up live capture
- Analyzing traffic from a different network segment
- Processing historical captures
- One-time audits

### Capture Traffic (if you do not already have a PCAP file)

On the machine where traffic flows (or on the CipherFlag host if it has a network interface):

```bash
# Capture 60 seconds of TLS traffic
sudo tcpdump -i eth0 -w capture.pcap -G 60 -W 1 port 443
```

Replace `eth0` with your network interface. This creates a file called `capture.pcap` containing 60 seconds of HTTPS traffic.

### Upload via the Web Interface

1. Open [http://localhost:8443](http://localhost:8443) in your browser
2. Click **Upload** in the navigation bar
3. Drag and drop your `.pcap` or `.pcapng` file onto the upload zone, or click to browse
4. Wait for processing to complete (a progress indicator shows the current status)
5. When complete, you will see a summary:
   - **Certificates found** -- total certificates extracted from the capture
   - **New certificates** -- certificates not previously seen by CipherFlag
6. Click the link to view the discovered certificates

### Upload via the API

For automation or scripting, use the REST API:

```bash
# Upload a PCAP file
curl -X POST http://localhost:8443/api/v1/pcap/upload \
  -F "file=@capture.pcap"
```

This returns a job object with an ID. Poll for completion:

```bash
# Check job status (replace JOB_ID with the returned ID)
curl http://localhost:8443/api/v1/pcap/jobs/JOB_ID
```

The job transitions through these states: `queued` -> `processing` -> `complete` (or `failed`).

### File Size Limits

The default maximum PCAP file size is 500 MB. For larger captures, split them with `tcpdump`:

```bash
# Split a large capture into 100 MB chunks
tcpdump -r large-capture.pcap -w chunk.pcap -C 100
```

Upload each chunk separately. CipherFlag deduplicates certificates automatically.

---

## 8. Explore the Dashboard

Once CipherFlag has data, the dashboard provides several views:

### Dashboard (Home)

The main dashboard shows:
- **Certificate count** and **observation count**
- **Grade distribution** pie chart (A+ through F)
- **Expiry timeline** -- certificates expiring in the coming weeks
- **Top issuers** -- which CAs issued the most certificates on your network

### PKI Explorer

A hierarchical tree view of your certificate authority structure:
- Root CAs at the top
- Intermediate CAs nested underneath
- Leaf certificates grouped by issuer
- Click any certificate to see its details, health report, and chain

### Certificates

A searchable, filterable table of all discovered certificates:
- **Search** by common name, organization, fingerprint, or serial number
- **Filter** by grade (A+, A, B, C, D, F), discovery source, CA status, expiration
- **Sort** by expiry date, grade, common name, or last seen
- Click any certificate for full details including subject, issuer, key info, SANs, health findings, and observation history

### Analytics

Cipher suite and protocol analytics:
- TLS version distribution (how much TLS 1.0/1.1/1.2/1.3 traffic)
- Cipher strength distribution (Best/Strong/Acceptable/Weak/Insecure)
- Issuer breakdown with average health scores

### Certificate Detail

Click any certificate to see:
- Full subject and issuer details
- Validity period and days until expiry
- Key algorithm and size
- Subject Alternative Names
- Health report with grade, score, and specific findings
- Remediation recommendations for each finding
- Observation history (where and when the certificate was seen)
- Certificate chain visualization

---

## 9. Export Certificate Inventory

CipherFlag supports exporting your certificate inventory in two formats.

### Export from the Web Interface

1. Navigate to the **Certificates** page
2. Apply any filters you want (e.g., only Grade D and F certificates)
3. Click the **Export** button in the top-right area
4. Choose **CSV** or **JSON**
5. Your browser downloads the file

The export respects your current filters -- if you are viewing only expiring certificates, the export contains only those certificates.

### Export via the API

```bash
# Export all certificates as CSV
curl -o certificates.csv \
  "http://localhost:8443/api/v1/export/certificates?format=csv"

# Export all certificates as JSON
curl -o certificates.json \
  "http://localhost:8443/api/v1/export/certificates?format=json"

# Export only failing certificates (Grade D and F)
curl -o failing.csv \
  "http://localhost:8443/api/v1/export/certificates?format=csv&grade=D,F"

# Export certificates expiring within 30 days
curl -o expiring.csv \
  "http://localhost:8443/api/v1/export/certificates?format=csv&expiring_within_days=30"

# Export certificates from a specific source
curl -o zeek-certs.json \
  "http://localhost:8443/api/v1/export/certificates?format=json&source=zeek_passive"
```

### CSV Format

The CSV export is designed to be compatible with Venafi's bulk import template. Columns include:

| Column | Description |
|--------|------------|
| Fingerprint SHA256 | Unique certificate identifier |
| Subject CN | Common name (e.g., www.example.com) |
| Subject Organization | Organization name |
| Subject Full DN | Full distinguished name |
| Issuer CN | Issuing CA common name |
| Issuer Organization | Issuing CA organization |
| Serial Number | Certificate serial |
| Not Before / Not After | Validity period |
| Key Algorithm / Size | e.g., RSA 2048, ECDSA 256 |
| Signature Algorithm | e.g., SHA256WithRSA |
| Subject Alt Names | All SANs, semicolon-separated |
| Discovery Source | How the certificate was found |
| First Seen / Last Seen | When CipherFlag first and last observed it |

---

## 10. Integrate with Venafi TPP

CipherFlag can automatically push discovered certificates to Venafi Trust Protection Platform. This is the primary integration for building certificate inventory in Venafi from network-observed data.

### What This Integration Does

- CipherFlag periodically checks for new or updated certificates (default: every 60 minutes)
- New certificates are pushed to a configurable policy folder in Venafi TPP
- Each certificate includes its PEM data, discovery metadata, observed endpoints, and health grade
- Venafi deduplicates by certificate thumbprint, so pushing the same certificate twice is safe

### Step 1: Create an API Integration in Venafi

1. Log into the Venafi TPP web console as an administrator
2. Navigate to **API** > **API Integrations**
3. Click **Create New Integration** and configure:
   - **Name:** CipherFlag
   - **Grant types:** Resource Owner, Refresh Token
   - **Scope:** `certificate:manage` (minimum required)
   - **Token refresh:** Enabled (recommended: 90-day lifetime)
4. After creation, note the **Client ID** displayed

### Step 2: Create the Target Policy Folder

In Venafi TPP:
1. Navigate to **Policy** > **Discovered** (or create your preferred folder structure)
2. Create a folder called **CipherFlag** (or choose your own name)
3. Ensure the service account used by CipherFlag has **Create** permission on this folder

The folder path will look like: `\VED\Policy\Discovered\CipherFlag`

### Step 3: Obtain a Refresh Token

Run this command, replacing the placeholder values:

```bash
curl -X POST "https://your-tpp-server.example.com/vedauth/authorize/oauth" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id-from-step-1",
    "username": "your-tpp-username",
    "password": "your-tpp-password",
    "scope": "certificate:manage"
  }'
```

The response looks like:
```json
{
  "access_token": "...",
  "refresh_token": "ABC123...",
  "expires": 3600
}
```

Copy the `refresh_token` value. CipherFlag uses this to automatically obtain and renew short-lived access tokens. You will not need to manually refresh tokens.

### Step 4: Configure CipherFlag

Edit your `.env` file:

```bash
VENAFI_ENABLED=true
VENAFI_BASE_URL=https://your-tpp-server.example.com/vedsdk
VENAFI_CLIENT_ID=your-client-id-from-step-1
VENAFI_REFRESH_TOKEN=ABC123...
VENAFI_FOLDER=\VED\Policy\Discovered\CipherFlag
```

Restart CipherFlag to apply the configuration:

```bash
docker compose restart cipherflag
```

### Step 5: Verify the Integration

Check the CipherFlag logs for Venafi activity:

```bash
docker compose logs -f cipherflag | grep -i venafi
```

You should see messages about certificate pushes. Then verify in Venafi TPP:
1. Navigate to the policy folder you configured
2. Certificates discovered by CipherFlag should appear within the push interval (default: 60 minutes)

### Adjusting the Push Interval

To change how often CipherFlag pushes to Venafi, edit `config/cipherflag.toml`:

```toml
[export.venafi]
push_interval_minutes = 30    # Push every 30 minutes instead of 60
```

Then restart:
```bash
docker compose restart cipherflag
```

---

## 11. Generate Reports

CipherFlag provides several ways to generate reports from your certificate inventory.

### Dashboard Reports

The dashboard itself serves as a live report. Key metrics available at a glance:
- Total certificates and observations
- Grade distribution (how many A+, A, B, C, D, F)
- Certificates expiring in 30, 60, 90 days
- Critical findings count

### Expiration Report

To get a list of certificates expiring soon:

```bash
# Certificates expiring within 30 days
curl -o expiring-30d.csv \
  "http://localhost:8443/api/v1/export/certificates?format=csv&expiring_within_days=30"

# Certificates expiring within 90 days
curl -o expiring-90d.csv \
  "http://localhost:8443/api/v1/export/certificates?format=csv&expiring_within_days=90"
```

### Compliance Report

To identify certificates that do not meet your security policy:

```bash
# All failing certificates (Grade F -- expired, weak keys, broken signatures)
curl -o compliance-failures.csv \
  "http://localhost:8443/api/v1/export/certificates?format=csv&grade=F"

# All certificates below Grade B
curl -o below-threshold.csv \
  "http://localhost:8443/api/v1/export/certificates?format=csv&grade=C,D,F"
```

### Issuer Report

The Stats API provides issuer-level analytics:

```bash
curl http://localhost:8443/api/v1/stats/issuers | python3 -m json.tool
```

This returns each issuer with certificate count, average health score, and worst grade.

### Cipher and Protocol Report

```bash
curl http://localhost:8443/api/v1/stats/ciphers | python3 -m json.tool
```

This shows TLS version distribution, cipher strength breakdown, and the full cipher-TLS matrix for your network.

### Scheduled Reports

CipherFlag does not have built-in report scheduling. To generate reports on a schedule, use a cron job:

```bash
# Add to crontab: daily expiration report at 7 AM
0 7 * * * curl -s -o /reports/expiring-30d-$(date +\%Y\%m\%d).csv \
  "http://localhost:8443/api/v1/export/certificates?format=csv&expiring_within_days=30"
```

---

## 12. Ongoing Operations

### Updating CipherFlag

When a new version is released:

```bash
cd cipherflag
git pull                      # or download the new release
docker compose build          # Rebuild containers
docker compose up -d          # Restart with new version
```

Database migrations are applied automatically on startup. Your data is preserved.

### Monitoring Health

Check container status:
```bash
docker compose ps
```

Check disk usage (Zeek logs and database):
```bash
docker system df
```

View real-time logs:
```bash
docker compose logs -f cipherflag    # Application logs
docker compose logs -f zeek          # Sensor logs
```

### Backup

The certificate database is stored in a Docker volume. To back it up:

```bash
# Create a database dump
docker compose exec postgres pg_dump -U cipherflag cipherflag > backup.sql

# Restore from backup
docker compose exec -T postgres psql -U cipherflag cipherflag < backup.sql
```

### Stopping and Starting

```bash
# Stop all services (data is preserved)
docker compose down

# Start again
docker compose up -d

# Stop and remove all data (fresh start)
docker compose down -v
```

### Security Considerations

CipherFlag v1 does not include built-in authentication. Protect your deployment with one of:

- **Network segmentation** -- only allow access from a management VLAN or jump host
- **Reverse proxy** -- place nginx or Caddy in front of CipherFlag with basic auth or SSO
- **Firewall rules** -- restrict port 8443 to specific IP addresses

---

## 13. Troubleshooting

### Containers will not start

**Check Docker is running:**
```bash
docker info
```

**Check for port conflicts:**
```bash
# Is port 8443 already in use?
lsof -i :8443
```

**Check container logs:**
```bash
docker compose logs postgres
docker compose logs cipherflag
docker compose logs zeek
```

### No certificates appearing (live capture)

1. **Verify the network interface exists** and is receiving traffic:
   ```bash
   docker compose exec zeek ip link show
   ```

2. **Verify Zeek is running and producing logs:**
   ```bash
   docker compose exec zeek ls -la /zeek-logs/
   ```
   You should see `x509.log` and `ssl.log` files that are growing.

3. **Check that traffic is reaching the interface:**
   ```bash
   docker compose exec zeek tcpdump -i $NETWORK_INTERFACE -c 10 port 443
   ```
   If no packets appear, the SPAN port or mirror is not configured correctly.

4. **Check the CipherFlag poller logs:**
   ```bash
   docker compose logs cipherflag | grep -i "zeek\|poller\|ingest"
   ```

### PCAP upload stuck in "processing"

1. **Check Zeek container logs:**
   ```bash
   docker compose logs zeek | tail -20
   ```

2. **Check if the sentinel file was created:**
   ```bash
   docker compose exec cipherflag ls /zeek-logs/
   ```
   Look for a directory matching the job ID with a `.done` file inside it.

3. **Check for PCAP processing errors:**
   ```bash
   docker compose exec zeek ls /pcap-input/
   ```

### Venafi push not working

See the detailed troubleshooting section in the [Venafi Export Guide](venafi-export.md), covering:
- Connection and timeout errors
- Authentication (401) errors
- Certificates not appearing in Venafi
- Missing PEM data

### Database connection errors

```bash
# Check postgres is healthy
docker compose exec postgres pg_isready -U cipherflag

# Check CipherFlag can reach postgres
docker compose logs cipherflag | grep -i "database\|postgres\|connect"
```

### High disk usage

Zeek logs accumulate over time. CipherFlag cleans up processed logs, but if disk is growing:

```bash
# Check Zeek log size
docker compose exec zeek du -sh /zeek-logs/

# Check database size
docker compose exec postgres psql -U cipherflag -c "SELECT pg_size_pretty(pg_database_size('cipherflag'));"
```

To reduce log retention, edit `config/cipherflag.toml`:
```toml
[sources.zeek_file]
poll_interval_seconds = 15    # Process logs faster
```

---

## Appendix: Configuration Reference

### Environment Variables (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_INTERFACE` | *(empty)* | Network interface for live capture. Leave empty for PCAP-only. |
| `POSTGRES_PASSWORD` | `changeme` | Database password. Change for non-local deployments. |
| `VENAFI_ENABLED` | `false` | Enable automated push to Venafi TPP. |
| `VENAFI_BASE_URL` | *(empty)* | Venafi TPP SDK URL (e.g., `https://tpp.example.com/vedsdk`). |
| `VENAFI_CLIENT_ID` | *(empty)* | OAuth2 client ID from Venafi API integration. |
| `VENAFI_REFRESH_TOKEN` | *(empty)* | OAuth2 refresh token for authentication. |
| `VENAFI_FOLDER` | `\VED\Policy\Discovered\CipherFlag` | Target policy folder in Venafi. |

### Application Configuration (config/cipherflag.toml)

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[server]` | `listen` | `0.0.0.0:8443` | API server listen address |
| `[analysis]` | `recheck_interval_hours` | `6` | How often to re-score certificates |
| `[analysis]` | `expiry_warning_days` | `[30, 60, 90, 180]` | Warning thresholds for expiration |
| `[analysis.protocol_policy]` | `min_tls_version` | `1.2` | Minimum acceptable TLS version |
| `[analysis.protocol_policy]` | `require_forward_secrecy` | `true` | Flag ciphers without FS |
| `[analysis.protocol_policy]` | `require_aead` | `true` | Flag non-AEAD ciphers |
| `[analysis.protocol_policy]` | `banned_ciphers` | `[RC4, DES, 3DES, NULL, EXPORT]` | Blocked cipher suites |
| `[sources.zeek_file]` | `enabled` | `true` | Enable Zeek log polling |
| `[sources.zeek_file]` | `log_dir` | `/var/log/zeek/current` | Zeek log directory |
| `[sources.zeek_file]` | `poll_interval_seconds` | `30` | How often to check for new logs |
| `[export.venafi]` | `push_interval_minutes` | `60` | How often to push to Venafi |
| `[pcap]` | `max_file_size_mb` | `500` | Maximum PCAP upload size |
| `[pcap]` | `retention_hours` | `24` | How long to keep processed PCAPs |

### Health Scoring Rules

| Rule | Severity | What It Checks |
|------|----------|---------------|
| EXP-001 | Critical | Certificate has expired |
| EXP-002 | Critical | Expires within 7 days |
| EXP-003 | High | Expires within 30 days |
| EXP-004 | Medium | Expires within 90 days |
| EXP-005 | Medium | Validity exceeds 398 days |
| KEY-001 | Critical | RSA key < 2048 bits |
| KEY-002 | Low | RSA key is 2048 bits (4096 recommended) |
| KEY-003 | Critical | ECDSA key < 256 bits |
| KEY-004 | Medium | Unknown key algorithm |
| SIG-001 | Critical | SHA-1 signature (broken) |
| SIG-002 | Critical | MD5 signature (broken) |
| SIG-003 | Medium | Unknown signature algorithm |
| CHN-001 | High | Self-signed end-entity certificate |
| REV-001 | High | No OCSP or CRL endpoints |
| REV-002 | Medium | No OCSP (CRL only) |
| SCT-001 | Medium | No Certificate Transparency SCTs |

### Grade Scale

| Grade | Score Range | Meaning |
|-------|------------|---------|
| A+ | 95-100 | Excellent -- meets all best practices |
| A | 85-94 | Good -- minor improvements possible |
| B | 70-84 | Acceptable -- some issues to address |
| C | 50-69 | Below standard -- action recommended |
| D | 20-49 | Poor -- significant issues |
| F | 0-19 or critical fail | Failing -- immediate action required |

---

*CipherFlag is licensed under the Apache License 2.0. For questions, issues, or contributions, visit [https://github.com/cipherflag/cipherflag](https://github.com/cipherflag/cipherflag).*
