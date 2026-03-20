# CipherFlag v1 Open-Source Certificate Inventory Tool — Design Spec

## Problem Statement

Organizations need visibility into certificates traversing their network to build and maintain certificate inventory. Commercial solutions (ExtraHop, Vectra) offer this as part of broader NDR platforms, but the cost is not justified when certificate inventory is the only requirement. There is no lightweight, open-source tool that passively discovers certificates from network traffic and feeds that inventory into enterprise certificate management platforms like Venafi.

## Solution

CipherFlag v1 is a containerized, open-source certificate inventory tool that:

1. Passively monitors network traffic via Zeek to discover TLS certificates
2. Accepts PCAP uploads for offline/ad-hoc analysis
3. Scores certificate health against industry standards
4. Exports discovered inventory to Venafi TPP and as CSV/JSON
5. Ships as a single `docker-compose up` experience

CipherFlag is not intended to replace commercial NDR platforms. It is a focused tool that fills the gap for organizations that need certificate inventory without the cost of a full platform.

## Target Users

**Primary (v1):** Small/mid security teams that need certificate visibility but cannot justify commercial NDR platforms. They get a single container deployment, plug in a SPAN port or feed PCAPs, and get a certificate inventory dashboard with Venafi export.

**Secondary (v1.1+):** Enterprise teams with existing Corelight sensors or Zeek deployments who want to add certificate inventory without additional commercial tooling. They drop the Zeek container and point CipherFlag at their existing log output.

## Architecture

### Container Topology (Docker Compose, 3 Services)

```
┌─────────────────────────────────────────────────────┐
│  docker-compose up                                  │
│                                                     │
│  ┌──────────────┐    /zeek-logs/     ┌───────────┐  │
│  │              │ ──────────────────>│           │  │
│  │  zeek-sensor │  x509.log          │ cipherflag│  │
│  │              │  ssl.log           │  (Go API  │  │
│  │  Listens on  │  conn.log          │  + static │  │
│  │  NET_IF or   │                    │  frontend)│  │
│  │  reads PCAPs │                    │           │  │
│  └──────────────┘                    └─────┬─────┘  │
│                                            │        │
│  ┌─────────────────────────────────────────┘        │
│  │                                                  │
│  │  ┌────────────┐                                  │
│  └─>│ postgresql │                                  │
│     │            │                                  │
│     │ cipherflag │                                  │
│     │ database   │                                  │
│     └────────────┘                                  │
└─────────────────────────────────────────────────────┘
```

**Why 3 services (not a monolith):**

- Clean separation of concerns — each container does one thing
- Users can swap PostgreSQL for an existing instance
- Corelight customers drop the Zeek container and run only CipherFlag + PostgreSQL
- The shared volume boundary (`/zeek-logs/`) makes CipherFlag sensor-agnostic
- Standard pattern, easy to extend with additional services later

### Shared Volumes

| Volume | Writer | Reader | Purpose |
|--------|--------|--------|---------|
| `zeek-logs` | zeek-sensor | cipherflag | Zeek log output (x509.log, ssl.log, conn.log) |
| `pcap-input` | cipherflag | zeek-sensor | PCAP files uploaded for offline analysis |
| `pg-data` | postgresql | postgresql | Database persistence |

### Zeek Sensor Container

- Base image: `zeek/zeek` (official open-source Zeek)
- Default mode runs both live capture and PCAP processing simultaneously:
  - Live capture: `zeek -i <interface>` for passive network monitoring (disabled if `NETWORK_INTERFACE` is unset)
  - PCAP watcher: background inotify/polling loop watches `/pcap-input/` and spawns `zeek -r <file>` for each new .pcap file
  - Both capabilities run concurrently — uploading a PCAP does not interrupt live capture
- Configured to output JSON format (`@load policy/tuning/json-logs`)
- Certificate PEM extraction enabled (`@load policy/protocols/ssl/extract-certs-pem`)
- Log rotation enabled (`LogRotationInterval = 1 hr`) to bound disk usage; processed logs are eligible for cleanup by CipherFlag's poller
- Logs written to `/zeek-logs/`
- PCAP completion signaling: the entrypoint script writes a sentinel file (`/zeek-logs/<job-id>/.done`) after each `zeek -r` process exits, enabling the CipherFlag poller to distinguish "still processing" from "complete with zero results"

### CipherFlag Container

- Multi-stage Docker build: Go binary + SvelteKit static assets in minimal runtime image
- Serves API and frontend on port 8443 (embedded static files; code default in `config.go` must be updated from 8080 to 8443)
- Background goroutine polls `/zeek-logs/` for new log entries
- PCAP upload endpoint writes files to `/pcap-input/` shared volume

### PostgreSQL Container

- Standard `postgres:15-alpine`
- Data persisted via Docker volume `pg-data`
- Auto-initialized via CipherFlag's existing migration system on first start

## Zeek Log Parsing & Certificate Ingestion

### Log Sources

**x509.log** — primary certificate data:
- Certificate fingerprint (SHA256), serial number
- Subject/issuer DN, subject CN
- Validity period (not_before, not_after)
- Key algorithm, key length, signature algorithm
- SAN entries (DNS names, IPs, emails)
- CA flag (basic constraints)
- OCSP/CRL URLs, SCT presence

**ssl.log** — network observation context:
- Server IP and port
- TLS version negotiated
- Cipher suite negotiated
- JA3/JA3S fingerprints
- SNI (server name indication)
- Certificate chain (links to x509.log via file IDs)

**conn.log** — connection metadata correlation:
- Connection UID (joins ssl.log to conn.log)
- Duration, bytes transferred
- Connection state

### Ingestion Pipeline

```
Zeek logs (JSON)
    → File poller (watches /zeek-logs/, tracks cursor via ingestion_state table)
        → Log parser (deserializes x509/ssl/conn JSON records)
            → Certificate builder (maps Zeek fields → CipherFlag Certificate model)
                → Deduplicator (upsert by SHA256 fingerprint, update last_seen)
                    → Health scorer (runs scoring analysis on new/updated certs)
                        → Observation recorder (creates CertificateObservation + EndpointProfile)
```

### Design Decisions

- **JSON log format:** Zeek supports JSON output natively. Easier to parse than Zeek's default TSV format with header-based typing.
- **Cursor-based polling:** The existing `ingestion_state` table tracks file byte position per log file. On restart, CipherFlag resumes where it left off. No data loss, no reprocessing.
- **Poll interval:** Configurable, defaults to 30 seconds (existing config key `sources.zeek_file.poll_interval_seconds`).
- **Batch upserts:** The existing `BatchUpsertCertificates` store method needs to be reimplemented with proper batch inserts (multi-row `INSERT ... ON CONFLICT` or `pgx.CopyFrom`) before ingestion begins. The current implementation loops single-row upserts, which will be a bottleneck at volume. The poller accumulates records and flushes in batches (100 records or 5 seconds, whichever comes first).
- **Real X.509 parsing:** For PEM files extracted by Zeek (`extract-certs-pem` policy), Go's `crypto/x509` package parses the full certificate. This captures fields Zeek doesn't expose (extended key usage details, policy OIDs) and provides the raw PEM for Venafi export.
- **Log cleanup:** After the poller successfully ingests a Zeek log file and advances the cursor past its end, the file becomes eligible for deletion. Combined with Zeek's log rotation, this bounds disk usage on the shared volume.

## PCAP Upload Flow

### User Experience

- New page at `/upload` with drag-and-drop or file picker for .pcap/.pcapng files
- Upload progress bar with status transitions: Uploading → Queued → Processing → Complete
- Summary on completion: certificates found, new vs. already known, health grades
- Link to filtered certificate list showing only certs discovered from that upload

### API

- `POST /api/v1/pcap/upload` — multipart file upload, returns job ID
- `GET /api/v1/pcap/jobs/{id}` — poll job status and results
- Size limit configurable (default 500MB)

### Processing Flow

```
Upload hits CipherFlag API
    → File written to /pcap-input/ shared volume
    → Zeek container's file watcher detects new .pcap
    → Zeek runs: zeek -r /pcap-input/<file>.pcap
    → Logs written to /zeek-logs/<job-id>/
    → CipherFlag poller picks up logs from job subdirectory
    → Normal ingestion pipeline (parse → dedupe → score → store)
    → Job status updated to complete with summary stats
```

### Database Addition

```sql
CREATE TABLE pcap_jobs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename      TEXT NOT NULL,
    file_size     BIGINT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'queued',
    certs_found   INTEGER DEFAULT 0,
    certs_new     INTEGER DEFAULT 0,
    error         TEXT,
    created_at    TIMESTAMPTZ DEFAULT now(),
    completed_at  TIMESTAMPTZ
);
```

Processed PCAPs cleaned up after configurable retention (default 24 hours).

## Venafi Export Integration

### Two Export Mechanisms

**CSV/JSON Download (manual workflow):**
- Endpoint: `GET /api/v1/export/certificates?format=csv|json`
- Supports same filters as certificate list API
- CSV columns aligned with Venafi bulk import template
- "Export" button added to certificates page in UI

**Venafi TPP REST API Push (automated workflow):**
- Configuration:
  ```toml
  [export.venafi]
  enabled = false
  base_url = "https://tpp.example.com/vedsdk"
  client_id = ""
  refresh_token = ""
  folder = "\\VED\\Policy\\Discovered\\CipherFlag"
  push_interval_minutes = 60
  ```
- Pushes to Venafi's `POST /certificates/import` endpoint
- Certificates placed in configurable policy folder
- Includes metadata: discovery source, first/last seen, observed endpoints, health grade
- Deduplication handled by Venafi (by certificate thumbprint)
- Runs on configurable interval, only sends new/updated certificates since last push
- **Token lifecycle:** Venafi TPP access tokens expire (typically 8 hours). The client uses OAuth2 refresh token flow — stores `refresh_token` in config, obtains short-lived access tokens automatically, and refreshes them before expiry. No manual token rotation required.

### Export Data Model

| Field | Source |
|-------|--------|
| Certificate (PEM) | Zeek cert extraction or PCAP-sourced |
| Subject DN | x509.log |
| Issuer DN | x509.log |
| Serial Number | x509.log |
| Validity dates | x509.log |
| SANs | x509.log |
| Key algorithm + size | x509.log |
| Signature algorithm | x509.log |
| Discovery source | CipherFlag metadata |
| First/last seen | CipherFlag metadata |
| Observed endpoints (IP:port) | ssl.log observations |
| Health grade | CipherFlag scoring |
| SNI hostnames | ssl.log |

### PEM Availability Note

Zeek's `extract-certs-pem` policy writes raw PEM files during live capture. For PCAP analysis, PEM is extracted from the TLS handshake. When raw PEM is available, Venafi gets the full certificate object. When only Zeek's parsed fields are available (e.g., if PEM extraction is disabled), metadata-only export is still possible.

## Security Considerations

**v1 ships without built-in authentication.** The API exposes PCAP upload (up to 500MB), certificate export, and Venafi push capabilities. Deployments should be protected by one of:

- Network segmentation (only accessible from management VLAN)
- Reverse proxy with authentication (nginx + basic auth, OAuth2 proxy, etc.)
- Host firewall rules restricting access to port 8443

The quick-start docs and README will include a security notice recommending network-level access control. Built-in API key or OAuth authentication is planned for a future release.

## Code Changes

### Prerequisites (Existing Code Upgrades)

These changes to existing code are required before new features can be built:

| File | Change | Reason |
|------|--------|--------|
| `internal/store/postgres.go` | Upgrade migration system from single `//go:embed` to multi-file runner using `//go:embed migrations/*.sql` with `fs.FS`, add `schema_migrations` tracking table | Current system only supports a single SQL file; v1 adds `002_pcap_jobs.sql` and `003_raw_pem.sql` |
| `internal/store/postgres.go` | Reimplement `BatchUpsertCertificates` with multi-row `INSERT ... ON CONFLICT` | Current loop-based approach will bottleneck at Zeek log volumes |
| `internal/model/certificate.go` | Add `RawPEM string` field | Required for Venafi export and PEM file storage from Zeek's cert extraction |
| `internal/store/migrations/` | Add `003_raw_pem.sql`: `ALTER TABLE certificates ADD COLUMN raw_pem TEXT` | Storage for extracted PEM data |
| `internal/config/config.go` | Update default listen port from `8080` to `8443`; add typed source config structs (e.g., `ZeekFileSourceConfig`) and decode `toml.Primitive` values | Port consistency; source config values are currently loaded but inaccessible |

### New Go Packages

| Package | Purpose |
|---------|---------|
| `internal/ingest/zeek/` | Zeek JSON log parser for x509.log, ssl.log, conn.log (directory exists as empty placeholder; new code fills it in) |
| `internal/ingest/poller.go` | File watcher/poller, monitors /zeek-logs/, manages cursors |
| `internal/ingest/pcap.go` | PCAP job manager — writes files, tracks job status |
| `internal/export/csv.go` | CSV export aligned with Venafi import template |
| `internal/export/json.go` | JSON export with full certificate + observation data |
| `internal/export/venafi/` | Venafi TPP REST API client with OAuth2 token refresh for certificate push |
| `internal/certparse/` | Go `crypto/x509` wrapper for PEM/DER parsing |

### Modified Existing Code

| File | Change |
|------|--------|
| `cmd/cipherflag/main.go` | Start Zeek log poller as background goroutine alongside HTTP server |
| `internal/api/server.go` | Add routes: `/api/v1/export/*`, `/api/v1/pcap/*` |
| `internal/store/store.go` | Add interface methods: `CreatePCAPJob`, `UpdatePCAPJob`, `GetPCAPJob`, `ListPCAPJobs`; update `UpsertCertificate` to handle `RawPEM` |
| `internal/store/postgres.go` | Implement new store methods, update certificate scan/insert to include `raw_pem` |
| `internal/store/migrations/` | Add `002_pcap_jobs.sql`, `003_raw_pem.sql` |
| `internal/config/config.go` | Add `Export`, `PCAP`, and typed source config sections |
| `config/cipherflag.toml` | Add export and PCAP configuration blocks |

### Frontend Additions

| Path | Purpose |
|------|---------|
| `src/routes/upload/` | PCAP upload page with drag-and-drop, job status tracking |
| `src/lib/api.ts` | Add export and PCAP API client functions |
| Certificates page | Add "Export" button for CSV/JSON download |

### Unchanged

- Health scoring engine (`internal/analysis/`)
- All existing API endpoints and handlers
- Graph visualization and all existing frontend pages
- Database schema for observations, endpoint_profiles, health_reports (certificates table gets `raw_pem` column only)

## Open-Source Packaging

### Repository Additions

```
cipherflag/
├── LICENSE                          (Apache 2.0)
├── README.md                        (rewritten for open-source audience)
├── CONTRIBUTING.md                  (development setup, PR process, code structure)
├── .env.example                     (sensible defaults, key variables documented)
├── docker-compose.yml               (Zeek + CipherFlag + PostgreSQL)
├── docker-compose.corelight.yml     (override: no Zeek container — v1.1, ships as placeholder)
├── Dockerfile                       (multi-stage: Go + SvelteKit → minimal runtime)
├── docker/
│   └── zeek/
│       ├── Dockerfile               (Zeek with CipherFlag-specific config)
│       └── local.zeek               (JSON logs, cert extraction, protocol config)
├── docs/
│   ├── quickstart.md                (5-minute docker-compose guide)
│   ├── configuration.md             (all config options)
│   ├── venafi-export.md             (Venafi integration setup)
│   ├── pcap-upload.md               (PCAP analysis guide)
│   ├── corelight.md                 (guide for Corelight customers)
│   └── architecture.md              (design overview for contributors)
```

### Quick-Start Experience

```bash
git clone https://github.com/<org>/cipherflag.git
cd cipherflag
cp .env.example .env       # edit: set NETWORK_INTERFACE or leave defaults
docker-compose up -d
# Open http://localhost:8443
```

### Environment Configuration

Key variables in `.env.example`:

- `NETWORK_INTERFACE` — network interface for live capture (e.g., `eth0`)
- `POSTGRES_PASSWORD` — database password
- `VENAFI_ENABLED` — enable/disable Venafi push (default: false)
- `VENAFI_BASE_URL` — Venafi TPP server URL
- `VENAFI_ACCESS_TOKEN` — Venafi API token
- `VENAFI_FOLDER` — target policy folder in Venafi

Everything else has working defaults. Zero config for evaluation, progressively configurable for production.

### Release Artifacts

- Docker images published to GitHub Container Registry (`ghcr.io/<org>/cipherflag`, `ghcr.io/<org>/cipherflag-zeek`)
- GitHub Releases with changelog
- `docker-compose.yml` works with both local builds and published images

## v1.1+ Roadmap (Out of Scope for v1)

- Corelight sensor API integration (pull logs via REST API)
- Two-way Venafi sync (pull enrichment data back from Venafi)
- Venafi as a Service (VaaS/cloud) support
- Active scanning (connect to endpoints and pull certificates)
- Alerting and notifications on expiring certificates
- OCSP/CRL live status checking

## License

Apache License 2.0
