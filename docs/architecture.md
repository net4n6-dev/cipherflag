# Architecture

## Container Topology

CipherFlag deploys as three Docker containers orchestrated by Docker Compose:

```
┌───────────────────────────────────────────────────────────────┐
│  docker-compose up                                            │
│                                                               │
│  ┌──────────────────┐                                         │
│  │  zeek-sensor      │                                        │
│  │                   │  writes to                              │
│  │  - Live capture   │──────────┐                             │
│  │    (SPAN/tap)     │          │                              │
│  │  - PCAP watcher   │          v                              │
│  │                   │   ┌─────────────┐   ┌──────────────┐   │
│  └──────────────────┘   │ zeek-logs   │   │ pcap-input   │   │
│                          │ (volume)    │   │ (volume)     │   │
│           reads from     │ x509.log   │   │              │   │
│          ┌───────────────│ ssl.log    │   │  writes to   │   │
│          │               │ conn.log   │   │──────────────│   │
│          v               └─────────────┘   └──────────────┘   │
│  ┌──────────────────┐          ^                  ^           │
│  │  cipherflag       │          │                  │           │
│  │                   │──────────┘                  │           │
│  │  - Go API server  │  reads logs         writes PCAPs       │
│  │  - SvelteKit UI   │                            │           │
│  │  - Zeek poller    │────────────────────────────┘           │
│  │  - Venafi export  │                                        │
│  │                   │                                        │
│  │  :8443            │                                        │
│  └────────┬─────────┘                                        │
│           │                                                   │
│           v                                                   │
│  ┌──────────────────┐                                         │
│  │  postgresql       │                                        │
│  │                   │                                        │
│  │  pg-data (volume) │                                        │
│  └──────────────────┘                                         │
└───────────────────────────────────────────────────────────────┘
```

**Shared volumes:**

| Volume | Writer | Reader | Content |
|--------|--------|--------|---------|
| `zeek-logs` | zeek-sensor | cipherflag | Zeek log output (x509.log, ssl.log, conn.log) |
| `pcap-input` | cipherflag | zeek-sensor | PCAP files uploaded for offline analysis |
| `pg-data` | postgresql | postgresql | Database persistence |

**Why three containers:**

- Users can point CipherFlag at an existing PostgreSQL instance
- Corelight customers (v1.1) drop the Zeek container and run only CipherFlag + PostgreSQL
- The shared volume boundary (`/zeek-logs/`) makes CipherFlag sensor-agnostic

---

## Ingestion Pipeline

Certificates flow from network traffic to the database through this pipeline:

```
Network traffic / PCAP file
    |
    v
Zeek sensor
    | writes JSON logs (x509.log, ssl.log, conn.log)
    v
File poller (internal/ingest/poller.go)
    | watches /zeek-logs/, tracks byte position per file via ingestion_state table
    v
Log parser (internal/ingest/zeek/)
    | deserializes Zeek JSON records into Go structs
    v
Certificate builder
    | maps Zeek fields to CipherFlag Certificate model
    | parses PEM when available (internal/certparse/)
    v
Deduplicator
    | batch upsert by SHA256 fingerprint, updates last_seen timestamp
    v
Health scorer (internal/analysis/scorer.go)
    | runs 16 rules, assigns grade A+ through F
    v
Observation recorder
    | creates TLS observations and endpoint profiles from ssl.log/conn.log
    v
PostgreSQL
```

**Key design decisions:**

- **Cursor-based polling:** The `ingestion_state` table tracks the byte position per log file. On restart, CipherFlag resumes where it left off with no data loss or reprocessing.
- **Batch upserts:** Certificates are accumulated and flushed in batches (100 records or 5 seconds, whichever comes first) using multi-row `INSERT ... ON CONFLICT`.
- **JSON log format:** Zeek is configured to output JSON, which is simpler to parse than Zeek's default TSV format.

### PCAP Upload Flow

```
User uploads .pcap via UI or API
    |
    v
POST /api/v1/pcap/upload
    | writes file to /pcap-input/ volume, creates pcap_jobs row
    v
Zeek container's file watcher detects new .pcap
    | runs: zeek -r /pcap-input/<file>.pcap
    | writes logs to /zeek-logs/<job-id>/
    v
CipherFlag poller picks up logs from job subdirectory
    | normal ingestion pipeline (parse, dedupe, score, store)
    v
Job status updated to complete with summary (certs found, new vs. known)
```

---

## Health Scoring

The scoring engine (`internal/analysis/scorer.go`) evaluates each certificate against 16 rules across five categories. Certificates start at 100 points; deductions reduce the score. Critical failures immediately set the grade to F.

| Category | Rules | Checks |
|----------|-------|--------|
| Expiration | EXP-001 through EXP-005 | Expired, expiring soon (7/30/90 day thresholds), validity > 398 days |
| Key Strength | KEY-001 through KEY-004 | RSA < 2048 bits, RSA 2048 (not 4096), ECDSA < 256 bits, unknown algorithm |
| Signature | SIG-001 through SIG-003 | SHA-1, MD5, unknown algorithm |
| Chain Trust | CHN-001 | Self-signed end-entity certificate |
| Revocation / CT | REV-001, REV-002, SCT-001 | No OCSP or CRL, no OCSP (CRL only), no CT SCTs |

**Grade thresholds:**

| Grade | Score |
|-------|-------|
| A+ | 95 -- 100 |
| A | 85 -- 94 |
| B | 70 -- 84 |
| C | 50 -- 69 |
| D | 20 -- 49 |
| F | < 20 or critical failure |

---

## Data Model

### Core Tables

**certificates** -- Discovered X.509 certificates.

| Column | Type | Description |
|--------|------|-------------|
| fingerprint_sha256 | TEXT (PK) | SHA-256 fingerprint |
| serial_number | TEXT | Certificate serial number |
| subject_cn | TEXT | Subject common name |
| issuer_cn | TEXT | Issuer common name |
| not_before / not_after | TIMESTAMPTZ | Validity period |
| key_algorithm | TEXT | Key algorithm (RSA, ECDSA) |
| key_length | INTEGER | Key size in bits |
| signature_algorithm | TEXT | Signature algorithm |
| is_ca | BOOLEAN | CA flag from basic constraints |
| san_dns_names | TEXT[] | Subject alternative names (DNS) |
| raw_pem | TEXT | Raw PEM data (when available) |
| source | TEXT | Discovery source (zeek_passive, pcap_upload) |
| first_seen / last_seen | TIMESTAMPTZ | Discovery timestamps |

**observations** -- TLS connections where a certificate was observed.

| Column | Type | Description |
|--------|------|-------------|
| certificate_fp | TEXT (FK) | Certificate fingerprint |
| server_ip | TEXT | Server IP address |
| server_port | INTEGER | Server port |
| server_name | TEXT | SNI hostname |
| negotiated_version | TEXT | TLS version |
| cipher_suite | TEXT | Negotiated cipher suite |

**health_reports** -- Scoring results per certificate.

| Column | Type | Description |
|--------|------|-------------|
| certificate_fp | TEXT (FK) | Certificate fingerprint |
| score | INTEGER | Numeric score (0--100) |
| grade | TEXT | Letter grade (A+ through F) |
| findings | JSONB | Array of rule violations |

**endpoint_profiles** -- Aggregate TLS configuration per endpoint.

| Column | Type | Description |
|--------|------|-------------|
| server_ip | TEXT | Server IP address |
| server_port | INTEGER | Server port |
| server_name | TEXT | SNI hostname |
| has_weak_ciphers | BOOLEAN | Endpoint uses weak cipher suites |

**pcap_jobs** -- PCAP upload processing status.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Job identifier |
| filename | TEXT | Original filename |
| status | TEXT | queued, processing, complete, error |
| certs_found / certs_new | INTEGER | Discovery counts |

**ingestion_state** -- Cursor tracking for Zeek log polling.

| Column | Type | Description |
|--------|------|-------------|
| file_path | TEXT (PK) | Log file path |
| byte_offset | BIGINT | Last processed byte position |
