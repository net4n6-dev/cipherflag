# Architecture

## Container Topology

`docker compose up -d` starts two containers, `postgres` and `cipherflag`.
The Zeek network sensor is a third, opt-in container:
`docker compose --profile zeek up -d`.

```
  live traffic (NETWORK_INTERFACE)      ./pcap-input/<job>/*.pcap
                 │                                  │
                 v                                  v
  ┌──────────────────────────────────────────────────────────┐
  │  zeek  (profile "zeek"; host network, NET_RAW/NET_ADMIN) │
  └────────────────────────────┬─────────────────────────────┘
                               │ writes JSON logs
                               v
  ┌──────────────────────────────────────────────────────────┐
  │  zeek-logs volume                                        │
  │    x509.log, ssl.log, ...       live logs                │
  │    x509.<time>.log, ...         rotated hourly           │
  │    <job>[--<file>]/ .done|.failed  one dir per PCAP      │
  └────────────────────────────┬─────────────────────────────┘
                               │ mounted read-only at /var/log/zeek/current
                               v
  ┌──────────────────────────────────────────────────────────┐
  │  cipherflag  (:8443)                                     │
  │    Go API server + SvelteKit UI                          │
  │    Zeek log poller  ([sources.zeek_file])                │
  │    scanners, connectors, CBOM export, Venafi push        │
  └────────────────────────────┬─────────────────────────────┘
                               v
  ┌──────────────────────────────────────────────────────────┐
  │  postgres  (pg-data volume)                              │
  └──────────────────────────────────────────────────────────┘
```

**Volumes and directories:**

| Name | Writer | Reader | Content |
|------|--------|--------|---------|
| `zeek-logs` (volume) | zeek | cipherflag (read-only, at `/var/log/zeek/current`) | Zeek JSON logs: live, rotated, and one directory per PCAP job |
| `./pcap-input` (host directory) | you | zeek | PCAP files to process offline, one subdirectory per job |
| `pg-data` (volume) | postgres | postgres | Database persistence |

Why the sensor is a separate, opt-in container:

- It needs host networking and the `NET_RAW`/`NET_ADMIN` capabilities to
  capture live traffic; a default install should not have them.
- The shared log directory is the whole interface, so any Zeek sensor that
  writes JSON logs (with `policy/protocols/ssl/log-certs-base64`) to a
  directory CipherFlag can read works without this container.
- Live capture needs a Linux host: on Docker Desktop (macOS, Windows) the
  host network is the Docker VM's, not the machine's. PCAP processing
  works everywhere.

---

## Ingestion Pipeline

Certificates flow from network traffic to the database through this pipeline:

```
Network traffic / PCAP file
    |
    v
Zeek sensor (docker/zeek, Zeek 9)
    | writes JSON logs; x509.log carries each certificate (log-certs-base64)
    v
Zeek log poller (internal/ingest/zeekfile/)
    | reads x509 logs, then ssl logs, from [sources.zeek_file] log_dir
    | tracks each file by identity (device and inode), so rotation is followed
    v
Log parser (internal/ingest/zeek/)
    | deserializes Zeek JSON records
    v
Unified ingester (internal/ingest/)
    | builds each certificate from its PEM, dedups by SHA-256 fingerprint,
    | fills only empty columns, records provenance, scores it
    v
Observation recorder
    | one observation per certificate in each ssl.log session's chain
    v
PostgreSQL
```

**Key design decisions:**

- **One cursor row per log directory:** `ingestion_state` holds a JSON map
  from file identity to byte offset, saved after every batch of lines.
  Entries for files that no longer exist are dropped. On restart the poller
  resumes where it left off; a batch interrupted before its cursor was saved
  is read again, which is harmless because ingest is idempotent.
- **Complete lines only:** a line Zeek is still writing is left for the next
  poll, so no record is cut in half.
- **Rotation and truncation:** a rotated file keeps its identity and is
  finished from its offset; the new live file starts at zero. A file smaller
  than its offset is read again from the start.
- **Certificates before sessions:** observations reference certificates, so
  x509 logs are read first. A session whose certificate is not stored is
  kept for up to three polls (about 90 seconds at the default interval)
  and recorded when its certificate arrives; only if it never does is it
  counted in the poller's log line.
- **JSON log format:** Zeek is configured to output JSON, which is simpler
  to parse than Zeek's default TSV format.

### Offline PCAP Flow

There is no upload endpoint in CE. PCAP files are handed to the sensor
through a directory:

```
Copy capture.pcap to ./pcap-input/<job>/ (ZEEK_PCAP_DIR)
    |
    v
Zeek container's PCAP watcher finds it (every 5 seconds) and waits until
    | the file has been unchanged for PCAP_SETTLE_SECONDS (default 10)
    | runs: zeek -r /pcap-input/<job>/capture.pcap
    | writes logs to zeek-logs/<job>/ (one capture in the job) or
    |   zeek-logs/<job>--<file name>/ (several captures in the job)
    | then marks that directory .done, or .failed if Zeek could not process it
    | and records the capture in zeek-logs/.state/<job>/<file name>, so it
    |   is not run again even if its log directory is deleted
    v
CipherFlag's poller reads a job's logs once it is .done
    | normal ingestion pipeline; a .failed job is never read
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
| source | TEXT | Discovery source that first saw it (e.g. zeek_passive, for live capture and PCAP files alike) |
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

**ingestion_state** -- Cursors for polling sources.

| Column | Type | Description |
|--------|------|-------------|
| source_name | TEXT (PK) | The source; the Zeek poller uses `zeek_file:<log_dir>` |
| cursor | TEXT | Source-specific; for Zeek, a JSON map from file identity to `{path, offset}` |
