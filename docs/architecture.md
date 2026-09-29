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
    | tracks each file by identity (device and inode), not path, so rotation
    | is followed
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
  from file identity (`<device>:<inode>`) to `{path, offset}`, saved after
  every batch of lines. Entries for files that no longer exist are dropped.
  On restart the poller resumes where it left off; a batch interrupted
  before its cursor was saved is read again, which is harmless because
  ingest is idempotent: certificates dedup by fingerprint, and an
  observation is unique per session (a unique index, inserted with
  `ON CONFLICT DO NOTHING`).
- **Complete lines only:** a line Zeek is still writing is left for the next
  poll, so no record is cut in half.
- **Rotation and truncation:** a rotated file keeps its identity and is
  finished from its offset; the new live file starts at zero. A file smaller
  than its offset is read again from the start. Because an inode can be
  reused, two more checks restart a file from zero: the same identity now
  under a different path when the stored path was a rotated name, and a
  stored offset that does not sit right after a newline.
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

The certificate scoring engine (`internal/analysis/scorer.go`) evaluates each certificate against 23 rules in eight categories. A certificate starts at 100 points; each finding deducts points (never below 0). A finding marked as an immediate failure sets the grade to F regardless of the score. The result is saved to `health_reports` and, with the PQC status and compliance mapping, to `asset_health_reports` (`internal/analysis/scoring/dispatcher.go`). SSH keys, crypto libraries and crypto configs are scored by their own rule families (SSH-, LIB-, CFG-) into `asset_health_reports`.

| Category | Rules | Checks |
|----------|-------|--------|
| Expiration | EXP-001 to EXP-006 | Expired (immediate fail); expires within 7, 30 or 90 days; validity over 398 days; validity over 200 days (up to 398) |
| Key strength | KEY-001 to KEY-005 | RSA under 2048 bits (immediate fail); RSA 2048 (low); RSA 3072 (info, no deduction); ECDSA under 256 bits (immediate fail); unknown algorithm |
| Signature | SIG-001 to SIG-003 | SHA-1 (immediate fail), MD5 (immediate fail), unknown algorithm |
| Chain | CHN-001 | Self-signed end-entity certificate |
| Revocation | REV-001, REV-002 | Neither OCSP nor CRL; no OCSP responder |
| Transparency | SCT-001 | No signed certificate timestamps |
| Wildcard | WLD-001, WLD-002 | Wildcard certificate (heavier with more than three wildcard SANs); wildcard over a whole TLD (immediate fail) |
| Agility | AGI-001 to AGI-003 | Over a year of validity and not from an ACME CA; ACME certificate valid over 100 days; non-standard signature algorithm |

Rules that concern end-entity certificates skip CA certificates (validity length, revocation, SCTs, wildcards, agility).

**Grade thresholds** (`ScoreToGrade` in `internal/model/health.go`):

| Grade | Score |
|-------|-------|
| A+ | 95 to 100 |
| A | 85 to 94 |
| B | 70 to 84 |
| C | 50 to 69 |
| D | 20 to 49 |
| F | below 20, or any immediate failure |

---

## Data Model

The schema is defined by the SQL files in `internal/store/migrations/`, applied in filename order at server startup and recorded in `schema_migrations`: `v2.0_baseline.sql`, `v2.1.0_venafi_push.sql`, `v2.2.0_sse_event_triggers.sql`, `v2.2.4_schema_parity.sql`, `v2.3.1_observations_unique.sql`. The tables below are the ones the ingestion and scoring paths use; each lists its key columns only, and the migration files are the full reference.

**certificates** (baseline, plus Venafi push columns in `v2.1.0`)

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Row id |
| fingerprint_sha256 | TEXT (unique) | SHA-256 fingerprint; the key other tables reference |
| subject_cn, subject_org, ..., issuer_cn, issuer_org, ... | TEXT | Subject and issuer name parts |
| serial_number | TEXT | Certificate serial number |
| not_before / not_after | TIMESTAMPTZ | Validity period |
| key_algorithm / key_size_bits | TEXT / INTEGER | Public key algorithm and size |
| signature_algorithm | TEXT | Signature algorithm |
| subject_alt_names | JSONB | Subject alternative names |
| is_ca | BOOLEAN | CA flag from basic constraints |
| key_usage, extended_key_usage | JSONB | Usage extensions |
| ocsp_responder_urls, crl_distribution_points, scts | JSONB | Revocation and transparency data |
| raw_pem | TEXT | Raw PEM |
| source_discovery | TEXT | Source that first saw it (default `zeek_passive`, for live capture and PCAP alike) |
| first_seen / last_seen | TIMESTAMPTZ | Discovery timestamps |
| discovered_on_host, file_path, store_type, application_tags | UUID, TEXT, TEXT, TEXT[] | Host attribution and tags |
| authority_key_id, subject_key_id, issuer_fingerprint_sha256, spki_fingerprint_sha256 | BYTEA / TEXT | PKI linkage |
| venafi_pushed_at, venafi_push_failures, venafi_last_push_attempt | TIMESTAMPTZ, INT | Venafi push state |

**observations** (baseline; unique index in `v2.3.1_observations_unique.sql`): one row per TLS session in which a certificate was seen.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Row id |
| cert_fingerprint | TEXT (FK) | `certificates.fingerprint_sha256`, `ON DELETE CASCADE` |
| server_ip, server_port, server_name | TEXT, INTEGER, TEXT | Server address and SNI hostname |
| client_ip | TEXT | Client address |
| negotiated_version, negotiated_cipher, cipher_strength | TEXT | TLS version, cipher suite and its strength class |
| ja3_fingerprint, ja3s_fingerprint | TEXT | JA3 and JA3S fingerprints |
| source | TEXT | Observing source (default `zeek_passive`) |
| observed_at | TIMESTAMPTZ | When the session was seen |

`idx_obs_session_unique` is a unique index on `(cert_fingerprint, source, observed_at, client_ip, server_ip, server_port)`. It makes recording a session idempotent, so a re-read log does not duplicate observations.

**health_reports** (baseline): the certificate score.

| Column | Type | Description |
|--------|------|-------------|
| cert_fingerprint | TEXT (unique, FK) | Certificate fingerprint |
| score | INTEGER | Numeric score (0 to 100) |
| grade | TEXT | Letter grade (A+ through F) |
| findings | JSONB | Array of rule findings |
| scored_at | TIMESTAMPTZ | When it was scored |

**asset_health_reports** (baseline; `risk_score` and `risk_factors` added in `v2.2.4`): the unified score for every asset type, unique on `(asset_type, asset_id)`. Its key columns are `asset_type`, `asset_id` (a certificate's is its fingerprint), `grade`, `score`, `findings`, `pqc_status`, `compliance` and `rule_engine_version`.

**endpoint_profiles** (baseline): a per-endpoint rollup keyed by `(server_ip, server_port)`, with `server_name`, `cert_fingerprint`, `min_tls_version`, `max_tls_version`, `cipher_suites`, `supports_forward_secrecy`, `supports_aead`, `has_weak_ciphers`, `observation_count`, `first_seen` and `last_seen`.

**ingestion_state** (baseline): cursors for polling sources.

| Column | Type | Description |
|--------|------|-------------|
| source_name | TEXT (PK) | The source; the Zeek poller uses `zeek_file:<log_dir>` |
| cursor | TEXT | Source-specific; for Zeek, a JSON map from file identity to `{path, offset}` |
| updated_at | TIMESTAMPTZ | Last save |

**Other tables** (all in the baseline unless noted): `users`; `hosts` and `host_identifiers`; `host_ip_sightings`; `ssh_keys`; `crypto_libraries` and `crypto_library_cves`; `crypto_configs`; `asset_provenance`; `agent_tokens`; `operator_declared_cas`; `application_metadata`; `asset_ownership_sightings`; `repositories`, `repo_scan_cache`, `scan_jobs` and `providers`; `lineage_links`; `cert_private_key_holding`; `host_trust_store`; and `ad_cs_events` (`v2.2.4`). `v2.2.0` adds `pg_notify` triggers on the asset tables that feed the live event stream.
