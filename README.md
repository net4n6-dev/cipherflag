# CipherFlag CE

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Release](https://img.shields.io/github/v/release/net4n6-dev/cipherflag)](https://github.com/net4n6-dev/cipherflag/releases)

> Open-source post-quantum migration inventory and CycloneDX 1.6 CBOM toolkit.
> Targets budget-constrained federal/state government and developer audiences.

CipherFlag CE discovers cryptographic assets across your environment,
classifies them by post-quantum readiness, evaluates them against
compliance frameworks (NIST SP 800-131A, NSA CNSA 2.0, FIPS 140-3,
EU NIS2), and exports them as CycloneDX 1.6 Cryptography Bill of
Materials (CBOM). It runs entirely on Apache 2.0 software, with no
calls home, no telemetry, and no commercial license required.

---

## What it does

### Core capabilities (v2.0)

**Layer 0 — unified asset model**
- Multi-source ingestion API (`POST /api/v1/ingest`) for X.509 certs,
  SSH keys, crypto libraries, and crypto-relevant config files
- Host identity resolution with deduplication and provenance tracking
- Bearer-token agent auth for unattended ingest

**Layer 1 — endpoint discovery (osquery)**
- osquery webhook adapter (`POST /api/v1/ingest/osquery`)
- 4 bash + 4 PowerShell discovery scripts you can drop into any
  endpoint-management tooling that doesn't speak osquery
- Script-output parser auto-classifies output into the unified asset
  model

**Layer 2 — native scanners**
- SSH key scanner (system + user `~/.ssh/`)
- Crypto-library scanner (OpenSSL, libgcrypt, BoringSSL, mbedTLS,
  GnuTLS, NSS, wolfSSL, lang-runtime crypto stdlibs)
- Cert-file scanner (PEM/DER/PKCS12/JKS on disk; matches private
  keys to certs by SPKI fingerprint)
- Config-file scanner (sshd, openssl.cnf, nginx, apache, envoy,
  haproxy)
- Truststore scanner (OS bundles, JVM cacerts, language-runtime CA
  stores)

**Layer 4.1 + 4.1b — scoring**
- 47-rule scoring catalog (CE subset: SSH-001..008, LIB-003..005,
  CFG-001..004, and the PQC-relevant certificate rules)
- CVE-based library scoring against open NVD/OSV data (LIB-001 +
  LIB-002); CE ships with a seed CVE catalog covering 37 known
  crypto-library vulnerabilities (Heartbleed, DROWN, etc.)

**Layer 4.2 — PQC taxonomy**
- 122 recognized algorithm spellings across 8 categories
  (asymmetric, symmetric, hash, signature, KEX, KDF, PQC-KEM,
  PQC-SIG)
- Vulnerable, weakened, hybrid, and quantum-safe statuses
- Pure-data Go module — no external runtime dependencies

**Layer 4.3 — compliance evaluation**
- NIST SP 800-131A Rev 2
- NSA CNSA 2.0
- FIPS 140-3 (algorithm allowlist)
- EU NIS2
- Per-asset compliance status with framework-specific findings

**Layer 5.1 — CycloneDX 1.6 CBOM generation**
- `GET /api/v1/export/cbom` returns valid CycloneDX 1.6 JSON
- Scheduled push (configurable interval)
- File sink and HTTP sink for build-pipeline integration

**Layer 5.2 — CBOM import**
- `POST /api/v1/import/cbom` accepts foreign CycloneDX BOMs,
  re-classifies algorithms via the PQC taxonomy, and ingests assets
  into the unified inventory

**Layer 5.3 — export sinks**
- S3 (AWS or S3-compatible: MinIO, Wasabi, Backblaze)
- Splunk HEC (RFC 5424 + CEF)
- Syslog (RFC 5424 + CEF)

**Layer 6.1a–c — Git repository scanner (deterministic only)**
- Block 1: PEM/DER/SSH/PKCS12/JKS file parsing
- Block 3: tree-sitter Python + Java parsers, Go AST parser
- Block 4: server config file parsing (nginx, apache, envoy,
  haproxy, openssl.cnf)
- Per-repo CBOM export endpoint

**Intake observation cache**
- In-process LRU dedup wrapper for the UnifiedIngester. Drops the
  observation count by 60-90% on long-running deployments with
  high-cardinality ingest sources.

**Layer 3 — commercial endpoint connectors (CE, off by default)**
- Microsoft Defender for Endpoint, SentinelOne, Tanium, Absolute,
  and Netwrix endpoint connectors ship in CE; all use documented
  vendor REST APIs and require no vendor SDK or license agreement.
  Enable each connector in `config/cipherflag.toml`.

**Layer 5.4 — Venafi TPP + Cloud push export (CE)**
- Push-exports the CBOM inventory to a Venafi Trust Protection
  Platform (TPP) instance or Venafi Cloud tenant via the documented
  Venafi REST API. Configurable endpoint and credentials in
  `config/cipherflag.toml`.

---

## What's NOT included (CipherFlag EE)

A separate **CipherFlag EE** product (commercial license) adds:

- **Layer 6.1d** — AI-enriched scanning (Anthropic LLM client,
  license-gated, prompt library, byte-range redactor, exploit /
  no-leak / strict-JSON guardrails)
- **Layer 6.2** — Container image scanner (binary crypto detect,
  OCI registry extraction, AI enrichment tier)
- **Layer 6.3** — Active network scanner
- **Layer 3** — Velociraptor endpoint integration (requires vendor
  gRPC SDK — EE-only; Wazuh is handled via webhook and not a
  dedicated connector)
- **Layer 4.1c** — TLS/SSH protocol-version scoring rules
  (PROTO-001..006) + `protocol_endpoints` aggregate
- **Layer 4.3** — PCI DSS 4.0 compliance evaluator
- **Layer 4.4** — Per-asset risk prioritization with blast-radius
  analysis (host-dependency graph + PKI edge engine)
- **Layer 5.4** — Thales CipherTrust + advanced Venafi TPP
  policy-folder management (deep TPP policy engine and CipherTrust
  adapters; the basic Venafi TPP + Cloud push export ships in CE)
- **Layer 8** — Operator UX (the production frontend; CE retains
  the v1 demo frontend as a known limitation)
- **Certificate Transparency multi-provider arc** (deferred to
  Phase 2 — will land in CE v2.1 once the EE arc completes)

Contact CipherFlag for EE access.

---

## Quick start

### Docker Compose (recommended)

```bash
git clone https://github.com/net4n6-dev/cipherflag.git
cd cipherflag
docker-compose up -d
```

The HTTP API comes up on `http://localhost:8080`; Postgres on
`localhost:5432`.

Initialize an admin user:

```bash
curl -sS -X POST http://localhost:8080/api/v1/auth/setup-admin \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"changeme","display_name":"Admin"}'
```

Then send an osquery webhook ingest:

```bash
curl -sS -X POST http://localhost:8080/api/v1/ingest/osquery \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <agent-token-from-setup>' \
  -d @discovery-packs/osquery/example-payload.json
```

Export a CBOM:

```bash
curl -sS http://localhost:8080/api/v1/export/cbom | jq '.bomFormat, .specVersion'
# "CycloneDX"
# "1.6"
```

### From source (Go 1.25+)

```bash
git clone https://github.com/net4n6-dev/cipherflag.git
cd cipherflag
go build ./...
cp config/cipherflag.toml.example config/cipherflag.toml
# edit config/cipherflag.toml — set [storage] postgres_url
./cipherflag migrate
./cipherflag serve
```

### CLI subcommands

```
cipherflag serve                   Start the HTTP API server
cipherflag migrate                 Apply the v2.0 baseline schema
cipherflag seed                    No-op in CE (no built-in seed dataset)
cipherflag setup                   Print configuration-driven setup banner
cipherflag declared-cas <verb>     Manage the operator-declared CA registry
cipherflag application-metadata    Manage per-application TTL metadata (HNDL)
cipherflag ownership <verb>        Manage asset ownership sightings
cipherflag scan-truststore         One-shot OS / JVM / runtime trust-store scan
cipherflag generate-signing-key    Generate an Ed25519 signing key for CBOMs
cipherflag sign-cbom <file>        Sign a CBOM JSON with the signing key
cipherflag verify-cbom <file>      Verify a signed CBOM
cipherflag version                 Print version
```

---

## Architecture overview

```
┌──────────────────────────────────────────────────────────────────┐
│  Discovery sources                                               │
│   • osquery webhook        • Layer 2 native scanners             │
│   • CBOM import endpoint   • Git repo scanner (deterministic)    │
└────────────────┬─────────────────────────────────────────────────┘
                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  Unified ingester (Layer 0)                                      │
│   • Multi-source dedup    • Host identity resolution             │
│   • Observation cache     • Provenance + ownership ledger        │
└────────────────┬─────────────────────────────────────────────────┘
                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  Scoring (Layer 4.1 + 4.1b + 4.2 + 4.3)                          │
│   • Per-asset health reports   • PQC classification              │
│   • CVE matching               • 4-framework compliance grading  │
└────────────────┬─────────────────────────────────────────────────┘
                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  Export (Layer 5.1 + 5.2 + 5.3)                                  │
│   • CycloneDX 1.6 CBOM gen/import                                │
│   • Scheduled push (S3, Splunk HEC, Syslog)                      │
│   • HTTP API for ad-hoc fetch                                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Inbound contributions are accepted under Apache 2.0; no Contributor
License Agreement (CLA) required. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

CipherFlag CE includes software from third parties — see [`NOTICE`](NOTICE)
for the full attribution list (IBM CBOMkit, HashiCorp golang-lru,
tree-sitter language bindings, and others).

---

## Documentation

- [`CHANGELOG.md`](CHANGELOG.md) — release history, breaking changes
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute, license terms
- [`NOTICE`](NOTICE) — third-party dependency attributions
- `discovery-packs/` — osquery queries + bash/PowerShell scripts
  for endpoint discovery
- `docs/` — operator-facing reference material

---

## Status and roadmap

| Capability | Status |
|---|---|
| PQC taxonomy + classification | shipped v2.0 |
| 4-framework compliance bundle | shipped v2.0 |
| CycloneDX 1.6 CBOM gen/import | shipped v2.0 |
| Export sinks (S3, Splunk, Syslog) | shipped v2.0 |
| Git repo deterministic scanner | shipped v2.0 |
| osquery webhook + 8 discovery scripts | shipped v2.0 |
| Native scanners (SSH/lib/cert/config/truststore) | shipped v2.0 |
| Endpoint connectors: Defender/SentinelOne/Tanium/Absolute/Netwrix | shipped v2.1 (CE, off by default) |
| Venafi TPP + Cloud push export | shipped v2.1 (CE) |
| Certificate Transparency multi-provider | **deferred to v2.1** (Phase 2) |
| Production operator UI | **EE-only** (CE retains v1 demo UI) |
| Risk prioritization + blast-radius | **EE-only** |
| AI-enriched repo scanning | **EE-only** |
| Container image scanning | **EE-only** |
| Active network scanning | **EE-only** |
| PCI DSS 4.0 compliance | **EE-only** |

---

## Reporting issues

Please open issues at https://github.com/net4n6-dev/cipherflag/issues.
For security issues, see [`SECURITY.md`](SECURITY.md) (if present) or
email the maintainer (see `LICENSE` for contact info).
