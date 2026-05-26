# Contributing to CipherFlag CE

## License of contributions

By submitting code, documentation, scripts, or other content to
CipherFlag CE, you agree that your contribution is licensed under the
**Apache License, Version 2.0** — the same license as the rest of
CipherFlag CE.

We do **not** require a Contributor License Agreement (CLA). You retain
copyright in your contribution; the project receives a non-exclusive
Apache 2.0 license to use, modify, and redistribute it.

Note: CipherFlag has a related enterprise edition (**CipherFlag EE**)
with a separate, proprietary license. EE incorporates features developed
independently in EE, plus a curated subset of features from CE. **Your
contributions to CE will not flow into EE** under the no-CLA model;
EE may independently re-implement equivalent functionality, but the
copyright on your CE contribution stays with you.

This trade-off is deliberate. The maintainer cannot relicense community
contributions back into the proprietary EE codebase, and the maintainer
has elected to accept that constraint in exchange for a contributor-
friendly inbound license model.

---

## Prerequisites

| Dependency | Version | Install |
|------------|---------|---------|
| Go | 1.24+ | [go.dev/dl](https://go.dev/dl/) or `brew install go` |
| Node.js | 22+ | [nodejs.org](https://nodejs.org/) or `brew install node` |
| PostgreSQL | 15+ | [postgresql.org](https://www.postgresql.org/download/) or `brew install postgresql@17` |

---

## Local Development Setup (Without Docker)

### 1. Create the database

```bash
createdb cipherflag
psql cipherflag -c "CREATE USER cipherflag WITH PASSWORD 'dev';"
psql cipherflag -c "GRANT ALL PRIVILEGES ON DATABASE cipherflag TO cipherflag;"
psql cipherflag -c "GRANT ALL ON SCHEMA public TO cipherflag;"
```

### 2. Build the Go binary

```bash
go build -o bin/cipherflag ./cmd/cipherflag/
```

### 3. Run migrations

```bash
./bin/cipherflag migrate
```

This applies the v2.0 baseline migration (26 tables) plus any
incremental migrations in `internal/store/migrations/`.

Note: `cipherflag seed` is a no-op in CE v2.0 — the v1.x demo dataset
(19 certificates, 206 TLS observations, 10 endpoint profiles) was
removed during the EE→CE port. CE is populated through real ingest
paths: the osquery webhook, the native Layer 2 scanners, and the
git repo scanner.

### 4. Start the API server

```bash
./bin/cipherflag serve
```

The API listens on `http://localhost:8443`.

### 5. Start the frontend dev server

```bash
cd frontend
npm install
npm run dev
```

The frontend runs on `http://localhost:5174` and proxies API requests to port 8443.

---

## Code Structure

```
internal/
├── analysis/
│   ├── compliance/     NIST/NSA CNSA 2.0/FIPS/NIS2 algorithm allowlists
│   ├── pqc/            PQC taxonomy (122 algorithm spellings, 8 categories)
│   ├── scoring/        47-rule scoring engine (SSH, LIB, CFG, PQC cert)
│   └── scorer.go       Legacy cert-only scorer (CryptoStore.HealthReports)
│
├── api/                HTTP layer
│   ├── server.go       Chi router and CE-bound route definitions
│   ├── handler/        Request handlers (certs, hosts, ssh-keys, libs,
│   │                   configs, scans, findings, cbom, repos, etc.)
│   └── middleware/     Auth (JWT + agent-token), CORS, role guards
│
├── auth/               JWT secret derivation + agent-token verification
├── config/             Configuration loader (TOML)
│
├── store/              Data access layer
│   ├── store.go        CryptoStore + CertStore interfaces
│   ├── postgres.go     PostgreSQL implementation (pgx/v5)
│   └── migrations/     v2.0_baseline.sql + future incremental files
│
├── ingest/             Layer 0 unified ingest + Layer 1 endpoint adapters
│   ├── ingester.go     UnifiedIngester (dedup + cache + scorer wiring)
│   ├── ingest.go       DiscoveryResult / IngestionSummary domain types
│   ├── ownership.go    Ownership-claim fan-out (asset_ownership_sightings)
│   ├── dedup/          Per-asset upsert dedup logic
│   ├── hostresolver/   Host-identity resolution and provenance tracking
│   ├── observcache/    In-process observation cache (Layer 0 dedup)
│   ├── osquery/        osquery webhook adapter
│   ├── scriptparse/    Discovery-script output parser (bash + PowerShell)
│   └── zeek/           Zeek JSON log parser (x509, ssl, conn)
│
├── scanner/            Layer 2 native scanners + Layer 6.1 git repo scanner
│   ├── sshkeys/        SSH-key scanner (system + user ~/.ssh/)
│   ├── libraries/      Crypto-library scanner (OpenSSL/GnuTLS/NSS/...)
│   ├── certfiles/      Cert-file scanner (PEM/DER/PKCS12/JKS)
│   ├── configs/        Config-file scanner (sshd, openssl.cnf, nginx, ...)
│   ├── truststore/     OS bundles, JVM cacerts, language CA stores
│   ├── executil/       Sandbox helper for invoking external scanners
│   ├── pipeline/       Layer 6.1 git-repo scan pipeline driver
│   ├── clone/          Repo cloning (Layer 6.1b-2)
│   ├── scheduler/      Repo scan scheduler goroutine (Layer 6.1b-4)
│   ├── cachegc/        repo_scan_cache GC goroutine
│   ├── detect/{b1,b3,b4}/ Deterministic detectors per scan block
│   ├── finding/        Layer 6.1 finding model + persistence
│   ├── fpreduce/       False-positive reduction filters
│   ├── enumerate/      File enumeration helpers
│   ├── lineage/        Repo→cert lineage emission
│   ├── metrics/        Scanner metrics
│   ├── config/         Per-repo scan-config resolver
│   └── scansource/     Scan-source attribution helper
│
├── export/
│   └── cbom/           CycloneDX 1.6 CBOM generation + sinks (s3,
│                       splunk, syslog, file, http)
│
├── import/
│   └── cbom/           CBOM import endpoint (Layer 5.2)
│
├── certparse/          X.509 parsing helpers (crypto/x509 wrapper +
│                       SPKI fingerprint, AKI/SKI extraction)
├── normalize/          Algorithm spelling normalizers
├── assets/             Asset metadata helpers
├── attrition/          Attrition thresholds (stale sweep)
├── secrets/            Per-provider secret resolver
├── model/              Domain types (Certificate, Host, SSHKey, ...)
└── testdb/             Test DSN + schema-isolation helpers (integration)

cmd/cipherflag/         Server entry point
├── main.go             Top-level CLI: serve | migrate | seed | setup
└── ...
```

### Frontend

The frontend is a SvelteKit application in `frontend/`:

- `src/lib/api.ts` -- API client with TypeScript types for all endpoints
- `src/routes/+page.svelte` -- Certificate landscape graph (Cytoscape.js)
- `src/routes/upload/` -- PCAP upload page with drag-and-drop

---

## Running Tests

```bash
# All Go tests
go test ./...

# Frontend type checking
cd frontend && npx svelte-check
```

---

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feat/your-feature main
   ```

2. **Make your changes.** Follow the existing code patterns and naming conventions.

3. **Test** your changes:
   ```bash
   go test ./...
   cd frontend && npx svelte-check
   ```

4. **Commit** with a clear message describing the change:
   ```bash
   git commit -m "feat: add support for widget parsing"
   ```

5. **Push** and open a pull request against `main`. Describe what the PR does and why.

---

## Commit Message Convention

Use conventional commit prefixes:

- `feat:` -- New feature
- `fix:` -- Bug fix
- `docs:` -- Documentation
- `refactor:` -- Code restructuring without behavior change
- `test:` -- Test additions or changes
- `chore:` -- Build, CI, or tooling changes
