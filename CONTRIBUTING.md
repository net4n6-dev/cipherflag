# Contributing to CipherFlag

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

### 3. Run migrations and seed demo data

```bash
./bin/cipherflag seed
```

This runs all SQL migrations and loads 19 certificates with realistic health scenarios (A+ through F), 206 TLS observations, and 10 endpoint profiles.

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
├── store/          Data access layer
│   ├── store.go        CertStore interface
│   ├── postgres.go     PostgreSQL implementation (pgx/v5)
│   └── migrations/     Numbered SQL migration files
│
├── api/            HTTP layer
│   ├── server.go       Chi router and route definitions
│   ├── handler/        Request handlers (certificates, graph, stats, export, pcap)
│   └── middleware/     CORS middleware
│
├── ingest/         Data ingestion
│   ├── poller.go       File watcher for Zeek log directory
│   ├── pcap.go         PCAP upload job manager
│   └── zeek/           Zeek JSON log parser (x509, ssl, conn)
│
├── export/         Data export
│   ├── csv.go          CSV export (Venafi import template format)
│   ├── json.go         JSON export
│   └── venafi/         Venafi TPP REST API client with OAuth2
│
├── analysis/       Certificate analysis
│   ├── scorer.go       Health scoring engine (16 rules, A+ to F)
│   └── chain.go        Chain builder and Cytoscape.js graph shaper
│
├── certparse/      X.509 certificate parsing (crypto/x509 wrapper)
│
├── config/         Configuration loader (TOML)
│
└── model/          Domain types
    ├── certificate.go  Certificate + DistinguishedName
    ├── observation.go  TLS observations + cipher strength
    ├── health.go       Grade, findings, scoring
    ├── protocol.go     Endpoint profiles
    ├── chain.go        Chain tree + Cytoscape.js graph types
    └── source.go       Ingestion source health
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
