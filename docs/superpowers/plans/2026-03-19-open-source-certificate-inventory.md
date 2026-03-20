# CipherFlag v1 Open-Source Certificate Inventory — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform CipherFlag from a seed-data demo into a production-ready, open-source certificate inventory tool that passively discovers certificates via Zeek, accepts PCAP uploads, and exports inventory to Venafi TPP.

**Architecture:** Docker Compose with 3 services (Zeek sensor, CipherFlag Go API with embedded SvelteKit frontend, PostgreSQL). Zeek writes JSON logs to a shared volume; CipherFlag polls and ingests them. Venafi export via REST API push and CSV/JSON download.

**Tech Stack:** Go 1.24, SvelteKit 2 / Svelte 5 / Tailwind CSS 4, PostgreSQL 15, Zeek (open-source), Docker / Docker Compose, pgx/v5, chi/v5, zerolog.

**Spec:** `docs/superpowers/specs/2026-03-19-open-source-certificate-inventory-design.md`

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `internal/store/migrations/002_pcap_jobs.sql` | PCAP jobs table schema |
| `internal/store/migrations/003_raw_pem.sql` | Add raw_pem column to certificates |
| `internal/ingest/zeek/parser.go` | Parse Zeek JSON log records (x509, ssl, conn) into Go structs |
| `internal/ingest/zeek/parser_test.go` | Tests for Zeek log parsing |
| `internal/ingest/poller.go` | File poller: watches log directory, tracks cursor, dispatches batches |
| `internal/ingest/poller_test.go` | Tests for file poller |
| `internal/ingest/pcap.go` | PCAP job manager: tracks upload jobs, watches for sentinel files |
| `internal/ingest/pcap_test.go` | Tests for PCAP job manager |
| `internal/certparse/certparse.go` | Parse PEM/DER files via Go crypto/x509, map to model.Certificate |
| `internal/certparse/certparse_test.go` | Tests for certificate parser |
| `internal/export/csv.go` | CSV export with Venafi-aligned column layout |
| `internal/export/csv_test.go` | Tests for CSV export |
| `internal/export/json.go` | JSON export with full certificate + observation data |
| `internal/export/json_test.go` | Tests for JSON export |
| `internal/export/venafi/client.go` | Venafi TPP REST API client with OAuth2 token refresh |
| `internal/export/venafi/client_test.go` | Tests for Venafi client |
| `internal/api/handler/export.go` | HTTP handlers for export endpoints |
| `internal/api/handler/pcap.go` | HTTP handlers for PCAP upload/status endpoints |
| `frontend/src/routes/upload/+page.svelte` | PCAP upload page with drag-and-drop |
| `Dockerfile` | Multi-stage build: Go + SvelteKit → minimal runtime |
| `docker/zeek/Dockerfile` | Zeek sensor image with CipherFlag config |
| `docker/zeek/entrypoint.sh` | Zeek entrypoint: live capture + PCAP watcher + sentinel files |
| `docker/zeek/local.zeek` | Zeek policy: JSON logs, cert extraction, log rotation |
| `docker-compose.yml` | 3-service orchestration |
| `.env.example` | Environment variable defaults |
| `LICENSE` | Apache License 2.0 |
| `CONTRIBUTING.md` | Development setup, PR process |
| `docs/quickstart.md` | 5-minute docker-compose guide |
| `docs/configuration.md` | All config options |
| `docs/venafi-export.md` | Venafi integration guide |
| `docs/architecture.md` | Design overview for contributors |

### Modified Files

| File | Changes |
|------|---------|
| `internal/store/postgres.go` | Multi-file migration runner, batch upsert rewrite, PCAP job CRUD, raw_pem in scans/inserts |
| `internal/store/store.go` | Add PCAP job interface methods, update UpsertCertificate signature notes |
| `internal/model/certificate.go` | Add `RawPEM string` field |
| `internal/config/config.go` | Port default 8443, typed source/export/pcap config structs |
| `config/cipherflag.toml` | Add export and pcap config sections |
| `cmd/cipherflag/main.go` | Start poller goroutine in serve command |
| `internal/api/server.go` | Register export and pcap routes |
| `frontend/src/lib/api.ts` | Add export and PCAP API client functions |
| `frontend/src/routes/certificates/+page.svelte` | Add Export button |
| `README.md` | Rewrite for open-source audience |

---

## Chunk 1: Prerequisites — Migration System, Config, and Model Changes

### Task 1: Upgrade Migration System to Multi-File Runner

**Files:**
- Modify: `internal/store/postgres.go:17-38`
- Test: `internal/store/postgres_test.go` (new)

- [ ] **Step 1: Write test for multi-file migration runner**

Create `internal/store/postgres_test.go`:

```go
package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connStr := os.Getenv("CIPHERFLAG_TEST_DB")
	if connStr == "" {
		connStr = "postgres://cipherflag:dev@localhost:5432/cipherflag_test?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		t.Skipf("skipping: cannot connect to test database: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func TestMigrate_RunsAllMigrations(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Clean slate
	pool.Exec(ctx, "DROP TABLE IF EXISTS schema_migrations CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS pcap_jobs CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS health_reports CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS observations CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS endpoint_profiles CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS certificates CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS ingestion_state CASCADE")
	pool.Exec(ctx, "DROP MATERIALIZED VIEW IF EXISTS mv_summary CASCADE")

	store := &PostgresStore{pool: pool}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() failed: %v", err)
	}

	// Verify schema_migrations tracking table exists and has entries
	var count int
	err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("schema_migrations table missing: %v", err)
	}
	if count < 1 {
		t.Fatalf("expected at least 1 migration recorded, got %d", count)
	}

	// Run again — should be idempotent
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate() failed: %v", err)
	}
}

func TestMigrate_CreatesAllTables(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Clean and migrate
	pool.Exec(ctx, "DROP TABLE IF EXISTS schema_migrations CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS pcap_jobs CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS health_reports CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS observations CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS endpoint_profiles CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS certificates CASCADE")
	pool.Exec(ctx, "DROP TABLE IF EXISTS ingestion_state CASCADE")
	pool.Exec(ctx, "DROP MATERIALIZED VIEW IF EXISTS mv_summary CASCADE")

	store := &PostgresStore{pool: pool}
	store.Migrate(ctx)

	// Check all expected tables exist
	tables := []string{"certificates", "observations", "endpoint_profiles",
		"health_reports", "ingestion_state", "pcap_jobs", "schema_migrations"}
	for _, table := range tables {
		var exists bool
		err := pool.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table).Scan(&exists)
		if err != nil || !exists {
			t.Errorf("table %q should exist after migration", table)
		}
	}

	// Check raw_pem column on certificates
	var colExists bool
	pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='certificates' AND column_name='raw_pem')").Scan(&colExists)
	if !colExists {
		t.Error("certificates.raw_pem column should exist after migration")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/store/ -run TestMigrate -v -count=1`
Expected: FAIL — `schema_migrations` table doesn't exist, `pcap_jobs` table doesn't exist.

- [ ] **Step 3: Create migration files 002 and 003**

Create `internal/store/migrations/002_pcap_jobs.sql`:

```sql
CREATE TABLE IF NOT EXISTS pcap_jobs (
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

Create `internal/store/migrations/003_raw_pem.sql`:

```sql
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS raw_pem TEXT;
```

- [ ] **Step 4: Rewrite Migrate() to use multi-file runner**

In `internal/store/postgres.go`, replace the single-file embed with:

```go
import (
	"embed"
	"io/fs"
	"sort"
	// ... existing imports
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func (s *PostgresStore) Migrate(ctx context.Context) error {
	// Create tracking table
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ DEFAULT now()
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	// Read migration files
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()

		// Check if already applied
		var applied bool
		s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", name).Scan(&applied)
		if applied {
			continue
		}

		// Read and execute
		content, err := fs.ReadFile(migrationsFS, "migrations/"+name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := s.pool.Exec(ctx, string(content)); err != nil {
			return fmt.Errorf("execute migration %s: %w", name, err)
		}

		// Record
		if _, err := s.pool.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", name); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
	}
	return nil
}
```

Remove the old `//go:embed migrations/001_initial.sql` and `var migrationSQL string` lines.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/store/ -run TestMigrate -v -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/store/postgres.go internal/store/postgres_test.go \
  internal/store/migrations/002_pcap_jobs.sql internal/store/migrations/003_raw_pem.sql
git commit -m "feat: upgrade migration system to multi-file runner with tracking"
```

---

### Task 2: Add RawPEM Field to Certificate Model

**Files:**
- Modify: `internal/model/certificate.go:48-70`

- [ ] **Step 1: Add RawPEM field to Certificate struct**

In `internal/model/certificate.go`, add after line 66 (`SCTs` field):

```go
RawPEM                string             `json:"raw_pem,omitempty"`
```

- [ ] **Step 2: Verify build compiles**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: Success (RawPEM is a new field, no existing code references it yet)

- [ ] **Step 3: Commit**

```bash
git add internal/model/certificate.go
git commit -m "feat: add RawPEM field to Certificate model"
```

---

### Task 3: Update PostgresStore for RawPEM and Batch Upserts

**Files:**
- Modify: `internal/store/postgres.go:47-91` (UpsertCertificate), `228-235` (BatchUpsertCertificates), `773-828` (scanners)

- [ ] **Step 1: Write test for batch upsert performance**

Add to `internal/store/postgres_test.go`:

```go
func TestBatchUpsertCertificates(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	store := &PostgresStore{pool: pool}
	store.Migrate(ctx)

	certs := make([]*model.Certificate, 50)
	now := time.Now()
	for i := range certs {
		certs[i] = &model.Certificate{
			FingerprintSHA256:  fmt.Sprintf("batch-test-fp-%04d", i),
			Subject:           model.DistinguishedName{CommonName: fmt.Sprintf("batch-%d.test.com", i), Full: fmt.Sprintf("CN=batch-%d.test.com", i)},
			Issuer:            model.DistinguishedName{CommonName: "Test CA", Full: "CN=Test CA"},
			SerialNumber:      fmt.Sprintf("BATCH%04d", i),
			NotBefore:         now.Add(-24 * time.Hour),
			NotAfter:          now.Add(365 * 24 * time.Hour),
			KeyAlgorithm:      model.KeyRSA,
			KeySizeBits:       2048,
			SignatureAlgorithm: model.SigSHA256WithRSA,
			SourceDiscovery:   model.SourceZeekPassive,
			FirstSeen:         now,
			LastSeen:          now,
			RawPEM:            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		}
	}

	if err := store.BatchUpsertCertificates(ctx, certs); err != nil {
		t.Fatalf("BatchUpsertCertificates failed: %v", err)
	}

	// Verify they were inserted
	cert, err := store.GetCertificate(ctx, "batch-test-fp-0000")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected certificate to exist")
	}
	if cert.RawPEM != "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----" {
		t.Errorf("expected RawPEM to be preserved, got %q", cert.RawPEM)
	}

	// Cleanup
	for i := range certs {
		pool.Exec(ctx, "DELETE FROM certificates WHERE fingerprint_sha256 = $1", fmt.Sprintf("batch-test-fp-%04d", i))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/store/ -run TestBatchUpsert -v -count=1`
Expected: FAIL — `raw_pem` not in INSERT/SELECT statements.

- [ ] **Step 3: Update UpsertCertificate to include raw_pem**

In `internal/store/postgres.go`, modify `UpsertCertificate` to add `raw_pem` as the 31st column in both INSERT and VALUES. Add to the ON CONFLICT UPDATE clause:

```go
ON CONFLICT (fingerprint_sha256) DO UPDATE SET
    last_seen = EXCLUDED.last_seen,
    source_discovery = EXCLUDED.source_discovery,
    raw_pem = COALESCE(NULLIF(EXCLUDED.raw_pem, ''), certificates.raw_pem)
```

Add `cert.RawPEM` as the 31st parameter.

- [ ] **Step 4: Update scanCertificate and scanCertificateRows to include raw_pem**

Add `raw_pem` to the SELECT list in `GetCertificate`, `SearchCertificates`, and `GetAllCertificatesForGraph`. Add `&c.RawPEM` to the Scan calls in both `scanCertificate` and `scanCertificateRows`.

- [ ] **Step 5: Rewrite BatchUpsertCertificates with multi-row INSERT**

Replace the loop-based implementation with a batch approach using a single transaction with `pgx.Batch`:

```go
func (s *PostgresStore) BatchUpsertCertificates(ctx context.Context, certs []*model.Certificate) error {
	if len(certs) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, cert := range certs {
		sans, _ := json.Marshal(cert.SubjectAltNames)
		ku, _ := json.Marshal(cert.KeyUsage)
		eku, _ := json.Marshal(cert.ExtendedKeyUsage)
		ocsp, _ := json.Marshal(cert.OCSPResponderURLs)
		crl, _ := json.Marshal(cert.CRLDistributionPoints)
		scts, _ := json.Marshal(cert.SCTs)

		batch.Queue(`
			INSERT INTO certificates (
				fingerprint_sha256, subject_cn, subject_org, subject_ou,
				subject_country, subject_state, subject_locality, subject_full,
				issuer_cn, issuer_org, issuer_ou, issuer_country, issuer_full,
				serial_number, not_before, not_after,
				key_algorithm, key_size_bits, signature_algorithm,
				subject_alt_names, is_ca, basic_constraints_path_len,
				key_usage, extended_key_usage,
				ocsp_responder_urls, crl_distribution_points, scts,
				source_discovery, first_seen, last_seen, raw_pem
			) VALUES (
				$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
				$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31
			)
			ON CONFLICT (fingerprint_sha256) DO UPDATE SET
				last_seen = EXCLUDED.last_seen,
				source_discovery = EXCLUDED.source_discovery,
				raw_pem = COALESCE(NULLIF(EXCLUDED.raw_pem, ''), certificates.raw_pem)
		`,
			cert.FingerprintSHA256,
			cert.Subject.CommonName, cert.Subject.Organization, cert.Subject.OrganizationalUnit,
			cert.Subject.Country, cert.Subject.State, cert.Subject.Locality, cert.Subject.Full,
			cert.Issuer.CommonName, cert.Issuer.Organization, cert.Issuer.OrganizationalUnit,
			cert.Issuer.Country, cert.Issuer.Full,
			cert.SerialNumber, cert.NotBefore, cert.NotAfter,
			string(cert.KeyAlgorithm), cert.KeySizeBits, string(cert.SignatureAlgorithm),
			sans, cert.IsCA, cert.BasicConstraintsPathLen,
			ku, eku, ocsp, crl, scts,
			string(cert.SourceDiscovery), cert.FirstSeen, cert.LastSeen, cert.RawPEM,
		)
	}

	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range certs {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("batch upsert: %w", err)
		}
	}
	return nil
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/store/ -run TestBatchUpsert -v -count=1`
Expected: PASS

- [ ] **Step 7: Run full build to verify nothing broken**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: Success

- [ ] **Step 8: Commit**

```bash
git add internal/store/postgres.go internal/store/postgres_test.go
git commit -m "feat: add raw_pem support and rewrite batch upserts with pgx.Batch"
```

---

### Task 4: Upgrade Config with Typed Source, Export, and PCAP Sections

**Files:**
- Modify: `internal/config/config.go`
- Modify: `config/cipherflag.toml`

- [ ] **Step 1: Rewrite config.go with typed structs**

Replace `internal/config/config.go` entirely:

```go
package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server   ServerConfig   `toml:"server"`
	Storage  StorageConfig  `toml:"storage"`
	Analysis AnalysisConfig `toml:"analysis"`
	Sources  SourcesConfig  `toml:"sources"`
	Export   ExportConfig   `toml:"export"`
	PCAP     PCAPConfig     `toml:"pcap"`
}

type ServerConfig struct {
	Listen      string `toml:"listen"`
	FrontendURL string `toml:"frontend_url"`
}

type StorageConfig struct {
	PostgresURL string `toml:"postgres_url"`
	SQLitePath  string `toml:"sqlite_path"`
}

type AnalysisConfig struct {
	RecheckIntervalHours int            `toml:"recheck_interval_hours"`
	ExpiryWarningDays    []int          `toml:"expiry_warning_days"`
	ProtocolPolicy       ProtocolPolicy `toml:"protocol_policy"`
}

type ProtocolPolicy struct {
	MinTLSVersion         string   `toml:"min_tls_version"`
	RequireForwardSecrecy bool     `toml:"require_forward_secrecy"`
	RequireAEAD           bool     `toml:"require_aead"`
	BannedCiphers         []string `toml:"banned_ciphers"`
}

type SourcesConfig struct {
	ZeekFile  ZeekFileSourceConfig  `toml:"zeek_file"`
	Corelight CorelightSourceConfig `toml:"corelight"`
}

type ZeekFileSourceConfig struct {
	Enabled             bool   `toml:"enabled"`
	LogDir              string `toml:"log_dir"`
	PollIntervalSeconds int    `toml:"poll_interval_seconds"`
}

type CorelightSourceConfig struct {
	Enabled  bool   `toml:"enabled"`
	APIURL   string `toml:"api_url"`
	APIToken string `toml:"api_token"`
}

type ExportConfig struct {
	Venafi VenafiExportConfig `toml:"venafi"`
}

type VenafiExportConfig struct {
	Enabled             bool   `toml:"enabled"`
	BaseURL             string `toml:"base_url"`
	ClientID            string `toml:"client_id"`
	RefreshToken        string `toml:"refresh_token"`
	Folder              string `toml:"folder"`
	PushIntervalMinutes int    `toml:"push_interval_minutes"`
}

type PCAPConfig struct {
	MaxFileSizeMB    int `toml:"max_file_size_mb"`
	RetentionHours   int `toml:"retention_hours"`
	InputDir         string `toml:"input_dir"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	// Defaults
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "0.0.0.0:8443"
	}
	if cfg.Analysis.RecheckIntervalHours == 0 {
		cfg.Analysis.RecheckIntervalHours = 6
	}
	if cfg.Sources.ZeekFile.PollIntervalSeconds == 0 {
		cfg.Sources.ZeekFile.PollIntervalSeconds = 30
	}
	if cfg.Sources.ZeekFile.LogDir == "" {
		cfg.Sources.ZeekFile.LogDir = "/var/log/zeek/current"
	}
	if cfg.Export.Venafi.PushIntervalMinutes == 0 {
		cfg.Export.Venafi.PushIntervalMinutes = 60
	}
	if cfg.Export.Venafi.Folder == "" {
		cfg.Export.Venafi.Folder = `\VED\Policy\Discovered\CipherFlag`
	}
	if cfg.PCAP.MaxFileSizeMB == 0 {
		cfg.PCAP.MaxFileSizeMB = 500
	}
	if cfg.PCAP.RetentionHours == 0 {
		cfg.PCAP.RetentionHours = 24
	}
	if cfg.PCAP.InputDir == "" {
		cfg.PCAP.InputDir = "/pcap-input"
	}
	return &cfg, nil
}
```

- [ ] **Step 2: Update cipherflag.toml with new sections**

Append to `config/cipherflag.toml`:

```toml
[export.venafi]
enabled = false
base_url = ""
client_id = ""
refresh_token = ""
folder = "\\VED\\Policy\\Discovered\\CipherFlag"
push_interval_minutes = 60

[pcap]
max_file_size_mb = 500
retention_hours = 24
input_dir = "/pcap-input"
```

- [ ] **Step 3: Verify build compiles**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: Success

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go config/cipherflag.toml
git commit -m "feat: add typed config for sources, export, and pcap sections"
```

---

### Task 5: Add PCAP Job Store Methods

**Files:**
- Modify: `internal/store/store.go:116-157`
- Modify: `internal/store/postgres.go`

- [ ] **Step 1: Define PCAPJob model**

Create a `PCAPJob` struct. Add to `internal/model/source.go`:

```go
type PCAPJob struct {
	ID          string    `json:"id"`
	Filename    string    `json:"filename"`
	FileSize    int64     `json:"file_size"`
	Status      string    `json:"status"` // queued, processing, complete, failed
	CertsFound  int       `json:"certs_found"`
	CertsNew    int       `json:"certs_new"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}
```

- [ ] **Step 2: Add interface methods to CertStore**

In `internal/store/store.go`, add to the `CertStore` interface before the `// Lifecycle` comment:

```go
// PCAP Jobs
CreatePCAPJob(ctx context.Context, job *model.PCAPJob) error
GetPCAPJob(ctx context.Context, id string) (*model.PCAPJob, error)
UpdatePCAPJob(ctx context.Context, job *model.PCAPJob) error
ListPCAPJobs(ctx context.Context, limit int) ([]model.PCAPJob, error)
```

- [ ] **Step 3: Write test for PCAP job CRUD**

Add to `internal/store/postgres_test.go`:

```go
func TestPCAPJobCRUD(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	st := &PostgresStore{pool: pool}
	st.Migrate(ctx)

	job := &model.PCAPJob{
		Filename: "test.pcap",
		FileSize: 1024,
		Status:   "queued",
	}
	if err := st.CreatePCAPJob(ctx, job); err != nil {
		t.Fatalf("CreatePCAPJob failed: %v", err)
	}
	if job.ID == "" {
		t.Fatal("expected ID to be set")
	}

	got, err := st.GetPCAPJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetPCAPJob failed: %v", err)
	}
	if got.Filename != "test.pcap" {
		t.Errorf("expected filename test.pcap, got %s", got.Filename)
	}
	if got.Status != "queued" {
		t.Errorf("expected status queued, got %s", got.Status)
	}

	got.Status = "complete"
	got.CertsFound = 5
	got.CertsNew = 3
	now := time.Now()
	got.CompletedAt = &now
	if err := st.UpdatePCAPJob(ctx, got); err != nil {
		t.Fatalf("UpdatePCAPJob failed: %v", err)
	}

	updated, _ := st.GetPCAPJob(ctx, job.ID)
	if updated.Status != "complete" {
		t.Errorf("expected status complete, got %s", updated.Status)
	}
	if updated.CertsFound != 5 {
		t.Errorf("expected certs_found 5, got %d", updated.CertsFound)
	}

	jobs, err := st.ListPCAPJobs(ctx, 10)
	if err != nil {
		t.Fatalf("ListPCAPJobs failed: %v", err)
	}
	found := false
	for _, j := range jobs {
		if j.ID == job.ID {
			found = true
		}
	}
	if !found {
		t.Error("expected job in list")
	}

	// Cleanup
	pool.Exec(ctx, "DELETE FROM pcap_jobs WHERE id = $1", job.ID)
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/store/ -run TestPCAPJob -v -count=1`
Expected: FAIL — methods not implemented.

- [ ] **Step 5: Implement PCAP job methods in postgres.go**

Add to `internal/store/postgres.go`:

```go
// ── PCAP Jobs ────────────────────────────────────────────────────────────

func (s *PostgresStore) CreatePCAPJob(ctx context.Context, job *model.PCAPJob) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO pcap_jobs (filename, file_size, status)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`, job.Filename, job.FileSize, job.Status).Scan(&job.ID, &job.CreatedAt)
}

func (s *PostgresStore) GetPCAPJob(ctx context.Context, id string) (*model.PCAPJob, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, filename, file_size, status, certs_found, certs_new,
			COALESCE(error, ''), created_at, completed_at
		FROM pcap_jobs WHERE id = $1
	`, id)
	var j model.PCAPJob
	err := row.Scan(&j.ID, &j.Filename, &j.FileSize, &j.Status,
		&j.CertsFound, &j.CertsNew, &j.Error, &j.CreatedAt, &j.CompletedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &j, nil
}

func (s *PostgresStore) UpdatePCAPJob(ctx context.Context, job *model.PCAPJob) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE pcap_jobs SET status=$1, certs_found=$2, certs_new=$3,
			error=$4, completed_at=$5
		WHERE id = $6
	`, job.Status, job.CertsFound, job.CertsNew, job.Error, job.CompletedAt, job.ID)
	return err
}

func (s *PostgresStore) ListPCAPJobs(ctx context.Context, limit int) ([]model.PCAPJob, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, filename, file_size, status, certs_found, certs_new,
			COALESCE(error, ''), created_at, completed_at
		FROM pcap_jobs ORDER BY created_at DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []model.PCAPJob
	for rows.Next() {
		var j model.PCAPJob
		if err := rows.Scan(&j.ID, &j.Filename, &j.FileSize, &j.Status,
			&j.CertsFound, &j.CertsNew, &j.Error, &j.CreatedAt, &j.CompletedAt); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/store/ -run TestPCAPJob -v -count=1`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/model/source.go internal/store/store.go internal/store/postgres.go internal/store/postgres_test.go
git commit -m "feat: add PCAP job model and store CRUD operations"
```

---

## Chunk 2: Zeek Log Parsing and Certificate Parsing

### Task 6: Zeek JSON Log Parser

**Files:**
- Create: `internal/ingest/zeek/parser.go`
- Create: `internal/ingest/zeek/parser_test.go`

- [ ] **Step 1: Write test for x509 log parsing**

Create `internal/ingest/zeek/parser_test.go`:

```go
package zeek

import (
	"testing"
	"time"
)

const sampleX509Log = `{"ts":1710000000.0,"id":"FZxxx","certificate.version":3,"certificate.serial":"0A01","certificate.subject":"CN=example.com,O=Example Inc","certificate.issuer":"CN=DigiCert SHA2,O=DigiCert Inc","certificate.not_valid_before":1700000000.0,"certificate.not_valid_after":1730000000.0,"certificate.key_alg":"rsaEncryption","certificate.sig_alg":"sha256WithRSAEncryption","certificate.key_type":"rsa","certificate.key_length":2048,"san.dns":["example.com","www.example.com"],"basic_constraints.ca":false,"fingerprint":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}`

func TestParseX509Record(t *testing.T) {
	rec, err := ParseX509Record([]byte(sampleX509Log))
	if err != nil {
		t.Fatalf("ParseX509Record failed: %v", err)
	}
	if rec.Fingerprint != "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
		t.Errorf("unexpected fingerprint: %s", rec.Fingerprint)
	}
	if rec.SubjectCN != "example.com" {
		t.Errorf("unexpected subject CN: %s", rec.SubjectCN)
	}
	if rec.IssuerCN != "DigiCert SHA2" {
		t.Errorf("unexpected issuer CN: %s", rec.IssuerCN)
	}
	if rec.KeyAlg != "rsaEncryption" {
		t.Errorf("unexpected key alg: %s", rec.KeyAlg)
	}
	if rec.KeyLength != 2048 {
		t.Errorf("unexpected key length: %d", rec.KeyLength)
	}
	if len(rec.SANsDNS) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(rec.SANsDNS))
	}
	if rec.IsCA {
		t.Error("expected IsCA=false")
	}
	if rec.NotValidBefore.IsZero() || rec.NotValidAfter.IsZero() {
		t.Error("expected valid timestamps")
	}
}

const sampleConnLog = `{"ts":1710000000.0,"uid":"CZxxx","id.orig_h":"10.0.0.1","id.orig_p":45678,"id.resp_h":"93.184.216.34","id.resp_p":443,"proto":"tcp","duration":1.5,"orig_bytes":1024,"resp_bytes":4096,"conn_state":"SF"}`

func TestParseConnRecord(t *testing.T) {
	rec, err := ParseConnRecord([]byte(sampleConnLog))
	if err != nil {
		t.Fatalf("ParseConnRecord failed: %v", err)
	}
	if rec.UID != "CZxxx" {
		t.Errorf("unexpected UID: %s", rec.UID)
	}
	if rec.ServerIP != "93.184.216.34" {
		t.Errorf("unexpected server IP: %s", rec.ServerIP)
	}
	if rec.Proto != "tcp" {
		t.Errorf("unexpected proto: %s", rec.Proto)
	}
	if rec.Duration != 1.5 {
		t.Errorf("unexpected duration: %f", rec.Duration)
	}
	if rec.ConnState != "SF" {
		t.Errorf("unexpected conn state: %s", rec.ConnState)
	}
}

const sampleSSLLog = `{"ts":1710000000.0,"uid":"CZxxx","id.orig_h":"10.0.0.1","id.orig_p":45678,"id.resp_h":"93.184.216.34","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","server_name":"example.com","established":true,"ja3":"abc123","ja3s":"def456","cert_chain_fps":["abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"]}`

func TestParseSSLRecord(t *testing.T) {
	rec, err := ParseSSLRecord([]byte(sampleSSLLog))
	if err != nil {
		t.Fatalf("ParseSSLRecord failed: %v", err)
	}
	if rec.ServerIP != "93.184.216.34" {
		t.Errorf("unexpected server IP: %s", rec.ServerIP)
	}
	if rec.ServerPort != 443 {
		t.Errorf("unexpected server port: %d", rec.ServerPort)
	}
	if rec.Version != "TLSv13" {
		t.Errorf("unexpected version: %s", rec.Version)
	}
	if rec.Cipher != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("unexpected cipher: %s", rec.Cipher)
	}
	if rec.ServerName != "example.com" {
		t.Errorf("unexpected SNI: %s", rec.ServerName)
	}
	if rec.JA3 != "abc123" {
		t.Errorf("unexpected JA3: %s", rec.JA3)
	}
	if len(rec.CertChainFPs) != 1 {
		t.Errorf("expected 1 cert chain FP, got %d", len(rec.CertChainFPs))
	}
	_ = time.Now() // suppress unused import
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/ingest/zeek/ -v -count=1`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Implement parser**

Create `internal/ingest/zeek/parser.go`:

```go
package zeek

import (
	"encoding/json"
	"strings"
	"time"
)

// X509Record represents a parsed Zeek x509.log JSON record.
type X509Record struct {
	Timestamp       time.Time
	FileID          string
	Fingerprint     string
	SubjectCN       string
	SubjectOrg      string
	SubjectFull     string
	IssuerCN        string
	IssuerOrg       string
	IssuerFull      string
	Serial          string
	NotValidBefore  time.Time
	NotValidAfter   time.Time
	KeyAlg          string
	KeyType         string
	KeyLength       int
	SigAlg          string
	SANsDNS         []string
	SANsIP          []string
	SANsEmail       []string
	IsCA            bool
	Version         int
}

// SSLRecord represents a parsed Zeek ssl.log JSON record.
type SSLRecord struct {
	Timestamp    time.Time
	UID          string
	ClientIP     string
	ClientPort   int
	ServerIP     string
	ServerPort   int
	Version      string
	Cipher       string
	ServerName   string
	Established  bool
	JA3          string
	JA3S         string
	CertChainFPs []string
}

// ConnRecord represents a parsed Zeek conn.log JSON record.
type ConnRecord struct {
	Timestamp  time.Time
	UID        string
	ClientIP   string
	ClientPort int
	ServerIP   string
	ServerPort int
	Proto      string
	Duration   float64
	OrigBytes  int64
	RespBytes  int64
	ConnState  string
}

// raw JSON structures for Zeek log parsing
type rawX509 struct {
	TS             float64  `json:"ts"`
	ID             string   `json:"id"`
	Version        int      `json:"certificate.version"`
	Serial         string   `json:"certificate.serial"`
	Subject        string   `json:"certificate.subject"`
	Issuer         string   `json:"certificate.issuer"`
	NotValidBefore float64  `json:"certificate.not_valid_before"`
	NotValidAfter  float64  `json:"certificate.not_valid_after"`
	KeyAlg         string   `json:"certificate.key_alg"`
	SigAlg         string   `json:"certificate.sig_alg"`
	KeyType        string   `json:"certificate.key_type"`
	KeyLength      int      `json:"certificate.key_length"`
	SANsDNS        []string `json:"san.dns"`
	SANsIP         []string `json:"san.ip"`
	SANsEmail      []string `json:"san.email"`
	IsCA           bool     `json:"basic_constraints.ca"`
	Fingerprint    string   `json:"fingerprint"`
}

type rawSSL struct {
	TS           float64  `json:"ts"`
	UID          string   `json:"uid"`
	OrigH        string   `json:"id.orig_h"`
	OrigP        int      `json:"id.orig_p"`
	RespH        string   `json:"id.resp_h"`
	RespP        int      `json:"id.resp_p"`
	Version      string   `json:"version"`
	Cipher       string   `json:"cipher"`
	ServerName   string   `json:"server_name"`
	Established  bool     `json:"established"`
	JA3          string   `json:"ja3"`
	JA3S         string   `json:"ja3s"`
	CertChainFPs []string `json:"cert_chain_fps"`
}

type rawConn struct {
	TS        float64 `json:"ts"`
	UID       string  `json:"uid"`
	OrigH     string  `json:"id.orig_h"`
	OrigP     int     `json:"id.orig_p"`
	RespH     string  `json:"id.resp_h"`
	RespP     int     `json:"id.resp_p"`
	Proto     string  `json:"proto"`
	Duration  float64 `json:"duration"`
	OrigBytes int64   `json:"orig_bytes"`
	RespBytes int64   `json:"resp_bytes"`
	ConnState string  `json:"conn_state"`
}

func ParseConnRecord(data []byte) (*ConnRecord, error) {
	var raw rawConn
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return &ConnRecord{
		Timestamp:  unixToTime(raw.TS),
		UID:        raw.UID,
		ClientIP:   raw.OrigH,
		ClientPort: raw.OrigP,
		ServerIP:   raw.RespH,
		ServerPort: raw.RespP,
		Proto:      raw.Proto,
		Duration:   raw.Duration,
		OrigBytes:  raw.OrigBytes,
		RespBytes:  raw.RespBytes,
		ConnState:  raw.ConnState,
	}, nil
}

func ParseX509Record(data []byte) (*X509Record, error) {
	var raw rawX509
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	subjectCN, subjectOrg := parseDN(raw.Subject)
	issuerCN, issuerOrg := parseDN(raw.Issuer)

	return &X509Record{
		Timestamp:      unixToTime(raw.TS),
		FileID:         raw.ID,
		Fingerprint:    raw.Fingerprint,
		SubjectCN:      subjectCN,
		SubjectOrg:     subjectOrg,
		SubjectFull:    raw.Subject,
		IssuerCN:       issuerCN,
		IssuerOrg:      issuerOrg,
		IssuerFull:     raw.Issuer,
		Serial:         raw.Serial,
		NotValidBefore: unixToTime(raw.NotValidBefore),
		NotValidAfter:  unixToTime(raw.NotValidAfter),
		KeyAlg:         raw.KeyAlg,
		KeyType:        raw.KeyType,
		KeyLength:      raw.KeyLength,
		SigAlg:         raw.SigAlg,
		SANsDNS:        raw.SANsDNS,
		SANsIP:         raw.SANsIP,
		SANsEmail:      raw.SANsEmail,
		IsCA:           raw.IsCA,
		Version:        raw.Version,
	}, nil
}

func ParseSSLRecord(data []byte) (*SSLRecord, error) {
	var raw rawSSL
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return &SSLRecord{
		Timestamp:    unixToTime(raw.TS),
		UID:          raw.UID,
		ClientIP:     raw.OrigH,
		ClientPort:   raw.OrigP,
		ServerIP:     raw.RespH,
		ServerPort:   raw.RespP,
		Version:      raw.Version,
		Cipher:       raw.Cipher,
		ServerName:   raw.ServerName,
		Established:  raw.Established,
		JA3:          raw.JA3,
		JA3S:         raw.JA3S,
		CertChainFPs: raw.CertChainFPs,
	}, nil
}

func unixToTime(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}

// parseDN extracts CN and O from a Zeek-formatted DN string like "CN=example.com,O=Example Inc"
func parseDN(dn string) (cn, org string) {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			cn = strings.TrimPrefix(part, "CN=")
		} else if strings.HasPrefix(part, "O=") {
			org = strings.TrimPrefix(part, "O=")
		}
	}
	return
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/ingest/zeek/ -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ingest/zeek/parser.go internal/ingest/zeek/parser_test.go
git commit -m "feat: add Zeek JSON log parser for x509 and ssl records"
```

---

### Task 7: Zeek Record to CipherFlag Model Mapper

**Files:**
- Create: `internal/ingest/zeek/mapper.go`
- Create: `internal/ingest/zeek/mapper_test.go`

- [ ] **Step 1: Write test for x509-to-Certificate mapping**

Create `internal/ingest/zeek/mapper_test.go`:

```go
package zeek

import (
	"testing"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func TestMapX509ToCertificate(t *testing.T) {
	rec := &X509Record{
		Fingerprint:    "abc123",
		SubjectCN:      "example.com",
		SubjectOrg:     "Example Inc",
		SubjectFull:    "CN=example.com,O=Example Inc",
		IssuerCN:       "DigiCert SHA2",
		IssuerOrg:      "DigiCert Inc",
		IssuerFull:     "CN=DigiCert SHA2,O=DigiCert Inc",
		Serial:         "0A01",
		NotValidBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotValidAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyAlg:         "rsaEncryption",
		KeyType:        "rsa",
		KeyLength:      2048,
		SigAlg:         "sha256WithRSAEncryption",
		SANsDNS:        []string{"example.com", "www.example.com"},
		IsCA:           false,
	}

	cert := MapX509ToCertificate(rec)

	if cert.FingerprintSHA256 != "abc123" {
		t.Errorf("fingerprint: got %s", cert.FingerprintSHA256)
	}
	if cert.KeyAlgorithm != model.KeyRSA {
		t.Errorf("key alg: got %s", cert.KeyAlgorithm)
	}
	if cert.KeySizeBits != 2048 {
		t.Errorf("key size: got %d", cert.KeySizeBits)
	}
	if cert.SignatureAlgorithm != model.SigSHA256WithRSA {
		t.Errorf("sig alg: got %s", cert.SignatureAlgorithm)
	}
	if cert.SourceDiscovery != model.SourceZeekPassive {
		t.Errorf("source: got %s", cert.SourceDiscovery)
	}
	if len(cert.SubjectAltNames) != 2 {
		t.Errorf("SANs: got %d", len(cert.SubjectAltNames))
	}
}

func TestMapSSLToObservation(t *testing.T) {
	rec := &SSLRecord{
		Timestamp:    time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		ServerIP:     "93.184.216.34",
		ServerPort:   443,
		ServerName:   "example.com",
		ClientIP:     "10.0.0.1",
		Version:      "TLSv13",
		Cipher:       "TLS_AES_256_GCM_SHA384",
		JA3:          "abc",
		JA3S:         "def",
		CertChainFPs: []string{"abc123"},
	}

	obs := MapSSLToObservations(rec)
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	o := obs[0]
	if o.ServerIP != "93.184.216.34" {
		t.Errorf("server IP: got %s", o.ServerIP)
	}
	if o.NegotiatedVersion != model.TLSVersion13 {
		t.Errorf("TLS version: got %s", o.NegotiatedVersion)
	}
	if o.CertFingerprint != "abc123" {
		t.Errorf("fingerprint: got %s", o.CertFingerprint)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/ingest/zeek/ -run TestMap -v -count=1`
Expected: FAIL — functions don't exist yet.

- [ ] **Step 3: Implement mapper**

Create `internal/ingest/zeek/mapper.go`:

```go
package zeek

import (
	"strings"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

// MapX509ToCertificate converts a Zeek x509 record to a CipherFlag Certificate.
func MapX509ToCertificate(rec *X509Record) *model.Certificate {
	now := time.Now()
	sans := make([]string, 0, len(rec.SANsDNS)+len(rec.SANsIP)+len(rec.SANsEmail))
	sans = append(sans, rec.SANsDNS...)
	sans = append(sans, rec.SANsIP...)
	sans = append(sans, rec.SANsEmail...)

	return &model.Certificate{
		FingerprintSHA256:  rec.Fingerprint,
		Subject: model.DistinguishedName{
			CommonName:   rec.SubjectCN,
			Organization: rec.SubjectOrg,
			Full:         rec.SubjectFull,
		},
		Issuer: model.DistinguishedName{
			CommonName:   rec.IssuerCN,
			Organization: rec.IssuerOrg,
			Full:         rec.IssuerFull,
		},
		SerialNumber:       rec.Serial,
		NotBefore:          rec.NotValidBefore,
		NotAfter:           rec.NotValidAfter,
		KeyAlgorithm:       mapKeyAlgorithm(rec.KeyAlg, rec.KeyType),
		KeySizeBits:        rec.KeyLength,
		SignatureAlgorithm: mapSigAlgorithm(rec.SigAlg),
		SubjectAltNames:    sans,
		IsCA:               rec.IsCA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now,
		LastSeen:           now,
	}
}

// MapSSLToObservations converts a Zeek ssl record to CertificateObservation(s) — one per cert in the chain.
func MapSSLToObservations(rec *SSLRecord) []*model.CertificateObservation {
	var obs []*model.CertificateObservation
	for _, fp := range rec.CertChainFPs {
		obs = append(obs, &model.CertificateObservation{
			CertFingerprint:   fp,
			ServerIP:          rec.ServerIP,
			ServerPort:        rec.ServerPort,
			ServerName:        rec.ServerName,
			ClientIP:          rec.ClientIP,
			NegotiatedVersion: mapTLSVersion(rec.Version),
			NegotiatedCipher:  rec.Cipher,
			CipherStrength:    classifyCipherStrength(rec.Cipher),
			JA3Fingerprint:    rec.JA3,
			JA3SFingerprint:   rec.JA3S,
			Source:            model.SourceZeekPassive,
			ObservedAt:        rec.Timestamp,
		})
	}
	return obs
}

func mapKeyAlgorithm(alg, keyType string) model.KeyAlgorithm {
	lower := strings.ToLower(alg + keyType)
	switch {
	case strings.Contains(lower, "rsa"):
		return model.KeyRSA
	case strings.Contains(lower, "ec") || strings.Contains(lower, "ecdsa"):
		return model.KeyECDSA
	case strings.Contains(lower, "ed25519"):
		return model.KeyEd25519
	default:
		return model.KeyUnknown
	}
}

func mapSigAlgorithm(alg string) model.SignatureAlgorithm {
	lower := strings.ToLower(alg)
	switch {
	case strings.Contains(lower, "sha256") && strings.Contains(lower, "rsa"):
		return model.SigSHA256WithRSA
	case strings.Contains(lower, "sha384") && strings.Contains(lower, "rsa"):
		return model.SigSHA384WithRSA
	case strings.Contains(lower, "sha512") && strings.Contains(lower, "rsa"):
		return model.SigSHA512WithRSA
	case strings.Contains(lower, "sha1") && strings.Contains(lower, "rsa"):
		return model.SigSHA1WithRSA
	case strings.Contains(lower, "md5"):
		return model.SigMD5WithRSA
	case strings.Contains(lower, "ecdsa") && strings.Contains(lower, "sha256"):
		return model.SigECDSAWithSHA256
	case strings.Contains(lower, "ecdsa") && strings.Contains(lower, "sha384"):
		return model.SigECDSAWithSHA384
	case strings.Contains(lower, "ed25519"):
		return model.SigEd25519Sig
	default:
		return model.SigUnknown
	}
}

func mapTLSVersion(v string) model.TLSVersion {
	switch v {
	case "TLSv13", "TLSv1.3":
		return model.TLSVersion13
	case "TLSv12", "TLSv1.2":
		return model.TLSVersion12
	case "TLSv11", "TLSv1.1":
		return model.TLSVersion11
	case "TLSv10", "TLSv1", "TLSv1.0":
		return model.TLSVersion10
	case "SSLv30", "SSLv3":
		return model.TLSVersionSSL30
	default:
		return model.TLSVersionUnk
	}
}

func classifyCipherStrength(cipher string) model.CipherStrength {
	lower := strings.ToLower(cipher)
	switch {
	case strings.Contains(lower, "chacha20") || strings.Contains(lower, "aes_256_gcm"):
		return model.StrengthBest
	case strings.Contains(lower, "aes_128_gcm") || strings.Contains(lower, "aes_256"):
		return model.StrengthStrong
	case strings.Contains(lower, "aes_128"):
		return model.StrengthAcceptable
	case strings.Contains(lower, "3des") || strings.Contains(lower, "rc4"):
		return model.StrengthWeak
	case strings.Contains(lower, "null") || strings.Contains(lower, "export"):
		return model.StrengthInsecure
	default:
		return model.StrengthUnknown
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/ingest/zeek/ -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ingest/zeek/mapper.go internal/ingest/zeek/mapper_test.go
git commit -m "feat: add Zeek-to-CipherFlag model mapper with algorithm classification"
```

---

### Task 8: X.509 PEM/DER Certificate Parser

**Files:**
- Create: `internal/certparse/certparse.go`
- Create: `internal/certparse/certparse_test.go`

- [ ] **Step 1: Write test for PEM parsing**

Create `internal/certparse/certparse_test.go`:

```go
package certparse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func generateTestCert(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com", Organization: []string{"Test Org"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com", "www.example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestParsePEM(t *testing.T) {
	pemData := generateTestCert(t)
	cert, err := ParsePEM(pemData)
	if err != nil {
		t.Fatalf("ParsePEM failed: %v", err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("CN: got %s", cert.Subject.CommonName)
	}
	if cert.KeyAlgorithm != model.KeyECDSA {
		t.Errorf("key alg: got %s", cert.KeyAlgorithm)
	}
	if len(cert.SubjectAltNames) != 2 {
		t.Errorf("SANs: got %d", len(cert.SubjectAltNames))
	}
	if cert.FingerprintSHA256 == "" {
		t.Error("fingerprint should not be empty")
	}
	if cert.RawPEM == "" {
		t.Error("RawPEM should be populated")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/certparse/ -v -count=1`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Implement certificate parser**

Create `internal/certparse/certparse.go`:

```go
package certparse

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

// ParsePEM parses a PEM-encoded certificate and returns a CipherFlag Certificate.
func ParsePEM(pemData []byte) (*model.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return parseDER(block.Bytes, string(pemData))
}

// ParseDER parses a DER-encoded certificate and returns a CipherFlag Certificate.
func ParseDER(derData []byte) (*model.Certificate, error) {
	return parseDER(derData, "")
}

func parseDER(derData []byte, rawPEM string) (*model.Certificate, error) {
	x, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	fp := sha256.Sum256(x.Raw)
	now := time.Now()

	cert := &model.Certificate{
		FingerprintSHA256: hex.EncodeToString(fp[:]),
		Subject: model.DistinguishedName{
			CommonName:   x.Subject.CommonName,
			Organization: strings.Join(x.Subject.Organization, ", "),
			OrganizationalUnit: strings.Join(x.Subject.OrganizationalUnit, ", "),
			Country:      strings.Join(x.Subject.Country, ", "),
			State:        strings.Join(x.Subject.Province, ", "),
			Locality:     strings.Join(x.Subject.Locality, ", "),
			Full:         x.Subject.String(),
		},
		Issuer: model.DistinguishedName{
			CommonName:   x.Issuer.CommonName,
			Organization: strings.Join(x.Issuer.Organization, ", "),
			OrganizationalUnit: strings.Join(x.Issuer.OrganizationalUnit, ", "),
			Country:      strings.Join(x.Issuer.Country, ", "),
			Full:         x.Issuer.String(),
		},
		SerialNumber:       x.SerialNumber.Text(16),
		NotBefore:          x.NotBefore,
		NotAfter:           x.NotAfter,
		KeyAlgorithm:       mapPublicKeyAlgorithm(x),
		KeySizeBits:        keySize(x),
		SignatureAlgorithm: mapSignatureAlgorithm(x.SignatureAlgorithm),
		SubjectAltNames:    x.DNSNames,
		IsCA:               x.IsCA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now,
		LastSeen:           now,
		RawPEM:             rawPEM,
	}

	if x.MaxPathLen > 0 || x.MaxPathLenZero {
		pl := x.MaxPathLen
		cert.BasicConstraintsPathLen = &pl
	}

	// Key usage
	for _, ku := range mapKeyUsage(x.KeyUsage) {
		cert.KeyUsage = append(cert.KeyUsage, ku)
	}
	for _, eku := range x.ExtKeyUsage {
		cert.ExtendedKeyUsage = append(cert.ExtendedKeyUsage, mapExtKeyUsage(eku))
	}

	cert.OCSPResponderURLs = x.OCSPServer
	cert.CRLDistributionPoints = x.CRLDistributionPoints

	return cert, nil
}

func mapPublicKeyAlgorithm(cert *x509.Certificate) model.KeyAlgorithm {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return model.KeyRSA
	case *ecdsa.PublicKey:
		return model.KeyECDSA
	case ed25519.PublicKey:
		return model.KeyEd25519
	default:
		return model.KeyUnknown
	}
}

func keySize(cert *x509.Certificate) int {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func mapSignatureAlgorithm(alg x509.SignatureAlgorithm) model.SignatureAlgorithm {
	switch alg {
	case x509.SHA256WithRSA:
		return model.SigSHA256WithRSA
	case x509.SHA384WithRSA:
		return model.SigSHA384WithRSA
	case x509.SHA512WithRSA:
		return model.SigSHA512WithRSA
	case x509.SHA1WithRSA:
		return model.SigSHA1WithRSA
	case x509.MD5WithRSA:
		return model.SigMD5WithRSA
	case x509.ECDSAWithSHA256:
		return model.SigECDSAWithSHA256
	case x509.ECDSAWithSHA384:
		return model.SigECDSAWithSHA384
	case x509.PureEd25519:
		return model.SigEd25519Sig
	default:
		return model.SigUnknown
	}
}

func mapKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
	}
	for _, p := range pairs {
		if ku&p.bit != 0 {
			usages = append(usages, p.name)
		}
	}
	return usages
}

func mapExtKeyUsage(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageServerAuth:
		return "Server Authentication"
	case x509.ExtKeyUsageClientAuth:
		return "Client Authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "Code Signing"
	case x509.ExtKeyUsageEmailProtection:
		return "Email Protection"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP Signing"
	default:
		return "Unknown"
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/certparse/ -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/certparse/certparse.go internal/certparse/certparse_test.go
git commit -m "feat: add X.509 PEM/DER certificate parser using crypto/x509"
```

---

## Chunk 3: File Poller and Ingestion Pipeline

### Task 9: File Poller — Watch Zeek Log Directory and Ingest

**Files:**
- Create: `internal/ingest/poller.go`
- Create: `internal/ingest/poller_test.go`

- [ ] **Step 1: Write test for poller reading a log file**

Create `internal/ingest/poller_test.go`:

```go
package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPoller_ReadsNewLogEntries(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "x509.log")

	// Write some records
	lines := []string{
		`{"ts":1710000000.0,"id":"F1","certificate.version":3,"certificate.serial":"01","certificate.subject":"CN=a.com","certificate.issuer":"CN=CA","certificate.not_valid_before":1700000000.0,"certificate.not_valid_after":1730000000.0,"certificate.key_alg":"rsaEncryption","certificate.sig_alg":"sha256WithRSAEncryption","certificate.key_type":"rsa","certificate.key_length":2048,"basic_constraints.ca":false,"fingerprint":"fp001"}`,
		`{"ts":1710000001.0,"id":"F2","certificate.version":3,"certificate.serial":"02","certificate.subject":"CN=b.com","certificate.issuer":"CN=CA","certificate.not_valid_before":1700000000.0,"certificate.not_valid_after":1730000000.0,"certificate.key_alg":"rsaEncryption","certificate.sig_alg":"sha256WithRSAEncryption","certificate.key_type":"rsa","certificate.key_length":4096,"basic_constraints.ca":false,"fingerprint":"fp002"}`,
	}
	f, _ := os.Create(logFile)
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
	f.Close()

	// Read entries
	entries, newOffset, err := ReadLogEntries(logFile, 0)
	if err != nil {
		t.Fatalf("ReadLogEntries failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if newOffset == 0 {
		t.Error("expected non-zero offset after reading")
	}

	// Append more data
	f, _ = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString(`{"ts":1710000002.0,"id":"F3","certificate.version":3,"certificate.serial":"03","certificate.subject":"CN=c.com","certificate.issuer":"CN=CA","certificate.not_valid_before":1700000000.0,"certificate.not_valid_after":1730000000.0,"certificate.key_alg":"rsaEncryption","certificate.sig_alg":"sha256WithRSAEncryption","certificate.key_type":"rsa","certificate.key_length":2048,"basic_constraints.ca":false,"fingerprint":"fp003"}` + "\n")
	f.Close()

	// Read from offset — should only get the new entry
	entries2, _, err := ReadLogEntries(logFile, newOffset)
	if err != nil {
		t.Fatalf("ReadLogEntries from offset failed: %v", err)
	}
	if len(entries2) != 1 {
		t.Fatalf("expected 1 new entry, got %d", len(entries2))
	}

	_ = time.Now()
	_ = context.Background()
}

func TestPoller_HandlesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "x509.log")
	os.Create(logFile)

	entries, offset, err := ReadLogEntries(logFile, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
	if offset != 0 {
		t.Errorf("expected offset 0, got %d", offset)
	}
}

func TestPoller_HandlesMissingFile(t *testing.T) {
	entries, offset, err := ReadLogEntries("/nonexistent/x509.log", 0)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
	if offset != 0 {
		t.Errorf("expected offset 0, got %d", offset)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/ingest/ -v -count=1`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Implement poller**

Create `internal/ingest/poller.go`:

```go
package ingest

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cyberflag-ai/cipherflag/internal/analysis"
	"github.com/cyberflag-ai/cipherflag/internal/ingest/zeek"
	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

// ReadLogEntries reads lines from a file starting at the given byte offset.
// Returns the parsed lines as raw byte slices and the new offset.
// If the file does not exist, returns empty results with no error.
func ReadLogEntries(path string, offset int64) ([][]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, offset, err
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, offset, err
		}
	}

	var entries [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		entries = append(entries, cp)
	}
	if err := scanner.Err(); err != nil {
		return entries, offset, err
	}

	// Calculate new offset
	newOffset, _ := f.Seek(0, io.SeekCurrent)
	return entries, newOffset, nil
}

// Poller watches a Zeek log directory and ingests certificates and observations.
type Poller struct {
	logDir   string
	store    store.CertStore
	interval time.Duration
}

// NewPoller creates a new file poller.
func NewPoller(logDir string, st store.CertStore, interval time.Duration) *Poller {
	return &Poller{
		logDir:   logDir,
		store:    st,
		interval: interval,
	}
}

// Run starts the polling loop. Blocks until context is cancelled.
func (p *Poller) Run(ctx context.Context) {
	log.Info().Str("dir", p.logDir).Dur("interval", p.interval).Msg("zeek log poller starting")

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Initial poll
	p.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("zeek log poller stopped")
			return
		case <-ticker.C:
			p.poll(ctx)
		}
	}
}

func (p *Poller) poll(ctx context.Context) {
	p.pollLogFile(ctx, "x509")
	p.pollLogFile(ctx, "ssl")
}

func (p *Poller) pollLogFile(ctx context.Context, logType string) {
	// Find log files matching the pattern
	pattern := filepath.Join(p.logDir, logType+".log")
	matches, _ := filepath.Glob(pattern)

	// Also check for rotated files
	rotated, _ := filepath.Glob(filepath.Join(p.logDir, logType+".*.log"))
	matches = append(matches, rotated...)

	for _, logFile := range matches {
		sourceName := fmt.Sprintf("zeek_%s_%s", logType, filepath.Base(logFile))

		// Get cursor
		state, err := p.store.GetIngestionState(ctx, sourceName)
		if err != nil {
			log.Error().Err(err).Str("source", sourceName).Msg("failed to get ingestion state")
			continue
		}

		var offset int64
		if state != nil && state.Cursor != "" {
			offset, _ = strconv.ParseInt(state.Cursor, 10, 64)
		}

		entries, newOffset, err := ReadLogEntries(logFile, offset)
		if err != nil {
			log.Error().Err(err).Str("file", logFile).Msg("failed to read log entries")
			continue
		}
		if len(entries) == 0 {
			continue
		}

		log.Info().Str("file", logFile).Int("entries", len(entries)).Msg("processing zeek log entries")

		switch logType {
		case "x509":
			p.ProcessX509Entries(ctx, entries)
		case "ssl":
			p.ProcessSSLEntries(ctx, entries)
		}

		// Update cursor
		p.store.SetIngestionState(ctx, &model.IngestionState{
			SourceName: sourceName,
			Cursor:     strconv.FormatInt(newOffset, 10),
		})
	}
}

func (p *Poller) ProcessX509Entries(ctx context.Context, entries [][]byte) {
	var certs []*model.Certificate
	for _, entry := range entries {
		rec, err := zeek.ParseX509Record(entry)
		if err != nil {
			log.Warn().Err(err).Msg("skipping unparseable x509 record")
			continue
		}
		if rec.Fingerprint == "" {
			continue
		}
		certs = append(certs, zeek.MapX509ToCertificate(rec))
	}

	if len(certs) == 0 {
		return
	}

	if err := p.store.BatchUpsertCertificates(ctx, certs); err != nil {
		log.Error().Err(err).Int("count", len(certs)).Msg("batch upsert failed")
		return
	}

	// Score new/updated certificates
	for _, cert := range certs {
		report := analysis.ScoreCertificate(cert)
		if err := p.store.SaveHealthReport(ctx, report); err != nil {
			log.Warn().Err(err).Str("fp", cert.FingerprintSHA256).Msg("failed to save health report")
		}
	}

	log.Info().Int("count", len(certs)).Msg("ingested certificates from x509 log")
}

func (p *Poller) ProcessSSLEntries(ctx context.Context, entries [][]byte) {
	var observations []*model.CertificateObservation
	for _, entry := range entries {
		rec, err := zeek.ParseSSLRecord(entry)
		if err != nil {
			log.Warn().Err(err).Msg("skipping unparseable ssl record")
			continue
		}
		observations = append(observations, zeek.MapSSLToObservations(rec)...)
	}

	if len(observations) == 0 {
		return
	}

	// Filter out observations for certificates we haven't ingested yet
	// (avoids FK violation on observations.cert_fingerprint)
	var valid []*model.CertificateObservation
	for _, obs := range observations {
		cert, _ := p.store.GetCertificate(ctx, obs.CertFingerprint)
		if cert != nil {
			valid = append(valid, obs)
		}
	}

	if len(valid) == 0 {
		return
	}

	if err := p.store.BatchRecordObservations(ctx, valid); err != nil {
		log.Error().Err(err).Int("count", len(valid)).Msg("batch record observations failed")
		return
	}

	log.Info().Int("count", len(valid)).Int("skipped_fk", len(observations)-len(valid)).Msg("ingested observations from ssl log")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/ingest/ -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ingest/poller.go internal/ingest/poller_test.go
git commit -m "feat: add file poller for Zeek log ingestion with cursor tracking"
```

---

### Task 10: Wire Poller into Main Serve Command

**Files:**
- Modify: `cmd/cipherflag/main.go:54-92`

- [ ] **Step 1: Add poller startup to runServe**

In `cmd/cipherflag/main.go`, add the poller import and start it as a background goroutine in `runServe`, after migration and before the HTTP server starts:

```go
import (
	// ... existing imports
	"github.com/cyberflag-ai/cipherflag/internal/ingest"
)

func runServe(ctx context.Context, cfg *config.Config) {
	// ... existing store setup and migration ...

	// Start Zeek log poller if enabled
	if cfg.Sources.ZeekFile.Enabled {
		pollerCtx, pollerCancel := context.WithCancel(ctx)
		defer pollerCancel()

		poller := ingest.NewPoller(
			cfg.Sources.ZeekFile.LogDir,
			st,
			time.Duration(cfg.Sources.ZeekFile.PollIntervalSeconds)*time.Second,
		)
		go poller.Run(pollerCtx)
		log.Info().Str("dir", cfg.Sources.ZeekFile.LogDir).Msg("zeek log poller started")
	}

	// ... existing router and server setup ...
	// Update the shutdown handler to cancel poller context too
}
```

- [ ] **Step 2: Verify build compiles**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: Success

- [ ] **Step 3: Commit**

```bash
git add cmd/cipherflag/main.go
git commit -m "feat: start Zeek log poller in serve command"
```

---

### Task 10a: PCAP Job Lifecycle Manager

**Files:**
- Create: `internal/ingest/pcap.go`
- Create: `internal/ingest/pcap_test.go`

- [ ] **Step 1: Write test for sentinel file detection**

Create `internal/ingest/pcap_test.go`:

```go
package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPCAPJobManager_DetectsSentinelFile(t *testing.T) {
	logDir := t.TempDir()

	// Simulate a completed PCAP job
	jobID := "test-job-001"
	jobDir := filepath.Join(logDir, jobID)
	os.MkdirAll(jobDir, 0755)

	// Write a sentinel file
	os.WriteFile(filepath.Join(jobDir, ".done"), []byte(""), 0644)

	// Write a fake x509.log
	os.WriteFile(filepath.Join(jobDir, "x509.log"), []byte(
		`{"ts":1710000000.0,"id":"F1","certificate.version":3,"certificate.serial":"01","certificate.subject":"CN=a.com","certificate.issuer":"CN=CA","certificate.not_valid_before":1700000000.0,"certificate.not_valid_after":1730000000.0,"certificate.key_alg":"rsaEncryption","certificate.sig_alg":"sha256WithRSAEncryption","certificate.key_type":"rsa","certificate.key_length":2048,"basic_constraints.ca":false,"fingerprint":"fp-pcap-001"}`+"\n",
	), 0644)

	completed := FindCompletedPCAPJobs(logDir)
	if len(completed) != 1 {
		t.Fatalf("expected 1 completed job, got %d", len(completed))
	}
	if completed[0] != jobID {
		t.Errorf("expected job ID %s, got %s", jobID, completed[0])
	}
	_ = context.Background()
}

func TestPCAPJobManager_IgnoresIncompleteJobs(t *testing.T) {
	logDir := t.TempDir()

	// Job directory without sentinel file
	jobDir := filepath.Join(logDir, "incomplete-job")
	os.MkdirAll(jobDir, 0755)
	os.WriteFile(filepath.Join(jobDir, "x509.log"), []byte("data\n"), 0644)

	completed := FindCompletedPCAPJobs(logDir)
	if len(completed) != 0 {
		t.Fatalf("expected 0 completed jobs, got %d", len(completed))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/ingest/ -run TestPCAPJob -v -count=1`
Expected: FAIL — `FindCompletedPCAPJobs` does not exist.

- [ ] **Step 3: Implement PCAP job manager**

Create `internal/ingest/pcap.go`:

```go
package ingest

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

// FindCompletedPCAPJobs scans the log directory for job subdirectories that
// have a .done sentinel file, indicating Zeek has finished processing them.
func FindCompletedPCAPJobs(logDir string) []string {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil
	}
	var completed []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sentinel := filepath.Join(logDir, entry.Name(), ".done")
		if _, err := os.Stat(sentinel); err == nil {
			completed = append(completed, entry.Name())
		}
	}
	return completed
}

// PCAPJobManager watches for completed PCAP jobs and updates their status.
type PCAPJobManager struct {
	logDir string
	store  store.CertStore
	poller *Poller
}

// NewPCAPJobManager creates a new PCAP job lifecycle manager.
func NewPCAPJobManager(logDir string, st store.CertStore, poller *Poller) *PCAPJobManager {
	return &PCAPJobManager{logDir: logDir, store: st, poller: poller}
}

// Run periodically checks for completed PCAP jobs. Blocks until context is cancelled.
func (m *PCAPJobManager) Run(ctx context.Context) {
	log.Info().Str("dir", m.logDir).Msg("pcap job manager starting")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkJobs(ctx)
		}
	}
}

func (m *PCAPJobManager) checkJobs(ctx context.Context) {
	completed := FindCompletedPCAPJobs(m.logDir)
	for _, jobID := range completed {
		job, err := m.store.GetPCAPJob(ctx, jobID)
		if err != nil || job == nil {
			continue
		}
		if job.Status == "complete" || job.Status == "failed" {
			continue
		}

		// Update to processing
		job.Status = "processing"
		m.store.UpdatePCAPJob(ctx, job)

		// Ingest logs from job subdirectory
		jobLogDir := filepath.Join(m.logDir, jobID)
		certsFound, certsNew := m.ingestJobLogs(ctx, jobLogDir)

		// Update to complete
		job.Status = "complete"
		job.CertsFound = certsFound
		job.CertsNew = certsNew
		now := time.Now()
		job.CompletedAt = &now
		m.store.UpdatePCAPJob(ctx, job)

		log.Info().Str("job", jobID).Int("found", certsFound).Int("new", certsNew).Msg("pcap job completed")
	}
}

func (m *PCAPJobManager) ingestJobLogs(ctx context.Context, jobLogDir string) (found, new int) {
	// Read x509.log from job directory
	x509Path := filepath.Join(jobLogDir, "x509.log")
	entries, _, err := ReadLogEntries(x509Path, 0)
	if err != nil || len(entries) == 0 {
		return 0, 0
	}

	found = len(entries)

	// Count how many are truly new by checking existence before ingestion
	for _, entry := range entries {
		rec, err := parseX509ForFingerprint(entry)
		if err != nil || rec == "" {
			continue
		}
		existing, _ := m.store.GetCertificate(ctx, rec)
		if existing == nil {
			new++
		}
	}

	// Delegate to the poller's processing methods
	m.poller.processX509Entries(ctx, entries)

	// Also process ssl.log if present
	sslPath := filepath.Join(jobLogDir, "ssl.log")
	sslEntries, _, _ := ReadLogEntries(sslPath, 0)
	if len(sslEntries) > 0 {
		m.poller.processSSLEntries(ctx, sslEntries)
	}

	return found, new
}

// parseX509ForFingerprint extracts just the fingerprint from a raw x509 JSON record.
func parseX509ForFingerprint(data []byte) (string, error) {
	rec, err := zeekParseX509(data)
	if err != nil {
		return "", err
	}
	return rec, nil
}
```

Note: The `parseX509ForFingerprint` helper should import and use `zeek.ParseX509Record` from the zeek package. Adjust the import and call accordingly:

```go
import "github.com/cyberflag-ai/cipherflag/internal/ingest/zeek"

func parseX509ForFingerprint(data []byte) (string, error) {
	rec, err := zeek.ParseX509Record(data)
	if err != nil {
		return "", err
	}
	return rec.Fingerprint, nil
}
```

Also, the `processX509Entries` and `processSSLEntries` methods on `Poller` need to be exported (capitalized) so `PCAPJobManager` can call them. Rename to `ProcessX509Entries` and `ProcessSSLEntries` in Task 9.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/ingest/ -run TestPCAPJob -v -count=1`
Expected: PASS

- [ ] **Step 5: Wire PCAPJobManager into main.go**

In `cmd/cipherflag/main.go`, start the job manager alongside the poller:

```go
pcapMgr := ingest.NewPCAPJobManager(
    cfg.Sources.ZeekFile.LogDir,
    st,
    poller,
)
go pcapMgr.Run(pollerCtx)
```

- [ ] **Step 6: Commit**

```bash
git add internal/ingest/pcap.go internal/ingest/pcap_test.go cmd/cipherflag/main.go
git commit -m "feat: add PCAP job lifecycle manager with sentinel file detection"
```

---

## Chunk 4: Export — CSV, JSON, and Venafi

### Task 11: CSV and JSON Certificate Export

**Files:**
- Create: `internal/export/csv.go`
- Create: `internal/export/csv_test.go`
- Create: `internal/export/json.go`
- Create: `internal/export/json_test.go`

- [ ] **Step 1: Write test for CSV export**

Create `internal/export/csv_test.go`:

```go
package export

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func TestWriteCSV(t *testing.T) {
	certs := []*model.Certificate{
		{
			FingerprintSHA256:  "fp001",
			Subject:           model.DistinguishedName{CommonName: "test.com", Organization: "Test", Full: "CN=test.com,O=Test"},
			Issuer:            model.DistinguishedName{CommonName: "CA", Full: "CN=CA"},
			SerialNumber:      "0A01",
			NotBefore:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			KeyAlgorithm:      model.KeyRSA,
			KeySizeBits:       2048,
			SignatureAlgorithm: model.SigSHA256WithRSA,
			SubjectAltNames:   []string{"test.com", "www.test.com"},
			SourceDiscovery:   model.SourceZeekPassive,
		},
	}

	var buf bytes.Buffer
	err := WriteCSV(&buf, certs)
	if err != nil {
		t.Fatalf("WriteCSV failed: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("CSV parse failed: %v", err)
	}

	// Header + 1 data row
	if len(records) != 2 {
		t.Fatalf("expected 2 rows (header + data), got %d", len(records))
	}

	header := records[0]
	if header[0] != "Fingerprint SHA256" {
		t.Errorf("first header column: got %s", header[0])
	}

	row := records[1]
	if row[0] != "fp001" {
		t.Errorf("fingerprint: got %s", row[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/export/ -run TestWriteCSV -v -count=1`
Expected: FAIL

- [ ] **Step 3: Implement CSV export**

Create `internal/export/csv.go`:

```go
package export

import (
	"encoding/csv"
	"io"
	"strings"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

var csvHeaders = []string{
	"Fingerprint SHA256", "Subject CN", "Subject Organization", "Subject Full DN",
	"Issuer CN", "Issuer Organization", "Issuer Full DN",
	"Serial Number", "Not Before", "Not After",
	"Key Algorithm", "Key Size Bits", "Signature Algorithm",
	"Subject Alt Names", "Is CA", "Discovery Source",
	"First Seen", "Last Seen",
}

func WriteCSV(w io.Writer, certs []*model.Certificate) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write(csvHeaders); err != nil {
		return err
	}

	for _, c := range certs {
		row := []string{
			c.FingerprintSHA256,
			c.Subject.CommonName, c.Subject.Organization, c.Subject.Full,
			c.Issuer.CommonName, c.Issuer.Organization, c.Issuer.Full,
			c.SerialNumber,
			c.NotBefore.Format("2006-01-02T15:04:05Z"),
			c.NotAfter.Format("2006-01-02T15:04:05Z"),
			string(c.KeyAlgorithm),
			strconv.Itoa(c.KeySizeBits),
			string(c.SignatureAlgorithm),
			strings.Join(c.SubjectAltNames, "; "),
			boolStr(c.IsCA),
			string(c.SourceDiscovery),
			c.FirstSeen.Format("2006-01-02T15:04:05Z"),
			c.LastSeen.Format("2006-01-02T15:04:05Z"),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
```

Use `strconv.Itoa(c.KeySizeBits)` in the row builder. Add `"strconv"` to imports.

- [ ] **Step 4: Write test for JSON export**

Create `internal/export/json_test.go`:

```go
package export

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func TestWriteJSON(t *testing.T) {
	certs := []*model.Certificate{
		{
			FingerprintSHA256: "fp001",
			Subject:          model.DistinguishedName{CommonName: "test.com"},
			NotAfter:         time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, certs)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var result ExportPayload
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(result.Certificates))
	}
	if result.Certificates[0].FingerprintSHA256 != "fp001" {
		t.Errorf("fingerprint: got %s", result.Certificates[0].FingerprintSHA256)
	}
	if result.ExportedAt.IsZero() {
		t.Error("expected non-zero ExportedAt")
	}
}
```

- [ ] **Step 5: Implement JSON export**

Create `internal/export/json.go`:

```go
package export

import (
	"encoding/json"
	"io"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

type ExportPayload struct {
	ExportedAt   time.Time            `json:"exported_at"`
	Count        int                  `json:"count"`
	Certificates []*model.Certificate `json:"certificates"`
}

func WriteJSON(w io.Writer, certs []*model.Certificate) error {
	payload := ExportPayload{
		ExportedAt:   time.Now(),
		Count:        len(certs),
		Certificates: certs,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
```

- [ ] **Step 6: Run all export tests**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/export/ -v -count=1`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/export/csv.go internal/export/csv_test.go \
  internal/export/json.go internal/export/json_test.go
git commit -m "feat: add CSV and JSON certificate export"
```

---

### Task 12: Venafi TPP REST API Client

**Files:**
- Create: `internal/export/venafi/client.go`
- Create: `internal/export/venafi/client_test.go`

- [ ] **Step 1: Write test for Venafi client with mock HTTP server**

Create `internal/export/venafi/client_test.go`:

```go
package venafi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func TestClient_ImportCertificate(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/vedauth/authorize/oauth":
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "test-token",
				"refresh_token": "new-refresh",
				"expires":       3600,
			})
		case "/vedsdk/certificates/import":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("expected Bearer token, got %s", r.Header.Get("Authorization"))
			}
			json.NewDecoder(r.Body).Decode(&received)
			json.NewEncoder(w).Encode(map[string]any{
				"CertificateDN": `\VED\Policy\Test\test.com`,
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL+"/vedsdk", server.URL+"/vedauth", "test-client", "test-refresh")
	cert := &model.Certificate{
		FingerprintSHA256: "fp001",
		Subject:          model.DistinguishedName{CommonName: "test.com"},
		RawPEM:           "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}

	err := client.ImportCertificate(context.Background(), cert, `\VED\Policy\Test`)
	if err != nil {
		t.Fatalf("ImportCertificate failed: %v", err)
	}
	if received == nil {
		t.Fatal("expected request body to be captured")
	}
}

func TestClient_RefreshesToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vedauth/authorize/oauth" {
			callCount++
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "token-" + string(rune('0'+callCount)),
				"refresh_token": "refresh-new",
				"expires":       3600,
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"CertificateDN": "ok"})
	}))
	defer server.Close()

	client := NewClient(server.URL+"/vedsdk", server.URL+"/vedauth", "cid", "refresh")

	// First call triggers token acquisition
	client.ImportCertificate(context.Background(), &model.Certificate{
		RawPEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}, `\VED\Policy\Test`)

	if callCount != 1 {
		t.Errorf("expected 1 auth call, got %d", callCount)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/export/venafi/ -v -count=1`
Expected: FAIL

- [ ] **Step 3: Implement Venafi client**

Create `internal/export/venafi/client.go`:

```go
package venafi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

// Client is a Venafi TPP REST API client with OAuth2 token management.
type Client struct {
	sdkBaseURL  string
	authBaseURL string
	clientID    string
	refreshTok  string
	httpClient  *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// NewClient creates a new Venafi TPP client.
func NewClient(sdkBaseURL, authBaseURL, clientID, refreshToken string) *Client {
	return &Client{
		sdkBaseURL:  sdkBaseURL,
		authBaseURL: authBaseURL,
		clientID:    clientID,
		refreshTok:  refreshToken,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// ImportCertificate pushes a certificate to Venafi TPP.
func (c *Client) ImportCertificate(ctx context.Context, cert *model.Certificate, policyFolder string) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return fmt.Errorf("get token: %w", err)
	}

	body := map[string]any{
		"CertificateData": cert.RawPEM,
		"PolicyDN":        policyFolder,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.sdkBaseURL+"/certificates/import", bytes.NewReader(bodyJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("import request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("import failed: status %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && time.Now().Before(c.expiresAt.Add(-60*time.Second)) {
		return c.accessToken, nil
	}

	body := map[string]string{
		"client_id":     c.clientID,
		"refresh_token": c.refreshTok,
		"grant_type":    "refresh_token",
	}
	bodyJSON, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", c.authBaseURL+"/authorize/oauth", bytes.NewReader(bodyJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth failed: status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Expires      int    `json:"expires"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	c.accessToken = result.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(result.Expires) * time.Second)
	if result.RefreshToken != "" {
		c.refreshTok = result.RefreshToken
	}

	return c.accessToken, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/Erik/projects/cipherflag && go test ./internal/export/venafi/ -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/export/venafi/client.go internal/export/venafi/client_test.go
git commit -m "feat: add Venafi TPP REST API client with OAuth2 token refresh"
```

---

### Task 13: Export and PCAP API Handlers

**Files:**
- Create: `internal/api/handler/export.go`
- Create: `internal/api/handler/pcap.go`
- Modify: `internal/api/server.go`

- [ ] **Step 1: Implement export handler**

Create `internal/api/handler/export.go`:

```go
package handler

import (
	"net/http"

	"github.com/cyberflag-ai/cipherflag/internal/export"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type ExportHandler struct {
	store store.CertStore
}

func NewExportHandler(st store.CertStore) *ExportHandler {
	return &ExportHandler{store: st}
}

func (h *ExportHandler) ExportCertificates(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// Use search to get filtered certificates
	// Note: SearchCertificates caps PageSize at 500. For export, we paginate
	// through all results by looping until we've fetched everything.
	q := store.CertSearchQuery{
		Search:   r.URL.Query().Get("search"),
		Grade:    r.URL.Query().Get("grade"),
		Source:   r.URL.Query().Get("source"),
		PageSize: 500,
		Page:     1,
	}

	var allCerts []model.Certificate
	for {
		result, err := h.store.SearchCertificates(r.Context(), q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		allCerts = append(allCerts, result.Certificates...)
		if len(allCerts) >= result.Total {
			break
		}
		q.Page++
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to pointer slice
	certs := make([]*model.Certificate, len(allCerts))
	for i := range allCerts {
		certs[i] = &allCerts[i]
	}

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=cipherflag-certificates.csv")
		export.WriteCSV(w, certs)
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=cipherflag-certificates.json")
		export.WriteJSON(w, certs)
	default:
		http.Error(w, "format must be csv or json", http.StatusBadRequest)
	}
}
```

Add the missing import for model:

```go
import "github.com/cyberflag-ai/cipherflag/internal/model"
```

- [ ] **Step 2: Implement PCAP handler**

Create `internal/api/handler/pcap.go`:

```go
package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"

	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type PCAPHandler struct {
	store    store.CertStore
	inputDir string
	maxSize  int64
}

func NewPCAPHandler(st store.CertStore, inputDir string, maxSizeMB int) *PCAPHandler {
	return &PCAPHandler{
		store:    st,
		inputDir: inputDir,
		maxSize:  int64(maxSizeMB) * 1024 * 1024,
	}
}

func (h *PCAPHandler) Upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, h.maxSize)

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "failed to read file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create job
	job := &model.PCAPJob{
		Filename: header.Filename,
		FileSize: header.Size,
		Status:   "queued",
	}
	if err := h.store.CreatePCAPJob(r.Context(), job); err != nil {
		http.Error(w, "failed to create job: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write file to input directory using job ID as subdirectory
	jobDir := filepath.Join(h.inputDir, job.ID)
	os.MkdirAll(jobDir, 0755)
	destPath := filepath.Join(jobDir, header.Filename)

	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "failed to save file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		http.Error(w, "failed to write file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(job)
}

func (h *PCAPHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, err := h.store.GetPCAPJob(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if job == nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

func (h *PCAPHandler) ListJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := h.store.ListPCAPJobs(r.Context(), 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
}
```

- [ ] **Step 3: Register new routes in server.go**

In `internal/api/server.go`, add the export and PCAP handlers. Update `NewRouter` to accept config for PCAP settings:

```go
func NewRouter(st store.CertStore, frontendURL string, pcapInputDir string, pcapMaxSizeMB int) http.Handler {
	// ... existing setup ...

	exportH := handler.NewExportHandler(st)
	pcapH := handler.NewPCAPHandler(st, pcapInputDir, pcapMaxSizeMB)

	r.Route("/api/v1", func(r chi.Router) {
		// ... existing routes ...

		// Export
		r.Get("/export/certificates", exportH.ExportCertificates)

		// PCAP
		r.Post("/pcap/upload", pcapH.Upload)
		r.Get("/pcap/jobs/{id}", pcapH.GetJob)
		r.Get("/pcap/jobs", pcapH.ListJobs)
	})
	// ...
}
```

- [ ] **Step 4: Update main.go to pass new router parameters**

In `cmd/cipherflag/main.go`, update the `NewRouter` call:

```go
router := api.NewRouter(st, cfg.Server.FrontendURL, cfg.PCAP.InputDir, cfg.PCAP.MaxFileSizeMB)
```

- [ ] **Step 5: Verify build compiles**

Run: `cd /Users/Erik/projects/cipherflag && go build ./...`
Expected: Success

- [ ] **Step 6: Commit**

```bash
git add internal/api/handler/export.go internal/api/handler/pcap.go \
  internal/api/server.go cmd/cipherflag/main.go
git commit -m "feat: add export and PCAP upload API handlers and routes"
```

---

## Chunk 5: Frontend — Upload Page and Export Button

### Task 14: Add Export and PCAP API Functions to Frontend Client

**Files:**
- Modify: `frontend/src/lib/api.ts`

- [ ] **Step 1: Add TypeScript types and API functions**

Append to `frontend/src/lib/api.ts`:

```typescript
export interface PCAPJob {
	id: string;
	filename: string;
	file_size: number;
	status: 'queued' | 'processing' | 'complete' | 'failed';
	certs_found: number;
	certs_new: number;
	error?: string;
	created_at: string;
	completed_at?: string;
}

// Add to the api object:
// uploadPCAP: (file: File) => { ... }
// getPCAPJob: (id: string) => fetchJSON<PCAPJob>(`/pcap/jobs/${id}`)
// listPCAPJobs: () => fetchJSON<{ jobs: PCAPJob[] }>('/pcap/jobs')
// exportCerts: (format: 'csv' | 'json', params?: string) => window.open(`${BASE}/export/certificates?format=${format}&${params || ''}`)
```

Add these methods to the `api` object:

```typescript
export const api = {
	// ... existing methods ...
	getPCAPJob: (id: string) => fetchJSON<PCAPJob>(`/pcap/jobs/${id}`),
	listPCAPJobs: () => fetchJSON<{ jobs: PCAPJob[] }>('/pcap/jobs'),
	uploadPCAP: async (file: File): Promise<PCAPJob> => {
		const formData = new FormData();
		formData.append('file', file);
		const res = await fetch(`${BASE}/pcap/upload`, { method: 'POST', body: formData });
		if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
		return res.json();
	},
	exportCerts: (format: 'csv' | 'json', params?: string) => {
		window.open(`${BASE}/export/certificates?format=${format}${params ? '&' + params : ''}`);
	},
};
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/lib/api.ts
git commit -m "feat: add PCAP and export API client functions to frontend"
```

---

### Task 15: PCAP Upload Page

**Files:**
- Create: `frontend/src/routes/upload/+page.svelte`

- [ ] **Step 1: Create the upload page**

Create `frontend/src/routes/upload/+page.svelte` with:
- Drag-and-drop zone with file picker fallback
- File size validation (client-side)
- Upload progress state machine: idle → uploading → polling → complete/failed
- Job status polling via `api.getPCAPJob` every 2 seconds while status is `queued` or `processing`
- Results summary showing certs_found, certs_new
- Link to certificates page filtered by the upload
- Recent jobs list from `api.listPCAPJobs`

Use Svelte 5 runes (`$state`, `$effect`) for reactive state, consistent with the existing frontend.

- [ ] **Step 2: Verify frontend builds**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npm run build`
Expected: Success

- [ ] **Step 3: Commit**

```bash
git add frontend/src/routes/upload/+page.svelte
git commit -m "feat: add PCAP upload page with drag-and-drop and job tracking"
```

---

### Task 16: Add Export Button to Certificates Page

**Files:**
- Modify: `frontend/src/routes/certificates/+page.svelte`

- [ ] **Step 1: Add export dropdown button**

In the certificates page, add an "Export" button near the existing filter controls. The button should offer CSV and JSON download options. Use `api.exportCerts()` which opens the download URL in a new tab. Pass the current search/filter parameters so the export matches what the user sees.

- [ ] **Step 2: Verify frontend builds**

Run: `cd /Users/Erik/projects/cipherflag/frontend && npm run build`
Expected: Success

- [ ] **Step 3: Commit**

```bash
git add frontend/src/routes/certificates/+page.svelte
git commit -m "feat: add export button to certificates page"
```

---

## Chunk 6: Docker Containerization

### Task 17: CipherFlag Dockerfile (Multi-Stage Build)

**Files:**
- Create: `Dockerfile`

- [ ] **Step 1: Write the Dockerfile**

Create `Dockerfile`:

```dockerfile
# ── Stage 1: Build Go binary ──
FROM golang:1.24-alpine AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o cipherflag ./cmd/cipherflag/

# ── Stage 2: Build frontend ──
FROM node:22-alpine AS frontend-builder
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# ── Stage 3: Runtime ──
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

COPY --from=go-builder /build/cipherflag .
COPY --from=frontend-builder /build/build ./frontend/build
COPY config/cipherflag.toml ./config/

EXPOSE 8443

ENTRYPOINT ["./cipherflag"]
CMD ["serve"]
```

- [ ] **Step 2: Verify Docker build succeeds**

Run: `cd /Users/Erik/projects/cipherflag && docker build -t cipherflag:dev .`
Expected: Success

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "feat: add multi-stage Dockerfile for CipherFlag"
```

---

### Task 18: Zeek Sensor Container

**Files:**
- Create: `docker/zeek/Dockerfile`
- Create: `docker/zeek/local.zeek`
- Create: `docker/zeek/entrypoint.sh`

- [ ] **Step 1: Create Zeek policy config**

Create `docker/zeek/local.zeek`:

```zeek
# CipherFlag Zeek configuration
@load policy/tuning/json-logs
@load policy/protocols/ssl/extract-certs-pem

# Log rotation every hour
redef Log::default_rotation_interval = 1 hr;

# Ensure we capture full certificate chains
redef SSL::extract_certs_pem = ALL_HOSTS;
```

- [ ] **Step 2: Create Zeek entrypoint script**

Create `docker/zeek/entrypoint.sh`:

```bash
#!/bin/sh
set -e

LOG_DIR="${ZEEK_LOG_DIR:-/zeek-logs}"
PCAP_DIR="${PCAP_INPUT_DIR:-/pcap-input}"
INTERFACE="${NETWORK_INTERFACE:-}"

mkdir -p "$LOG_DIR" "$PCAP_DIR"

# Background PCAP watcher
pcap_watcher() {
    echo "PCAP watcher: monitoring $PCAP_DIR"
    while true; do
        for pcap in "$PCAP_DIR"/*/*.pcap "$PCAP_DIR"/*/*.pcapng; do
            [ -f "$pcap" ] || continue

            # Extract job ID from parent directory name
            job_dir=$(dirname "$pcap")
            job_id=$(basename "$job_dir")
            out_dir="$LOG_DIR/$job_id"
            done_marker="$out_dir/.done"

            [ -f "$done_marker" ] && continue

            echo "Processing PCAP: $pcap (job: $job_id)"
            mkdir -p "$out_dir"
            cd "$out_dir"
            zeek -r "$pcap" /usr/local/zeek/share/zeek/site/local.zeek 2>&1 || true
            touch "$done_marker"
            echo "Completed PCAP: $pcap"
            cd /
        done
        sleep 5
    done
}

# Start PCAP watcher in background
pcap_watcher &

# Start live capture if interface is set
if [ -n "$INTERFACE" ]; then
    echo "Starting live capture on interface: $INTERFACE"
    cd "$LOG_DIR"
    exec zeek -i "$INTERFACE" /usr/local/zeek/share/zeek/site/local.zeek
else
    echo "No NETWORK_INTERFACE set, running in PCAP-only mode"
    # Keep container alive for PCAP processing
    wait
fi
```

- [ ] **Step 3: Create Zeek Dockerfile**

Create `docker/zeek/Dockerfile`:

```dockerfile
FROM zeek/zeek:latest

COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/zeek-logs", "/pcap-input"]

ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 4: Commit**

```bash
chmod +x docker/zeek/entrypoint.sh
git add docker/zeek/
git commit -m "feat: add Zeek sensor container with live capture and PCAP processing"
```

---

### Task 19: Docker Compose Orchestration

**Files:**
- Create: `docker-compose.yml`
- Create: `.env.example`

- [ ] **Step 1: Create docker-compose.yml**

Create `docker-compose.yml`:

```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: cipherflag
      POSTGRES_USER: cipherflag
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
    volumes:
      - pg-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cipherflag"]
      interval: 5s
      timeout: 5s
      retries: 5

  zeek:
    build:
      context: ./docker/zeek
    environment:
      NETWORK_INTERFACE: ${NETWORK_INTERFACE:-}
      ZEEK_LOG_DIR: /zeek-logs
      PCAP_INPUT_DIR: /pcap-input
    volumes:
      - zeek-logs:/zeek-logs
      - pcap-input:/pcap-input
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN

  cipherflag:
    build:
      context: .
    environment:
      CIPHERFLAG_CONFIG: /app/config/cipherflag.toml
    ports:
      - "8443:8443"
    volumes:
      - zeek-logs:/zeek-logs:ro
      - pcap-input:/pcap-input
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  pg-data:
  zeek-logs:
  pcap-input:
```

Note: The cipherflag.toml inside the container needs to use `postgres` as the hostname. This should be handled via environment variable override or a Docker-specific config. Add an environment variable to override the postgres URL:

```yaml
  cipherflag:
    environment:
      CIPHERFLAG_CONFIG: /app/config/cipherflag.toml
    # The config file will need to use postgres://cipherflag:${POSTGRES_PASSWORD}@postgres:5432/cipherflag
```

The implementer should update the config loader to support environment variable overrides (e.g., `CIPHERFLAG_POSTGRES_URL` overrides `storage.postgres_url`).

- [ ] **Step 2: Create .env.example**

Create `.env.example`:

```bash
# CipherFlag Environment Configuration

# Network interface for live packet capture (e.g., eth0, en0)
# Leave empty for PCAP-only mode
NETWORK_INTERFACE=

# PostgreSQL password
POSTGRES_PASSWORD=changeme

# Venafi TPP Integration (disabled by default)
VENAFI_ENABLED=false
VENAFI_BASE_URL=
VENAFI_CLIENT_ID=
VENAFI_REFRESH_TOKEN=
VENAFI_FOLDER=\VED\Policy\Discovered\CipherFlag
```

- [ ] **Step 3: Verify compose config is valid**

Run: `cd /Users/Erik/projects/cipherflag && docker compose config`
Expected: Valid YAML output, no errors

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml .env.example
git commit -m "feat: add Docker Compose orchestration with 3 services"
```

---

## Chunk 7: Open-Source Packaging

### Task 20: Apache 2.0 License

**Files:**
- Create: `LICENSE`

- [ ] **Step 1: Create LICENSE file**

Write the full Apache License 2.0 text to `LICENSE` with copyright: `Copyright 2026 CipherFlag Contributors`

- [ ] **Step 2: Commit**

```bash
git add LICENSE
git commit -m "chore: add Apache 2.0 license"
```

---

### Task 21: README and Documentation

**Files:**
- Modify: `README.md`
- Create: `CONTRIBUTING.md`
- Create: `docs/quickstart.md`
- Create: `docs/configuration.md`
- Create: `docs/venafi-export.md`
- Create: `docs/architecture.md`

- [ ] **Step 1: Rewrite README.md**

Rewrite `README.md` for open-source audience with:
- One-paragraph description
- Quick-start (3 commands)
- Feature list
- Screenshots placeholder section
- Configuration overview (link to docs/)
- Contributing (link to CONTRIBUTING.md)
- License badge

- [ ] **Step 2: Create CONTRIBUTING.md**

Write development setup instructions:
- Prerequisites (Go 1.24+, Node 22+, PostgreSQL 15+)
- Local development without Docker
- Code structure overview
- PR process, commit conventions

- [ ] **Step 3: Create docs/quickstart.md**

Write 5-minute guide covering:
- Prerequisites (Docker, Docker Compose)
- Clone, configure .env, docker-compose up
- Open browser, verify dashboard
- Upload a PCAP for testing
- Configure Venafi export (optional)

- [ ] **Step 4: Create docs/configuration.md**

Document all configuration options from `cipherflag.toml` and `.env.example`.

- [ ] **Step 5: Create docs/venafi-export.md**

Write Venafi integration guide:
- How to get TPP API credentials
- Configure CipherFlag for push
- CSV/JSON manual export workflow
- Troubleshooting

- [ ] **Step 6: Create docs/architecture.md**

Write design overview for contributors covering the container topology, ingestion pipeline, health scoring, and data model.

- [ ] **Step 7: Commit all docs**

```bash
git add README.md CONTRIBUTING.md docs/
git commit -m "docs: add open-source documentation suite"
```

---

### Task 22: Add .gitignore and Clean Up

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Update .gitignore**

Ensure `.gitignore` includes:

```
bin/
*.exe
node_modules/
frontend/build/
frontend/.svelte-kit/
.env
*.pcap
*.pcapng
```

- [ ] **Step 2: Commit**

```bash
git add .gitignore
git commit -m "chore: update .gitignore for open-source release"
```

---

## Dependency Graph

```
Task 1 (migrations) ──┬── Task 3 (raw_pem + batch) ── Task 5 (pcap store)
                       │                                    │
Task 2 (model) ────────┘                                    │
                                                            ├── Task 9 (poller) ── Task 10 (wire poller) ── Task 10a (pcap lifecycle)
Task 4 (config) ────────────────────────────────────────────┘        │
                                                                     │
                            Task 6 (parser + conn.log) ── Task 7 (mapper) ──┘
                            Task 8 (certparse) ─────────────────────────────┘

Task 4 (config) ── Task 13 (handlers) ── Task 14 (frontend api) ── Task 15 (upload page)
                        │                                            └── Task 16 (export button)
Task 11 (csv/json) ────┘
Task 12 (venafi) ───────┘

Task 17 (cipherflag dockerfile) ──┐
Task 18 (zeek container) ────────┼── Task 19 (docker compose)
                                  │
Task 20 (license) ── Task 21 (docs) ── Task 22 (gitignore)
```

**Parallelizable groups:**
- Tasks 1-5 (prerequisites) are sequential
- Task 4 (config) is a prerequisite for Tasks 10, 10a, and 13
- Tasks 6-8 (parsing) can run in parallel after Task 2
- Task 10a (pcap lifecycle) depends on Tasks 9 and 5
- Tasks 11-12 (export) can run in parallel with Tasks 6-10 (ingestion)
- Tasks 17-18 (dockerfiles) can run in parallel
- Tasks 20-22 (packaging) can run in parallel with everything else

## Notes for Implementers

- **Frontend nav:** When creating Task 15 (upload page), also add an "Upload" link to the navigation in `frontend/src/routes/+layout.svelte`.
- **Venafi push scheduler:** Task 12 implements only the Venafi API client. A background goroutine that periodically calls `ImportCertificate` for new/updated certificates should be added in Task 10 (wire poller) alongside the poller startup, using `cfg.Export.Venafi.PushIntervalMinutes`. Only start if `cfg.Export.Venafi.Enabled` is true.
- **Zeek JSON metadata lines:** Zeek JSON logs may include metadata records like `{"_path":"x509",...}`. The parser skips unparseable lines with a warning, which is acceptable behavior.
