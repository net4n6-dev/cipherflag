# CE Schema/Code Parity (2.2.4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a database built purely from CE's embedded migrations support every CE code path, get `go test -tags integration ./internal/...` green, and add a CI job that keeps it green.

**Architecture:** One additive, idempotent migration (`v2.2.4_schema_parity.sql`) adds what CE code needs (`hosts` columns, `risk_score`/`risk_factors`, `added_*` renames, `ad_cs_events`). The EE-only references CE still carries (`protocol_endpoints` query legs, dead posture-snapshot code) are deleted instead of given stub tables. The existing red integration tests are the RED for most fixes; two new store tests guard the migration and the query set.

**Tech Stack:** Go 1.25.6, PostgreSQL 15 (embedded SQL migrations run by `PostgresStore.Migrate`), pgx v5, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-25-ce-schema-code-parity-design.md` (read it first; this plan implements it).

## Global Constraints

- Go 1.25.6. Migrations are plain `.sql` files in `internal/store/migrations/`, applied in lexicographic filename order, each executed as one multi-statement `Exec` (one implicit transaction) and recorded in `schema_migrations` afterwards. Never edit an already-released migration (`v2.0_baseline.sql`, `v2.1.0_venafi_push.sql`, `v2.2.0_sse_event_triggers.sql`); `v2.2.4_schema_parity.sql` is new and unreleased, so it may be edited during this plan.
- Every statement in the new migration must be idempotent (`IF NOT EXISTS`, guarded renames): it can re-run if the recording insert fails.
- Schema-sensitive tests are integration-tagged (`//go:build integration`, header line 1, then a blank line, then the licence header) and need the database: `export CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable"` (container `cipherflag-test-db`, port 5434; `docker start cipherflag-test-db` if stopped). Per-package schemas are dropped and rebuilt by `testdb.Acquire`, so runs are isolated.
- A plain `go test ./...` does NOT run integration tests. Every task's verification names both commands where relevant.
- No EE-only table may be added to CE's schema.
- Every new `.go` file starts with the Apache-2.0 header used by neighbouring files (copy lines from an existing file; integration-tagged files put `//go:build integration` first).
- Commit rules: commit steps run only after Erik has approved this plan (asked at handoff); the commit hook rejects a `Co-Authored-By` trailer, so never add one; stage only the files a task names; conventional-commit subjects. Tag and push are NEVER part of this plan without a separate explicit go. Never `rm`; use `git rm` only where a step says so (the spec authorises exactly one deletion, Task 3).
- At most 5 files touched per task (`docs/CLAUDE.md`). After editing Go files run `gofmt -l <files>` and fix output.
- Work on branch `fix/ce-schema-parity` (already checked out; the spec is committed on it).
- Red baseline for reference: `.superpowers/sdd/2026-09-25-cbom-export-completion/t0-fullsuite.txt` (11 failing packages, 47 ok; produced from the unmodified tree).

## Review Focus

Failure modes the spec implies that a straightforward implementation would miss; each has a test in the named task.

1. Upgrading a database that already holds rows (hosts, application metadata, declared CAs written by 2.2.3): the migration must keep them, default the new columns, and carry values through the renames (Task 1).
2. Re-running the migration file, or `Migrate` twice, must not error (Task 1).
3. A weak-algorithms request naming the removed `protocol_endpoint` asset type must be harmless, not a SQL error (Task 2).
4. Application list/detail/deadline queries and the application-scope CBOM query must run on a database with no `protocol_endpoints` table (Task 2).
5. Drift beyond the eight gap types already known (for example trigger functions referencing missing columns): classified and either fixed under the spec or reported, never absorbed silently (Task 4).

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `internal/store/migrations/v2.2.4_schema_parity.sql` (new) | additive, idempotent schema parity migration | 1, 4 |
| `internal/store/schema_parity_integration_test.go` (new) | columns/tables exist; idempotence; upgrade keeps rows | 1, 4 |
| `internal/store/applications.go` | drop `protocol_endpoints` legs; drop posture-snapshot code | 2, 3 |
| `internal/store/cbom_store.go` | drop `protocol_endpoints` leg from `ListApplicationScopeAssets` | 2 |
| `internal/store/weak_algorithms.go` | drop the protocol-endpoint scan | 2 |
| `internal/store/weak_algorithms_integration_test.go` | drop the protocol-endpoint seed and assertions | 2 |
| `internal/store/query_smoke_integration_test.go` (new) | CE queries run without schema-drift errors | 2 |
| `internal/store/applications_prune_integration_test.go` | deleted with the dead code it tests | 3 |
| `.github/workflows/ci.yml` | integration job | 5 |
| `CHANGELOG.md`, `cmd/cipherflag/main.go`, spec | release | 6 |

---

### Task 0: Preconditions

No code changes; no commit.

- [ ] **Step 1: Confirm branch, clean tree, and database**

```bash
git branch --show-current
git status --short
docker start cipherflag-test-db >/dev/null 2>&1; sleep 3
docker exec cipherflag-test-db psql -U cipherflag -d cipherflag_test -tAc "select 1"
```

Expected: `fix/ce-schema-parity`; status shows only the untracked `docs/CLAUDE.md`, the Layer 0 spec/plan files and this plan (nothing modified); `1`.

- [ ] **Step 2: Create the workspace file for this plan's ledger** — run `/Users/Erik/.claude/plugins/cache/claude-plugins-official/superpowers/6.4.1/skills/subagent-driven-development/scripts/sdd-workspace docs/superpowers/plans/2026-09-25-ce-schema-code-parity.md` and keep the printed directory for run logs (`t4-run-N.txt` files go there).

---

### Task 1: The parity migration, with guard tests

**Files:**
- Create: `internal/store/migrations/v2.2.4_schema_parity.sql`
- Create: `internal/store/schema_parity_integration_test.go`

**Interfaces:**
- Consumes: `testStore(t)` (`internal/store/testhelper_test.go`), `st.pool`, `migrationsFS`, `st.Migrate`.
- Produces: the migration file name `v2.2.4_schema_parity.sql` (Tasks 4 and 6 extend or reference it) and the test file (Task 4 extends its `want` list).

- [ ] **Step 1: Write the failing tests** — create `internal/store/schema_parity_integration_test.go`:

```go
//go:build integration

// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"context"
	"io/fs"
	"testing"
)

const parityMigration = "migrations/v2.2.4_schema_parity.sql"

func columnCount(t *testing.T, st *PostgresStore, table, column string) int {
	t.Helper()
	var n int
	err := st.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
	`, table, column).Scan(&n)
	if err != nil {
		t.Fatalf("column lookup %s.%s: %v", table, column, err)
	}
	return n
}

// The store code reads and writes these; CE's migrations must create them.
func TestSchemaParity_ColumnsAndTablesExist(t *testing.T) {
	st := testStore(t)

	want := []struct{ table, column string }{
		{"hosts", "aliases"},
		{"hosts", "discovery_sources"},
		{"asset_health_reports", "risk_score"},
		{"asset_health_reports", "risk_factors"},
		{"operator_declared_cas", "added_at"},
		{"operator_declared_cas", "added_by"},
		{"application_metadata", "added_at"},
		{"application_metadata", "added_by"},
		{"ad_cs_events", "id"},
		{"ad_cs_events", "raw_event"},
	}
	for _, w := range want {
		if columnCount(t, st, w.table, w.column) != 1 {
			t.Errorf("%s.%s is missing from the migrated schema", w.table, w.column)
		}
	}

	// The baseline's old names must be gone after the rename.
	for _, old := range []struct{ table, column string }{
		{"operator_declared_cas", "declared_at"},
		{"operator_declared_cas", "declared_by"},
		{"application_metadata", "declared_at"},
		{"application_metadata", "declared_by"},
	} {
		if columnCount(t, st, old.table, old.column) != 0 {
			t.Errorf("%s.%s should have been renamed to added_*", old.table, old.column)
		}
	}
}

// The runner can re-run a file if recording it fails, so the whole migration
// must be idempotent, and Migrate itself must be a no-op the second time.
func TestSchemaParity_MigrationIsIdempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	sql, err := fs.ReadFile(migrationsFS, parityMigration)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := st.pool.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("re-running the migration file failed: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate failed: %v", err)
	}
}

// An existing 2.2.3 database has rows and the old column names. Rewind the
// schema to that shape, insert rows, upgrade, and check nothing was lost.
func TestSchemaParity_UpgradeKeepsExistingRows(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	sql, err := fs.ReadFile(migrationsFS, parityMigration)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	// Whatever happens, leave the shared per-package schema fully migrated.
	t.Cleanup(func() { _, _ = st.pool.Exec(context.Background(), string(sql)) })

	rewind := `
		ALTER TABLE hosts DROP COLUMN aliases, DROP COLUMN discovery_sources;
		ALTER TABLE asset_health_reports DROP COLUMN risk_score, DROP COLUMN risk_factors;
		ALTER TABLE operator_declared_cas RENAME COLUMN added_at TO declared_at;
		ALTER TABLE operator_declared_cas RENAME COLUMN added_by TO declared_by;
		ALTER TABLE application_metadata RENAME COLUMN added_at TO declared_at;
		ALTER TABLE application_metadata RENAME COLUMN added_by TO declared_by;
		DROP TABLE ad_cs_events;
	`
	if _, err := st.pool.Exec(ctx, rewind); err != nil {
		t.Fatalf("rewind to the 2.2.3 shape: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `
		INSERT INTO hosts (canonical_hostname) VALUES ('legacy-host');
		INSERT INTO application_metadata (tag, note) VALUES ('legacy-app', 'kept');
		INSERT INTO operator_declared_cas (fingerprint_sha256, subject_cn) VALUES ('fp-legacy', 'CN=Legacy');
	`); err != nil {
		t.Fatalf("seed legacy rows: %v", err)
	}

	if _, err := st.pool.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("upgrade: %v", err)
	}

	var aliases string
	if err := st.pool.QueryRow(ctx,
		`SELECT aliases::text FROM hosts WHERE canonical_hostname = 'legacy-host'`).Scan(&aliases); err != nil {
		t.Fatalf("legacy host lost: %v", err)
	}
	if aliases != "[]" {
		t.Errorf("legacy host aliases = %q, want the default []", aliases)
	}

	var note string
	var stamped bool
	if err := st.pool.QueryRow(ctx,
		`SELECT note, added_at IS NOT NULL FROM application_metadata WHERE tag = 'legacy-app'`).Scan(&note, &stamped); err != nil {
		t.Fatalf("legacy application_metadata row lost: %v", err)
	}
	if note != "kept" || !stamped {
		t.Errorf("legacy application_metadata = (%q, added_at set=%v)", note, stamped)
	}

	var subject string
	if err := st.pool.QueryRow(ctx,
		`SELECT subject_cn FROM operator_declared_cas WHERE fingerprint_sha256 = 'fp-legacy' AND added_at IS NOT NULL`).Scan(&subject); err != nil {
		t.Fatalf("legacy operator_declared_cas row lost or lost its timestamp: %v", err)
	}
	if subject != "CN=Legacy" {
		t.Errorf("legacy CA subject = %q", subject)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
export CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable"
go test -tags integration ./internal/store/ -run 'TestSchemaParity' -count=1 2>&1 | tail -30
```

Expected: `ColumnsAndTablesExist` FAILS listing `hosts.aliases`, `asset_health_reports.risk_score`, `operator_declared_cas.added_at`, `ad_cs_events.id`… as missing; `MigrationIsIdempotent` and `UpgradeKeepsExistingRows` FAIL with `read migration: open migrations/v2.2.4_schema_parity.sql: file does not exist`.

- [ ] **Step 3: Write the migration** — create `internal/store/migrations/v2.2.4_schema_parity.sql`:

```sql
-- v2.2.4_schema_parity.sql
--
-- Brings the CE schema in line with what the CE store code reads and writes.
-- The v2.0 baseline was cut from EE's migrations per the port triage, but the
-- ported Go code was not stripped to match and a few CE-bound columns were
-- dropped. See docs/superpowers/specs/2026-09-25-ce-schema-code-parity-design.md.
--
-- Additive and idempotent: safe on fresh installs and on existing 2.x
-- databases, and safe to re-run if the runner fails to record it.

-- hosts: written by UpsertHost (baseline omitted these two columns).
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS aliases           JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS discovery_sources JSONB NOT NULL DEFAULT '[]';

-- asset_health_reports: read and written by SaveAssetHealthReport and every
-- CBOM query. The EE risk engine is EE-only, so CE leaves these at their
-- defaults and adds no risk-score index.
ALTER TABLE asset_health_reports
    ADD COLUMN IF NOT EXISTS risk_score   INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS risk_factors JSONB   NOT NULL DEFAULT '{}';

-- operator_declared_cas / application_metadata: the baseline named these
-- declared_by / declared_at; the store code, the JSON API and EE use added_*.
-- Renames carry existing rows and are guarded so a re-run is a no-op.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'operator_declared_cas' AND column_name = 'declared_at') THEN
        ALTER TABLE operator_declared_cas RENAME COLUMN declared_at TO added_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'operator_declared_cas' AND column_name = 'declared_by') THEN
        ALTER TABLE operator_declared_cas RENAME COLUMN declared_by TO added_by;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'application_metadata' AND column_name = 'declared_at') THEN
        ALTER TABLE application_metadata RENAME COLUMN declared_at TO added_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'application_metadata' AND column_name = 'declared_by') THEN
        ALTER TABLE application_metadata RENAME COLUMN declared_by TO added_by;
    END IF;
END
$$;

-- ad_cs_events: written by the Netwrix connector, which ships in CE.
-- Definition copied unchanged from EE migration 007_ad_cs_events.sql.
CREATE TABLE IF NOT EXISTS ad_cs_events (
    id              UUID PRIMARY KEY,

    event_type      TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    ca_name         TEXT NOT NULL,
    template_name   TEXT,
    requested_by    TEXT,

    serial_number   TEXT NOT NULL,
    issuer_dn       TEXT NOT NULL,
    subject_dn      TEXT,

    source          TEXT NOT NULL DEFAULT 'netwrix',
    raw_event       JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ad_cs_events_event_timestamp ON ad_cs_events (event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ad_cs_events_ca_name ON ad_cs_events (ca_name);
CREATE INDEX IF NOT EXISTS idx_ad_cs_events_event_type ON ad_cs_events (event_type);
CREATE INDEX IF NOT EXISTS idx_ad_cs_events_serial_issuer ON ad_cs_events (serial_number, issuer_dn);
```

- [ ] **Step 4: Run to verify they pass**

```bash
gofmt -l internal/store/schema_parity_integration_test.go
go vet -tags integration ./internal/store/
go test -tags integration ./internal/store/ -run 'TestSchemaParity' -count=1 -v 2>&1 | grep -E '^(=== RUN|--- |PASS|FAIL|ok)'
```

Expected: three `--- PASS`. If `UpgradeKeepsExistingRows` fails on the rewind statement, read the error: it means an object depends on a rewound column, which is itself drift to classify (Task 4 rules); do not weaken the test.

- [ ] **Step 5: Confirm nothing else regressed in this package's non-integration tests**

Run: `go build ./... && go test ./internal/store/ -count=1`
Expected: `ok`.

- [ ] **Step 6: Commit** (per the Global Constraints commit rule)

```bash
git add internal/store/migrations/v2.2.4_schema_parity.sql internal/store/schema_parity_integration_test.go
git commit -m "fix(store): add v2.2.4 schema parity migration for columns CE code already uses"
```

---

### Task 2: Strip the `protocol_endpoints` legs

**Files:**
- Modify: `internal/store/applications.go` (lines ~166, ~297, ~365)
- Modify: `internal/store/cbom_store.go` (line ~269)
- Modify: `internal/store/weak_algorithms.go` (call site ~lines 135-141; function `scanProtocolEndpointsForWeakAlgo` ~334-end of function)
- Modify: `internal/store/weak_algorithms_integration_test.go`
- Create: `internal/store/query_smoke_integration_test.go`

**Interfaces:**
- Consumes: Task 1's migrated schema (so the only remaining "does not exist" is `protocol_endpoints`); `testStore`.
- Produces: `noSchemaDrift(t, what, err)` helper (reused in Task 4).

- [ ] **Step 1: Write the failing smoke test** — create `internal/store/query_smoke_integration_test.go` (integration tag and licence header as in Task 1, then):

```go
package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// noSchemaDrift fails the test if err is a "does not exist" SQL error: the query
// references a table or column the CE migrations do not create.
func noSchemaDrift(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "does not exist") {
		t.Errorf("%s: schema drift: %v", what, err)
	}
}

// Runs the CE queries that touch the objects this release reconciles, against an
// empty migrated schema. Only the absence of drift errors is asserted.
func TestQuerySmoke_NoSchemaDrift(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	_, err := st.ListApplications(ctx, nil)
	noSchemaDrift(t, "ListApplications", err)

	_, err = st.tagsWithDeadlineBefore(ctx, time.Now())
	noSchemaDrift(t, "tagsWithDeadlineBefore", err)

	_, err = st.GetApplication(ctx, "no-such-app")
	noSchemaDrift(t, "GetApplication", err)

	_, err = st.ListApplicationScopeAssets(ctx, "no-such-app")
	noSchemaDrift(t, "ListApplicationScopeAssets", err)

	_, err = st.ListAllAssetHealthReports(ctx)
	noSchemaDrift(t, "ListAllAssetHealthReports", err)

	_, err = st.ListScopeAssets(ctx, ScopeAssetQuery{HostIDs: []string{"00000000-0000-0000-0000-000000000001"}})
	noSchemaDrift(t, "ListScopeAssets", err)

	_, err = st.ListWeakAlgorithmOccurrences(ctx, WeakAlgoFilter{})
	noSchemaDrift(t, "ListWeakAlgorithmOccurrences", err)

	// The removed EE-only asset type must be harmless as a filter, not a SQL error.
	_, err = st.ListWeakAlgorithmOccurrences(ctx, WeakAlgoFilter{AssetTypes: []string{"protocol_endpoint"}})
	noSchemaDrift(t, "ListWeakAlgorithmOccurrences(protocol_endpoint filter)", err)
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
gofmt -l internal/store/query_smoke_integration_test.go
go test -tags integration ./internal/store/ -run TestQuerySmoke -count=1 2>&1 | tail -20
```

Expected: FAIL with `schema drift: ... relation "protocol_endpoints" does not exist` for `ListApplications`, `tagsWithDeadlineBefore`, `GetApplication`, `ListApplicationScopeAssets`, and both `ListWeakAlgorithmOccurrences` calls; `ListAllAssetHealthReports` and `ListScopeAssets` must NOT be reported (Task 1 fixed `risk_score`). If they are, Task 1 is incomplete.

- [ ] **Step 3: Remove the application query legs** — in `internal/store/applications.go`:

(a) The following 3-line block occurs twice (in `ListApplications` and `tagsWithDeadlineBefore`); delete both occurrences (use replace-all with an empty replacement, keeping the surrounding `UNION ALL` lines intact by including the leading `UNION ALL` in the match):

```
			UNION ALL
			SELECT unnest(p.application_tags), 'protocol_endpoint', p.id::text
			FROM protocol_endpoints p WHERE array_length(p.application_tags, 1) > 0
```

(b) In `GetApplication`, delete this 2-line block:

```
			UNION ALL
			SELECT 'protocol_endpoint', id::text, server_ip || ':' || server_port::text FROM protocol_endpoints WHERE $1 = ANY(application_tags)
```

(c) In `internal/store/cbom_store.go` (`ListApplicationScopeAssets`), delete:

```
			UNION ALL
			SELECT id::text, 'protocol_endpoint' FROM protocol_endpoints WHERE $1 = ANY(application_tags)
```

In each case leave a one-line SQL comment where the leg was, in the CE-flavor style used elsewhere: `-- CE-flavor: the protocol_endpoint leg is omitted (EE-only, Layer 4.1c).` (put it once above the union in each query, inside the SQL string).

- [ ] **Step 4: Remove the weak-algorithm protocol scan** — in `internal/store/weak_algorithms.go`, delete the whole `if include("protocol_endpoint") { ... }` block:

```go
	if include("protocol_endpoint") {
		if ok, err := s.scanProtocolEndpointsForWeakAlgo(ctx, append1); err != nil {
			return nil, fmt.Errorf("weak-algo protocol_endpoints: %w", err)
		} else if !ok {
			return out, nil
		}
	}
```

and delete the entire function `scanProtocolEndpointsForWeakAlgo` (from its `func` line through its closing brace; it begins around line 334 with `rows, err := s.pool.Query(ctx, ... FROM protocol_endpoints ...`). Add above the remaining scans a comment: `// CE-flavor: no protocol_endpoint scan (EE-only, Layer 4.1c).`

- [ ] **Step 5: Update the existing weak-algorithm integration test** — in `internal/store/weak_algorithms_integration_test.go` make these four edits:

(a) Delete the whole seed block from the comment `// --- Protocol endpoint: SSHv1 + weak KEX + weak cipher.` through the closing brace of the `if err := ... t.Fatalf("seed protocol_endpoint: %v", err)` statement (the `var epID string` line, the `INSERT INTO protocol_endpoints ...` query and its error check).

(b) In the `t.Cleanup`, delete the line `_, _ = st.pool.Exec(ctx, \`DELETE FROM protocol_endpoints WHERE id::text = $1\`, epID)`.

(c) Change `case certFP, certFP2, sshID1, sshID2, epID:` to `case certFP, certFP2, sshID1, sshID2:`.

(d) Delete the assertion block starting at `// Protocol endpoint: sshv1 + weak kex + weak cipher = 3 rows minimum.` through the last `t.Errorf("protocol_endpoint missing weak KEX row")` and its closing brace.

- [ ] **Step 6: Verify**

```bash
gofmt -l internal/store
go build ./... && go vet -tags integration ./internal/store/
go test -tags integration ./internal/store/ -run 'TestQuerySmoke|TestListWeakAlgorithmOccurrences|TestSchemaParity' -count=1 -v 2>&1 | grep -E '^(--- |FAIL|ok|PASS)'
grep -rn "protocol_endpoints" --include='*.go' internal/store | grep -v _test.go
```

Expected: PASS for the three test groups; the final grep prints only comments (no SQL). If `TestListWeakAlgorithmOccurrences_MixedScope` fails for a reason other than the removed endpoint, that is Task 4 material; note it and continue.

- [ ] **Step 7: Commit**

```bash
git add internal/store/applications.go internal/store/cbom_store.go internal/store/weak_algorithms.go \
  internal/store/weak_algorithms_integration_test.go internal/store/query_smoke_integration_test.go
git commit -m "fix(store): drop EE-only protocol_endpoints query legs from CE"
```

---

### Task 3: Delete the dead posture-snapshot code

**Files:**
- Modify: `internal/store/applications.go` (lines 612-~729)
- Delete: `internal/store/applications_prune_integration_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: removal of `ApplicationPostureSnapshot`, `SaveApplicationPostureSnapshot`, `PruneApplicationPostureSnapshotsOlderThan`, `LatestPostureSnapshotAt`, `ListApplicationSnapshots`.

This is a pure deletion of code with no non-test callers; the guard is that the repository still builds and its tests pass, and that nothing references the removed names. (The spec explicitly authorises deleting `applications_prune_integration_test.go`.)

- [ ] **Step 1: Prove there are no callers outside the doomed code**

```bash
grep -rn "ApplicationPostureSnapshot\|LatestPostureSnapshotAt\|ListApplicationSnapshots\|PruneApplicationPostureSnapshotsOlderThan" --include='*.go' . | grep -v "internal/store/applications.go" | grep -v "internal/store/applications_prune_integration_test.go"
```

Expected: no output. If anything prints, stop: the code is not dead; report to Erik.

- [ ] **Step 2: Delete the code** — in `internal/store/applications.go`, delete from the doc comment `// ApplicationPostureSnapshot is one row in the application_posture_snapshots` (line ~612) through the closing brace of `ListApplicationSnapshots`, leaving `sortApplicationsByTotalDesc` and its own doc comment (line ~731) untouched. Remove any import the compiler then reports unused.

- [ ] **Step 3: Delete its test with git**

```bash
git rm internal/store/applications_prune_integration_test.go
```

- [ ] **Step 4: Verify**

```bash
gofmt -l internal/store
go build ./... && go vet ./... && go vet -tags integration ./internal/store/
go test ./internal/store/ -count=1
grep -rn "application_posture_snapshots\|PostureSnapshot" --include='*.go' internal cmd
```

Expected: build and vet clean, `ok`, and the final grep prints nothing.

- [ ] **Step 5: Commit**

```bash
git add internal/store/applications.go
git commit -m "chore(store): remove dead EE-only application posture snapshot code"
```

(`git rm` already staged the test deletion; the commit includes it.)

---

### Task 4: Drive the whole integration suite to green

**Files:**
- Modify (as needed): `internal/store/migrations/v2.2.4_schema_parity.sql`, `internal/store/schema_parity_integration_test.go`, and whichever Go files a same-class mismatch lives in. At most 5 files per commit; commit per fix class.

**Interfaces:**
- Consumes: Tasks 1-3; `noSchemaDrift` (Task 2).
- Produces: `go test -tags integration ./internal/... -count=1` green (or a written classification of every remaining failure).

The red baseline had 11 failing packages, so some remaining failures may be downstream of the gaps already fixed and some may be new drift. This task is a bounded loop; each iteration follows the same rules.

- [ ] **Step 1: Run the whole suite and capture it**

```bash
export CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable"
go test -tags integration ./internal/... -count=1 > <workspace>/t4-run-1.txt 2>&1; echo "exit=$?"
grep -E '^(FAIL|ok)\s' <workspace>/t4-run-1.txt | awk '{print $1, $2}' | sort | uniq -c
grep -E '^FAIL\s' <workspace>/t4-run-1.txt
```

(`<workspace>` is the directory printed in Task 0.) Record the failing packages in the ledger.

- [ ] **Step 2: Classify every failing test** by the first error it prints (read with `grep -B2 -A12 -- '--- FAIL' <file>`):

| Error shape | Class | Action |
|---|---|---|
| `column "X" of relation "Y" does not exist` / `relation "Y" does not exist` | **same-class** | CE-bound object (a CE feature/connector uses it): add it to `v2.2.4_schema_parity.sql` (idempotent), extend the `want` list in `TestSchemaParity_ColumnsAndTablesExist`. EE-only object (Layer 4.1c, risk engine, teams, etc.): delete the CE code that queries it, as in Task 2. If it is genuinely ambiguous which side it is, STOP and ask Erik. |
| `record "new" has no field "X"` or another plpgsql/trigger error | **same-class** | The function body in a shipped migration references a column that does not exist; fix by `CREATE OR REPLACE FUNCTION` in `v2.2.4_schema_parity.sql` (never edit the shipped file). |
| An assertion failure with no SQL error (`want 2, got 0`, a nil host, and so on) | **check first** | Re-run that package after the fixes above; many are downstream of a schema gap. If it still fails, read the test: stale-test-only (fix the test) vs product defect (ledger it and report to Erik in the final message; do not fix). |
| A failure needing a product decision not covered by the spec | **stop** | Ledger it and ask Erik. |

- [ ] **Step 3: Fix one class at a time, TDD.** The failing integration test is the RED; watch it fail (already captured), make the smallest fix, re-run that package (`go test -tags integration ./<pkg> -count=1`), then the whole suite. Commit each fix class separately with a `fix(store):` (or appropriate scope) message naming the objects, staging only the files changed.

- [ ] **Step 4: Repeat Steps 1-3**, writing `t4-run-2.txt`, `t4-run-3.txt`. Stop after run 4 if it is still red and report the classification of everything left.

- [ ] **Step 5: Final confirmation**

```bash
go test -tags integration ./... -count=1 2>&1 | grep -E '^(FAIL|ok)\s' | awk '{print $1}' | sort | uniq -c
go build ./... && go vet ./... && go test ./... -count=1 2>&1 | grep -v "no test files" | grep -vE '^ok\s'; echo "(no lines above = ordinary suite green)"
```

Expected: only `ok` for the integration run (no `FAIL`), and no non-ok lines for the ordinary suite. This includes the CBOM golden tests, which restores the safety net the v2.3 plan needs.

---

### Task 5: CI integration job

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the green suite from Task 4.
- Produces: a required-able `integration` job.

- [ ] **Step 1: Add the job** — append this job under `jobs:` in `.github/workflows/ci.yml` (same indentation as `test:` and `frontend:`):

```yaml
  integration:
    name: Integration Tests
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_USER: cipherflag
          POSTGRES_PASSWORD: changeme
          POSTGRES_DB: cipherflag_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U cipherflag -d cipherflag_test"
          --health-interval 5s
          --health-timeout 5s
          --health-retries 10
    env:
      CIPHERFLAG_TEST_DB: postgres://cipherflag:changeme@localhost:5432/cipherflag_test?sslmode=disable
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Run integration tests
        run: go test -tags integration ./... -count=1
```

- [ ] **Step 2: Validate what can be validated locally** (the workflow itself only runs on GitHub)

```bash
python3 -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/ci.yml')); print(sorted(d['jobs'].keys()))"
grep -n "CIPHERFLAG_TEST_DB" internal/testdb/dsn.go | head -2
```

Expected: `['frontend', 'integration', 'test']`, and `dsn.go` reads `CIPHERFLAG_TEST_DB`. The identical command was run green locally in Task 4 Step 5; if `python3` lacks `yaml`, validate with `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml")'` or re-read the indentation by eye.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run integration tests against a Postgres service"
```

- [ ] **Step 4: Tell Erik** in the final report that the job cannot be proven on GitHub from here (it runs on the first push), and that marking it a required check is a GitHub repository setting for him.

---

### Task 6: Release notes and version

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `cmd/cipherflag/main.go` (`const Version`)
- Modify: `docs/superpowers/specs/2026-09-25-ce-schema-code-parity-design.md` (status line only)

- [ ] **Step 1: Full verification**

```bash
go build ./... && go vet ./...
go test ./... -count=1 2>&1 | grep -v "no test files" | grep -vE '^ok\s'; echo "(no lines above = ordinary suite green)"
CIPHERFLAG_TEST_DB="postgres://cipherflag:changeme@localhost:5434/cipherflag_test?sslmode=disable" \
  go test -tags integration ./... -count=1 2>&1 | grep -E '^FAIL'; echo "(no lines above = integration suite green)"
```

Expected: both echo lines appear with nothing above them. If anything is red, stop; do not write release notes over it.

- [ ] **Step 2: Version and changelog** — set `const Version = "2.2.4"` in `cmd/cipherflag/main.go`, then insert this section at the top of `CHANGELOG.md`, above the current newest entry (2.2.3). Run `date +%F` and put its output where `RELEASE_DATE` appears in the heading (never commit the literal `RELEASE_DATE`):

```markdown
## [2.2.4] - RELEASE_DATE

### Fixed
- **A database built from CE's migrations lacked columns and tables CE's own
  code uses.** The v2.0 baseline was cut from EE's migrations, but the ported
  code was not trimmed to match and a few CE-bound columns were dropped. On a
  fresh database this broke host ingestion (`hosts.aliases`,
  `hosts.discovery_sources`), asset scoring and every CBOM export query
  (`asset_health_reports.risk_score`, `risk_factors`), shadow-CA and
  application-metadata storage (`added_by`/`added_at` were named
  `declared_by`/`declared_at`), and the Netwrix connector (`ad_cs_events`).
  A new migration, `v2.2.4_schema_parity.sql`, adds the missing columns,
  renames the mis-named ones (rows are preserved), and creates
  `ad_cs_events`. It applies automatically at startup, is idempotent, and
  needs no manual step.
- Removed CE code that queried EE-only tables that CE never creates:
  the `protocol_endpoints` legs of the application summary, application
  detail, deadline, weak-algorithm and application-CBOM queries, and the
  unused application-posture-snapshot store functions. These queries failed
  on every CE database.

### Changed
- CI now runs the integration-tagged test suite against a Postgres service,
  so schema drift fails the build.

### Notes
- The `risk_score` and `risk_factors` columns stay at their defaults in CE;
  the risk engine is EE-only.
- If you reinitialised a 2.x database to work around missing tables, no action
  is needed.
```

- [ ] **Step 3: Update the spec status line** — change `Status: design decisions approved in conversation 2026-09-25; awaiting written-spec review.` to `Status: implemented; see docs/superpowers/plans/2026-09-25-ce-schema-code-parity.md.`

- [ ] **Step 4: Verify and commit** (two commits)

```bash
go build ./... && go test ./cmd/... -count=1
git add CHANGELOG.md cmd/cipherflag/main.go
git commit -m "chore(release): bump version to 2.2.4; document schema parity fix"
git add docs/superpowers/specs/2026-09-25-ce-schema-code-parity-design.md docs/superpowers/plans/2026-09-25-ce-schema-code-parity.md
git commit -m "docs: mark schema parity spec implemented; add plan"
```

- [ ] **Step 5: Stop before tag and push.** Report to Erik, and do not proceed further without his explicit go:
  - what shipped in each commit and the final integration and ordinary suite results;
  - every remaining classified failure, if any, and every ledger `Ruling:`;
  - a known follow-up not fixed here: EE's `operator_declared_cas.added_by` foreign key is `ON DELETE SET NULL`, CE's baseline `declared_by` FK has no `ON DELETE` clause, so deleting a user who declared a CA or application metadata may fail with a foreign-key error;
  - the tag/push procedure: `git remote -v` must show `net4n6-dev/cipherflag`, remote `main` must be an ancestor of the branch, then fast-forward `main`, tag `v2.2.4`, and push `main` plus that tag by explicit refspec (as for 2.2.2 and 2.2.3);
  - that after 2.2.4 ships, the CBOM export completion plan resumes at its Task 0 on a branch cut from the updated `main`, and that `docker stop cipherflag-test-db` is available when finished.
