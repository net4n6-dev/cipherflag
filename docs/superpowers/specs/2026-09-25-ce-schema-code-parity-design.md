# CE schema/code parity (2.2.4)

Status: implemented; see docs/superpowers/plans/2026-09-25-ce-schema-code-parity.md.
Target release: **2.2.4** (patch). Blocks: `docs/superpowers/plans/2026-09-25-cbom-export-completion.md`
(v2.3 Spec 1), which resumes at its Task 0 once this ships.

## Problem

CE's schema baseline (`internal/store/migrations/v2.0_baseline.sql`, plus
`v2.1.0`, `v2.2.0`) does not create objects that CE's own store code reads and
writes. The baseline was cut from EE's migrations "per the triage"
(`cipherflag-EE/docs/superpowers/ce-port/triage-migrations.md`): the triage
omitted some EE-only schema, but the ported Go code was not stripped to match,
and one baseline transcription dropped CE-bound columns. CE's CI runs plain
`go test ./...`, which skips the integration-tagged tests, so nothing exercised
the store against a real schema.

**Evidence (2026-09-25).** `go test -tags integration ./internal/...` against a
Postgres schema built by `Migrate`: 11 packages fail, 47 pass; every root cause
is a missing object. Runtime proof: the estate query's column list
(`SELECT ... risk_score ... FROM asset_health_reports`) errors with
`column "risk_score" does not exist` on the migrated schema. Which features are
affected below comes from reading the code paths, not from running each one.

| Missing object | Used by (CE code) | Origin | Decision |
|---|---|---|---|
| `hosts.aliases`, `hosts.discovery_sources` | `UpsertHost` (any host-creating ingest) | baseline omission (triage: 006 "almost all CE-bound") | add columns |
| `asset_health_reports.risk_score`, `.risk_factors` | `SaveAssetHealthReport`, all CBOM export queries | triage: EE-only, code not stripped | add columns |
| `operator_declared_cas` / `application_metadata`: `added_by`, `added_at` | shadow-CA and application-metadata stores | baseline names them `declared_by`/`declared_at`; code and EE use `added_*` | rename columns to `added_*` |
| `ad_cs_events` table | Netwrix connector, wired in `cmd/cipherflag/main.go` | triage: EE-only; owner's 2026-05-31 decision puts documented-API connectors in CE | add table |
| `protocol_endpoints` table | `weak-algorithms` scan, application summaries, application-scope CBOM query | EE-only (Layer 4.1c); code legs left behind | strip the CE code legs |
| `application_posture_snapshots` table | `Save/Prune/Latest/ListApplicationPostureSnapshot*` in `store/applications.go`; no callers outside their own integration test | EE-only (its writer package is EE-only) | delete the dead code |

## Goals

- A database built purely from CE's embedded migrations supports every shipped
  CE code path: host ingest, asset scoring, CBOM export, shadow CAs,
  application metadata, weak-algorithm analysis, Netwrix.
- `go test -tags integration ./internal/...` is green.
- CI runs that suite so schema/code drift fails the build.
- No EE-only table is added to CE's schema.

## Design

### 1. One additive migration

New file `internal/store/migrations/v2.2.4_schema_parity.sql` (sorts after
`v2.2.0_...`; the runner applies files in lexicographic order and records each in
`schema_migrations`). It never edits an applied migration. Idempotent, so it is
safe on fresh installs and on existing 2.x databases:

```sql
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS aliases           JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS discovery_sources JSONB NOT NULL DEFAULT '[]';

ALTER TABLE asset_health_reports
    ADD COLUMN IF NOT EXISTS risk_score   INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS risk_factors JSONB   NOT NULL DEFAULT '{}';
```

(no EE risk-score index: the risk engine is EE-only), then guarded renames, one
`DO $$ ... $$` block per column, each checking `information_schema.columns` for
the old name in `current_schema()` before `ALTER TABLE ... RENAME COLUMN`:
`operator_declared_cas.declared_at -> added_at`, `.declared_by -> added_by`,
`application_metadata.declared_at -> added_at`, `.declared_by -> added_by`
(using `current_schema()` keeps the per-package test schemas correct); then
`CREATE TABLE IF NOT EXISTS ad_cs_events (...)` with the four indexes, copied
unchanged from EE migration `007_ad_cs_events.sql`.

Renames preserve any existing rows; these features could not have persisted
rows under the old schema, so no live data depends on the old names.

### 2. Strip the EE-only code legs

- Remove the `protocol_endpoints` UNION legs from the three queries in
  `internal/store/applications.go` and from `ListApplicationScopeAssets`
  (`internal/store/cbom_store.go`). The application summary and CBOM queries
  then cover certificates, SSH keys, libraries, configs, hosts and repositories.
- Remove `scanProtocolEndpointsForWeakAlgo` and its call site in
  `internal/store/weak_algorithms.go`.
- Delete `ApplicationPostureSnapshot` and the four snapshot functions in
  `internal/store/applications.go`, plus `applications_prune_integration_test.go`.
- Follow the existing "CE-flavor" comment pattern already used in
  `postgres.go` and `events.go` where a leg is omitted.

### 3. CI guard

Add an `integration` job to `.github/workflows/ci.yml`: a `postgres:15-alpine`
service container, `CIPHERFLAG_TEST_DB` pointing at it, and
`go test -tags integration ./... -count=1`. The job is part of the required
checks so drift fails the build.

### 4. Release

Bump to 2.2.4 with a changelog entry that states what was broken on a
freshly built database, that the migration applies automatically at startup, and
the CI change.

## Testing and acceptance

1. Start from the current red state (`t0-fullsuite.txt` baseline). Drive
   `go test -tags integration ./internal/... -count=1` to green.
2. Any further failure is classified: same-class schema/code mismatch (fix under
   this spec), or a different defect (report; do not silently absorb).
3. Migration idempotence: applying the full migration set to a fresh schema
   and to a schema that already holds v2.2.0 objects both succeed, and applying
   `Migrate` twice is a no-op (a store integration test).
4. Query smoke: a store integration test executes the estate, scope and
   application CBOM queries against the migrated schema and asserts no error.
5. `go build ./...`, `go vet ./...`, and the ordinary `go test ./...` stay green.

## Out of scope

The EE risk engine (the added columns stay at their defaults in CE), any other
EE-only tables, and adding a compatibility layer for pre-2.0 databases (already
documented as "reinitialize").

## Risks

- Further drift may surface once the first layer is fixed; the acceptance loop
  handles it, with classification as above.
- Existing 2.x databases run the new migration on next start. `Migrate` executes
  each file as one multi-statement `Exec` (verified in `store/postgres.go:65-115`),
  which Postgres runs as a single implicit transaction, so a failed run leaves
  the old schema intact, and the file is recorded in `schema_migrations` only
  after it succeeds. If the recording insert itself failed after a successful
  run, the file would re-run on the next start, which is why every statement is
  idempotent (`IF NOT EXISTS`, guarded renames).
- Removing dead posture-snapshot code changes the store's exported surface; a
  repo-wide grep showed no callers outside the file's own test.

## Sequencing

Ship 2.2.4 (branch `fix/ce-schema-parity` off `main`), tag and push on the
owner's go, then resume the CBOM export completion plan at Task 0 on a branch
cut from the updated `main`.

## Outcome (added after implementation)

The design held, but the drift was wider than the eight gap types found up
front. Driving the integration suite to green needed a systematic method rather
than one error per run: diffing an EE-built schema against the CE-built one
(columns, data types and nullability, CHECKs, unique indexes) and checking every
`ON CONFLICT` target in CE code against the unique indexes that exist.

What that added beyond the original design:

- `ssh_keys.{owner_user,is_authorized,is_protected,grants_root}`,
  `crypto_libraries.package_manager`, and `created_at` on
  `host_ip_sightings` / `asset_ownership_sightings`.
- Unique indexes `ssh_keys(host_id, fingerprint_sha256)` and
  `crypto_libraries(host_id, library_name, version)`: CE's baseline keys were
  wider (with `file_path` / `install_path`), so the `ON CONFLICT` upserts failed
  even with the columns present.
- `host_ip_sightings`: `ip` inet to text (via `host()`), `host_id` nullable,
  `attribution` NOT NULL, `idx_hip_unique`, and the window CHECK renamed to
  `host_ip_sightings_window_check`.
- Seven CHECK constraints added `NOT VALID`. `asset_ownership_sightings`'
  asset_type check was not added: CE already has its own, deliberately without
  the EE-only `protocol_endpoint` value.
- More EE-only references removed: the ownership-backfill and HNDL tag lookups,
  and the `protocol_observations` update in `MergeHosts`.

Corrections to claims made in this spec:

- "No callers outside their own integration test" was wrong for the posture
  snapshot code: `GetApplication` called `ListApplicationSnapshots`, ignoring
  its error. On CE that query always failed, so the call block was removed and
  `ScoreDelta7d` / `ReferenceSnapshotAt` stay zero (JSON shape unchanged).
- The first constraint diff compared only tables that already had a CE
  constraint and so missed `application_metadata_ttl_range`; the query was
  fixed and re-run.

Tests and goldens that asserted EE-only behaviour were changed to assert CE's
(no PCI DSS 4 / FIPS 203-205 frameworks, no risk-engine factors, no
certificate-to-issuer dependency edges: CE's issuance lookup is a deliberate
no-op). The two CBOM goldens were regenerated only after verifying
programmatically that the sole change was removal of 9 `cert:` issuer edges.

Not done, by design: dead `pcap_jobs` store methods remain (no callers);
EE-only columns and CHECKs with no CE reference were left out; and the
`operator_declared_cas` / `application_metadata` foreign keys lack EE's
`ON DELETE SET NULL` (deleting a user who declared a CA or application
metadata may fail with a foreign-key error).
