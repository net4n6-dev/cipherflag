# Schema migrations

SQL migrations applied automatically at server startup by `PostgresStore.Migrate`
in `internal/store/postgres.go`. Forward-only by convention.

## CE v2.0 baseline

CipherFlag CE v2.0.0 ships a single consolidated migration:

- `v2.0_baseline.sql` — the post-port schema baked in as one DDL file.

This **replaces** the v1.x incremental migrations 001-005 that earlier CE
releases carried. Existing v1.x users must reinitialize their database —
no automated v1→v2 data migration is provided. See `CHANGELOG.md`
v2.0.0 §"Compatibility".

The baseline is generated from the CipherFlag EE migration set
(`internal/store/migrations/*.sql` in the EE repo at port time) per the
triage in `docs/superpowers/ce-port/triage-migrations.md` (in EE).
EE-only schema (risk-engine, blast-radius, host-dependency edges,
protocol-endpoints, AI ledger, briefing cache, multi-tenant teams, etc.)
is stripped; mixed migrations have their CE-bound DDL cherry-picked.

## How the runner works

The runner embeds this directory via `//go:embed migrations/*.sql`,
lists every `.sql` file, **sorts the filenames lexicographically with
`sort.Strings`**, and applies any whose filename is not yet recorded in
the `schema_migrations` tracking table. Filenames are the primary key
of that tracking table.

## Future CE migrations (post-v2.0)

Future CE migrations start numbering at `v2.0.1_*.sql` and onward. The
"v2.0" prefix sorts before any "v2.0.1" prefix lexicographically, so the
baseline always applies first.

Examples of acceptable future filenames:
- `v2.0.1_new_feature.sql`
- `v2.1.0_phase2_ct_provider.sql` (Phase 2 CT multi-provider port)

## Don't rename applied migrations

Once a migration's filename is recorded in `schema_migrations`, renaming
the file will cause the runner to apply it a second time as a "new"
migration. Don't rename applied migrations.
