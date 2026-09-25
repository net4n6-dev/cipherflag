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
