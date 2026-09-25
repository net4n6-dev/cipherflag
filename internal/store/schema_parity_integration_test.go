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
		{"ssh_keys", "owner_user"},
		{"ssh_keys", "is_authorized"},
		{"ssh_keys", "is_protected"},
		{"ssh_keys", "grants_root"},
		{"crypto_libraries", "package_manager"},
		{"host_ip_sightings", "created_at"},
		{"asset_ownership_sightings", "created_at"},
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

// The store upserts use ON CONFLICT on exact column sets, which Postgres only
// accepts when a unique index on precisely those columns exists. CE's baseline
// carried wider keys (with file_path / install_path), so those upserts failed.
func TestSchemaParity_UpsertConflictTargetsHaveUniqueIndexes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for _, name := range []string{
		"ssh_keys_host_id_fingerprint_sha256_key",
		"crypto_libraries_host_id_library_name_version_key",
	} {
		var n int
		if err := st.pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_indexes
			WHERE schemaname = current_schema() AND indexname = $1
		`, name).Scan(&n); err != nil {
			t.Fatalf("index lookup %s: %v", name, err)
		}
		if n != 1 {
			t.Errorf("unique index %s is missing", name)
		}
	}
}

// The tests and the stores rely on these being enforced by the database.
func TestSchemaParity_CheckConstraintsExist(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	for _, c := range []struct{ table, name string }{
		{"application_metadata", "application_metadata_ttl_range"},
		{"asset_ownership_sightings", "aos_confidence_check"},
		{"asset_ownership_sightings", "aos_source_check"},
		{"asset_ownership_sightings", "aos_window_check"},
		{"host_ip_sightings", "host_ip_sightings_confidence_check"},
		{"host_ip_sightings", "host_ip_sightings_source_check"},
		{"host_ip_sightings", "host_ip_sightings_window_check"},
	} {
		var n int
		if err := st.pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_constraint k
			JOIN pg_class t ON t.oid = k.conrelid
			JOIN pg_namespace s ON s.oid = t.relnamespace
			WHERE s.nspname = current_schema() AND t.relname = $1 AND k.conname = $2
		`, c.table, c.name).Scan(&n); err != nil {
			t.Fatalf("constraint lookup %s.%s: %v", c.table, c.name, err)
		}
		if n != 1 {
			t.Errorf("check constraint %s on %s is missing", c.name, c.table)
		}
	}
}

// The store treats host_ip_sightings.ip as text, allows null-host sightings, and
// never stores a NULL attribution; the baseline had inet, NOT NULL host_id and a
// nullable attribution.
func TestSchemaParity_HostIPSightingsShape(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	var ipType, hostNullable, attrNullable string
	if err := st.pool.QueryRow(ctx, `
		SELECT
		  (SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'host_ip_sightings' AND column_name = 'ip'),
		  (SELECT is_nullable FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'host_ip_sightings' AND column_name = 'host_id'),
		  (SELECT is_nullable FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'host_ip_sightings' AND column_name = 'attribution')
	`).Scan(&ipType, &hostNullable, &attrNullable); err != nil {
		t.Fatalf("shape lookup: %v", err)
	}
	if ipType != "text" {
		t.Errorf("host_ip_sightings.ip type = %q, want text", ipType)
	}
	if hostNullable != "YES" {
		t.Errorf("host_ip_sightings.host_id nullable = %q, want YES", hostNullable)
	}
	if attrNullable != "NO" {
		t.Errorf("host_ip_sightings.attribution nullable = %q, want NO", attrNullable)
	}

	var n int
	if err := st.pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'idx_hip_unique'
	`).Scan(&n); err != nil || n != 1 {
		t.Errorf("idx_hip_unique (dedupes null-host sightings) missing: n=%d err=%v", n, err)
	}
	if err := st.pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_constraint k JOIN pg_class t ON t.oid = k.conrelid
		JOIN pg_namespace s ON s.oid = t.relnamespace
		WHERE s.nspname = current_schema() AND t.relname = 'host_ip_sightings' AND k.conname = 'host_ip_sightings_window_valid'
	`).Scan(&n); err != nil || n != 0 {
		t.Errorf("baseline-named host_ip_sightings_window_valid should have been renamed: n=%d err=%v", n, err)
	}
}

// EE's added_by foreign keys are ON DELETE SET NULL, and the stores document
// that ("empty if added_by was deleted"). The baseline's had no ON DELETE, so
// once these tables became writable, deleting any user who had declared a CA or
// application metadata failed with a foreign-key violation.
func TestSchemaParity_DeletingDeclaringUserKeepsRowsAndNullsAddedBy(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	var userID string
	if err := st.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash) VALUES ('declarer@example.com', 'x') RETURNING id::text
	`).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO operator_declared_cas (fingerprint_sha256, subject_cn, added_by) VALUES ('fp-del', 'CN=Del', $1)`,
		userID); err != nil {
		t.Fatalf("seed declared CA: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO application_metadata (tag, note, added_by) VALUES ('del-app', 'kept', $1)`,
		userID); err != nil {
		t.Fatalf("seed application metadata: %v", err)
	}

	if err := st.DeleteUser(ctx, userID); err != nil {
		t.Fatalf("DeleteUser must succeed for a user who declared a CA / application metadata: %v", err)
	}

	for _, q := range []string{
		`SELECT added_by IS NULL FROM operator_declared_cas WHERE fingerprint_sha256 = 'fp-del'`,
		`SELECT added_by IS NULL FROM application_metadata WHERE tag = 'del-app'`,
	} {
		var isNull bool
		if err := st.pool.QueryRow(ctx, q).Scan(&isNull); err != nil {
			t.Fatalf("row lost after deleting its declaring user (%s): %v", q, err)
		}
		if !isNull {
			t.Errorf("added_by should be NULL after the user was deleted (%s)", q)
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
		ALTER TABLE operator_declared_cas
			DROP CONSTRAINT operator_declared_cas_added_by_fkey,
			ADD CONSTRAINT operator_declared_cas_declared_by_fkey FOREIGN KEY (declared_by) REFERENCES users(id);
		ALTER TABLE application_metadata
			DROP CONSTRAINT application_metadata_added_by_fkey,
			ADD CONSTRAINT application_metadata_declared_by_fkey FOREIGN KEY (declared_by) REFERENCES users(id);
		DROP TABLE ad_cs_events;
		ALTER TABLE ssh_keys DROP COLUMN owner_user, DROP COLUMN is_authorized, DROP COLUMN is_protected, DROP COLUMN grants_root;
		ALTER TABLE crypto_libraries DROP COLUMN package_manager;
		ALTER TABLE host_ip_sightings DROP COLUMN created_at;
		ALTER TABLE asset_ownership_sightings DROP COLUMN created_at;
		DROP INDEX ssh_keys_host_id_fingerprint_sha256_key;
		DROP INDEX crypto_libraries_host_id_library_name_version_key;
		ALTER TABLE application_metadata DROP CONSTRAINT application_metadata_ttl_range;
		ALTER TABLE asset_ownership_sightings
			DROP CONSTRAINT aos_confidence_check,
			DROP CONSTRAINT aos_source_check, DROP CONSTRAINT aos_window_check;
		ALTER TABLE host_ip_sightings
			DROP CONSTRAINT host_ip_sightings_confidence_check, DROP CONSTRAINT host_ip_sightings_source_check;
		DROP INDEX idx_hip_unique;
		ALTER TABLE host_ip_sightings ALTER COLUMN host_id SET NOT NULL;
		ALTER TABLE host_ip_sightings ALTER COLUMN ip TYPE inet USING ip::inet;
		ALTER TABLE host_ip_sightings ALTER COLUMN attribution DROP NOT NULL;
		ALTER TABLE host_ip_sightings RENAME CONSTRAINT host_ip_sightings_window_check TO host_ip_sightings_window_valid;
	`
	if _, err := st.pool.Exec(ctx, rewind); err != nil {
		t.Fatalf("rewind to the 2.2.3 shape: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `
		INSERT INTO hosts (canonical_hostname) VALUES ('legacy-host');
		INSERT INTO application_metadata (tag, note) VALUES ('legacy-app', 'kept');
		INSERT INTO operator_declared_cas (fingerprint_sha256, subject_cn) VALUES ('fp-legacy', 'CN=Legacy');
		INSERT INTO ssh_keys (host_id, key_type, fingerprint_sha256, file_path)
			SELECT id, 'ssh-rsa', 'SHA256:legacy', '/root/.ssh/id_rsa' FROM hosts WHERE canonical_hostname = 'legacy-host';
		INSERT INTO crypto_libraries (host_id, library_name, version, install_path)
			SELECT id, 'openssl', '1.1.1', '/usr/lib' FROM hosts WHERE canonical_hostname = 'legacy-host';
		INSERT INTO host_ip_sightings (host_id, ip, first_seen, last_seen, source, confidence)
			SELECT id, '10.0.0.1'::inet, now(), now(), 'dhcp', 'direct' FROM hosts WHERE canonical_hostname = 'legacy-host';
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

	// Legacy SSH key and library rows survive with the new columns defaulted, and
	// the upsert conflict targets now work against them.
	var owner string
	var authorized bool
	if err := st.pool.QueryRow(ctx,
		`SELECT owner_user, is_authorized FROM ssh_keys WHERE fingerprint_sha256 = 'SHA256:legacy'`).Scan(&owner, &authorized); err != nil {
		t.Fatalf("legacy ssh key lost: %v", err)
	}
	if owner != "" || authorized {
		t.Errorf("legacy ssh key defaults = (%q, %v), want ('', false)", owner, authorized)
	}
	var pm string
	if err := st.pool.QueryRow(ctx,
		`SELECT package_manager FROM crypto_libraries WHERE library_name = 'openssl' AND version = '1.1.1'`).Scan(&pm); err != nil {
		t.Fatalf("legacy library lost: %v", err)
	}
	if pm != "" {
		t.Errorf("legacy library package_manager = %q, want ''", pm)
	}

	// An inet address must convert to bare text, not "10.0.0.1/32".
	var ip string
	if err := st.pool.QueryRow(ctx,
		`SELECT ip FROM host_ip_sightings WHERE source = 'dhcp'`).Scan(&ip); err != nil {
		t.Fatalf("legacy host_ip_sighting lost: %v", err)
	}
	if ip != "10.0.0.1" {
		t.Errorf("legacy sighting ip = %q, want 10.0.0.1 (no mask)", ip)
	}
}
