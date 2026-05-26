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

package migrations_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// migrationsDir returns the absolute path to the SQL migrations directory by
// walking up from this test file's location. Using runtime.Caller makes the
// path work regardless of the working directory the test runner uses.
func migrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("migrationsDir: runtime.Caller failed")
	}
	// file = .../internal/store/migrations/migrations_testhelper_test.go
	return filepath.Dir(file)
}

// openSchemaPool creates a fresh Postgres schema named after the test and
// returns a pool scoped to that schema. The schema is dropped and recreated
// on each call so tests are isolated from one another.
func openSchemaPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	baseDSN := testdb.DSN()
	if baseDSN == "" {
		t.Skip("CIPHERFLAG_TEST_DB not set, skipping integration test")
	}

	schema := fmt.Sprintf("migtest_%s", sanitizeIdent(t.Name()))
	if len(schema) > 50 {
		schema = schema[:50]
	}

	// Open an admin connection to create/drop the schema.
	adminConn, err := pgx.Connect(ctx, baseDSN)
	if err != nil {
		t.Fatalf("openSchemaPool: admin connect: %v", err)
	}
	defer adminConn.Close(ctx)

	if _, err := adminConn.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgQuoteIdent(schema)+" CASCADE"); err != nil {
		t.Fatalf("openSchemaPool: drop schema: %v", err)
	}
	if _, err := adminConn.Exec(ctx, "CREATE SCHEMA "+pgQuoteIdent(schema)); err != nil {
		t.Fatalf("openSchemaPool: create schema: %v", err)
	}

	t.Cleanup(func() {
		cleanCtx := context.Background()
		conn, err := pgx.Connect(cleanCtx, baseDSN)
		if err != nil {
			return // best-effort cleanup
		}
		defer conn.Close(cleanCtx)
		conn.Exec(cleanCtx, "DROP SCHEMA IF EXISTS "+pgQuoteIdent(schema)+" CASCADE") //nolint:errcheck
	})

	// Build a pool DSN with search_path set to the new schema.
	dsn := appendSearchPath(baseDSN, schema)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("openSchemaPool: pgxpool.New: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("openSchemaPool: ping: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	return pool
}

// ensureSchemaMigrationsTable creates the schema_migrations tracking table in
// the pool's current search_path schema if it does not already exist.
func ensureSchemaMigrationsTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		t.Fatalf("ensureSchemaMigrationsTable: %v", err)
	}
}

// testStoreAtMigration returns a pgxpool connected to a fresh schema with all
// migrations up to (and including) migration number `upTo` applied. Migration
// numbers are extracted from the leading digits of the SQL filename
// (e.g., "048_pqc_migration_snapshots.sql" → 48).
func testStoreAtMigration(t *testing.T, upTo int) *pgxpool.Pool {
	t.Helper()
	pool := openSchemaPool(t)
	ensureSchemaMigrationsTable(t, pool)
	applyMigrationsUpTo(t, pool, upTo)
	return pool
}

// applyMigrationsUpTo applies all SQL migrations whose numeric prefix is less
// than or equal to `upTo` that have not yet been recorded in schema_migrations.
func applyMigrationsUpTo(t *testing.T, pool *pgxpool.Pool, upTo int) {
	t.Helper()
	ctx := context.Background()
	dir := migrationsDir(t)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("applyMigrationsUpTo: ReadDir %s: %v", dir, err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") && !strings.HasSuffix(e.Name(), ".down.sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		n := migrationNumber(name)
		if n < 0 || n > upTo {
			continue
		}

		// Skip already-applied migrations (idempotent).
		var exists bool
		if err := pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", name,
		).Scan(&exists); err != nil {
			t.Fatalf("applyMigrationsUpTo: check %s: %v", name, err)
		}
		if exists {
			continue
		}

		sqlBytes, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("applyMigrationsUpTo: ReadFile %s: %v", name, err)
		}

		if _, err := pool.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("applyMigrationsUpTo: exec %s: %v", name, err)
		}

		if _, err := pool.Exec(ctx,
			"INSERT INTO schema_migrations (version) VALUES ($1)", name,
		); err != nil {
			t.Fatalf("applyMigrationsUpTo: record %s: %v", name, err)
		}
	}
}

// migrationNumber extracts the leading integer from a migration filename such
// as "049_rename_ct_domain_kind.sql". Returns -1 if no leading digits are found.
//
// CE-flavor: "v2.0_baseline.sql" is treated as migration #0 — it must
// always apply before any future CE migration. Returning 0 makes the
// upTo guard accept it for any non-negative upTo.
func migrationNumber(name string) int {
	if name == "v2.0_baseline.sql" {
		return 0
	}
	i := 0
	for i < len(name) && name[i] >= '0' && name[i] <= '9' {
		i++
	}
	if i == 0 {
		return -1
	}
	n := 0
	for _, c := range name[:i] {
		n = n*10 + int(c-'0')
	}
	return n
}

// mustExec executes a SQL statement against the pool and fails the test on error.
func mustExec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatalf("mustExec: %v\nSQL: %s", err, query)
	}
}

// mustQueryRow executes a query that returns exactly one row and returns a
// *sql.Row-like value. The caller must call .Scan(...) on the result.
func mustQueryRow(t *testing.T, pool *pgxpool.Pool, query string, args ...any) pgxRow {
	t.Helper()
	return pgxRow{t: t, row: pool.QueryRow(context.Background(), query, args...)}
}

// pgxRow wraps pgx.Row to provide a test-aware Scan that fails the test on error.
type pgxRow struct {
	t   *testing.T
	row interface{ Scan(dest ...any) error }
}

func (r pgxRow) Scan(dest ...any) {
	r.t.Helper()
	if err := r.row.Scan(dest...); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		r.t.Fatalf("pgxRow.Scan: %v", err)
	}
}

// sanitizeIdent converts a test name to a lowercase Postgres-safe identifier
// by replacing non-alphanumeric characters with underscores.
func sanitizeIdent(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// appendSearchPath returns a new DSN string with search_path set to schema.
// Uses url.Parse + q.Set so that any pre-existing options= key is replaced
// rather than duplicated (raw string concatenation would produce two options
// keys, which pgx may not interpret correctly).
func appendSearchPath(dsn, schema string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		// URL parse failures should be impossible for a DSN we've already
		// used to connect. Return the input unchanged; pgx will error at
		// connection time with a clearer message.
		return dsn
	}
	q := u.Query()
	q.Set("options", "-c search_path="+schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// pgQuoteIdent quotes a Postgres identifier with double quotes.
func pgQuoteIdent(s string) string {
	return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
}
