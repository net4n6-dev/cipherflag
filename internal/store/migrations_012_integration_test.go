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
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// TestMigration012_TablesExist is a schema-shape smoke test. It runs against
// the cipherflag-test-db Postgres (port 5434) and asserts that migration 012
// has created the two new tables with the expected columns. It uses the
// normal store constructor which applies all migrations.
func TestMigration012_TablesExist(t *testing.T) {
	dsn := testdb.Require(t)
	ctx := context.Background()
	s, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for _, col := range []struct{ table, column string }{
		{"repositories", "id"},
		{"repositories", "provider_id"},
		{"repositories", "url"},
		{"repositories", "default_branch"},
		{"repositories", "schedule_cron"},
		{"repositories", "default_scan_mode"},
		{"repositories", "tags"},
		{"repositories", "auth_secret_ref"},
		{"repositories", "last_scanned_sha"},
		{"repositories", "last_scan_at"},
		{"repositories", "first_seen"},
		{"repositories", "last_seen"},
		{"lineage_links", "id"},
		{"lineage_links", "from_asset_type"},
		{"lineage_links", "from_asset_id"},
		{"lineage_links", "to_asset_type"},
		{"lineage_links", "to_asset_id"},
		{"lineage_links", "link_type"},
		{"lineage_links", "confidence"},
		{"lineage_links", "evidence"},
		{"lineage_links", "created_at"},
	} {
		var exists bool
		err := s.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name = $1 AND column_name = $2
			)
		`, col.table, col.column).Scan(&exists)
		if err != nil {
			t.Fatalf("check %s.%s: %v", col.table, col.column, err)
		}
		if !exists {
			t.Errorf("expected column %s.%s to exist", col.table, col.column)
		}
	}
}
