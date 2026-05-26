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

// TestMigration013_TablesExist asserts that migration 013 creates the five
// scanner operational tables with the expected columns.
func TestMigration013_TablesExist(t *testing.T) {
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

	columns := []struct{ table, column string }{
		// providers
		{"providers", "id"},
		{"providers", "kind"},
		{"providers", "base_url"},
		{"providers", "auth_secret_ref"},
		{"providers", "display_name"},
		{"providers", "created_at"},
		// scan_jobs
		{"scan_jobs", "id"},
		{"scan_jobs", "repo_id"},
		{"scan_jobs", "scan_mode"},
		{"scan_jobs", "trigger"},
		{"scan_jobs", "branch_ref"},
		{"scan_jobs", "status"},
		{"scan_jobs", "worker_id"},
		{"scan_jobs", "started_at"},
		{"scan_jobs", "completed_at"},
		{"scan_jobs", "summary_json"},
		{"scan_jobs", "llm_tokens_spent"},
		{"scan_jobs", "llm_cost_usd"},
		{"scan_jobs", "findings_count"},
		{"scan_jobs", "error_text"},
		{"scan_jobs", "created_at"},
		// repo_scan_cache
		{"repo_scan_cache", "blob_sha"},
		{"repo_scan_cache", "rule_version"},
		{"repo_scan_cache", "prompt_content_hash"},
		{"repo_scan_cache", "scan_mode"},
		{"repo_scan_cache", "findings_json"},
		{"repo_scan_cache", "scanned_at"},
		{"repo_scan_cache", "token_cost"},
		// ai_usage_ledger
		{"ai_usage_ledger", "id"},
		{"ai_usage_ledger", "scan_id"},
		{"ai_usage_ledger", "provider"},
		{"ai_usage_ledger", "model"},
		{"ai_usage_ledger", "prompt_id"},
		{"ai_usage_ledger", "prompt_version"},
		{"ai_usage_ledger", "prompt_content_hash"},
		{"ai_usage_ledger", "tokens_in"},
		{"ai_usage_ledger", "tokens_out"},
		{"ai_usage_ledger", "cost_usd"},
		{"ai_usage_ledger", "at"},
		// ai_guardrail_violations
		{"ai_guardrail_violations", "id"},
		{"ai_guardrail_violations", "scan_id"},
		{"ai_guardrail_violations", "guardrail"},
		{"ai_guardrail_violations", "prompt_id"},
		{"ai_guardrail_violations", "prompt_version"},
		{"ai_guardrail_violations", "raw_response_excerpt"},
		{"ai_guardrail_violations", "at"},
	}
	for _, c := range columns {
		var exists bool
		err := s.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name = $1 AND column_name = $2
			)
		`, c.table, c.column).Scan(&exists)
		if err != nil {
			t.Fatalf("check %s.%s: %v", c.table, c.column, err)
		}
		if !exists {
			t.Errorf("expected column %s.%s to exist", c.table, c.column)
		}
	}
}

// TestMigration013_PartialIndexQueuedScans asserts the WHERE status='queued'
// partial index exists on scan_jobs — critical for the SKIP LOCKED claim
// loop in 6.1b-2.
func TestMigration013_PartialIndexQueuedScans(t *testing.T) {
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

	var exists bool
	err = s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE tablename = 'scan_jobs' AND indexname = 'idx_scan_jobs_queued'
		)
	`).Scan(&exists)
	if err != nil {
		t.Fatalf("check idx_scan_jobs_queued: %v", err)
	}
	if !exists {
		t.Fatal("expected partial index idx_scan_jobs_queued on scan_jobs")
	}
}

// TestMigration014_FKExists asserts that migration 014 back-wired the FK
// from repositories.provider_id to providers.id.
func TestMigration014_FKExists(t *testing.T) {
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

	var exists bool
	err = s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.table_constraints
			WHERE constraint_name = 'fk_repositories_provider'
			  AND table_name      = 'repositories'
			  AND constraint_type = 'FOREIGN KEY'
		)
	`).Scan(&exists)
	if err != nil {
		t.Fatalf("check FK: %v", err)
	}
	if !exists {
		t.Fatal("expected fk_repositories_provider FK on repositories")
	}
}
