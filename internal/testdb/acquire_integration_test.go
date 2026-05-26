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

package testdb

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestAcquire_CreatesSchemaAndStoresScopedDSN(t *testing.T) {
	base := DSN()
	if base == "" {
		t.Skip("CIPHERFLAG_TEST_DB not set")
	}
	resetRegistry(t)

	// Reset scopedDSN so we can observe Acquire's effect in isolation.
	scopedDSN.Store("")

	cleanup := Acquire(context.Background(), "internal/acquiretest")
	t.Cleanup(cleanup)

	// After Acquire, scopedDSN should carry the schema-qualified DSN.
	got, ok := scopedDSN.Load().(string)
	if !ok || got == "" {
		t.Fatalf("scopedDSN not set after Acquire; got %v", got)
	}
	if !strings.Contains(got, "search_path%3Dtest_internal_acquiretest") &&
		!strings.Contains(got, "search_path=test_internal_acquiretest") {
		t.Errorf("scopedDSN missing search_path=test_internal_acquiretest: %q", got)
	}

	// The schema should actually exist in the DB.
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect with base DSN: %v", err)
	}
	defer conn.Close(ctx)

	var exists bool
	if err := conn.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)",
		"test_internal_acquiretest",
	).Scan(&exists); err != nil {
		t.Fatalf("check schema exists: %v", err)
	}
	if !exists {
		t.Error("expected schema test_internal_acquiretest to exist after Acquire")
	}

	// Cleanup of this test drops the registry entry so the next test starts fresh.
	_, _ = conn.Exec(ctx, "DROP SCHEMA IF EXISTS test_internal_acquiretest CASCADE")
}

func TestAcquire_EmptyDSNReturnsNoop(t *testing.T) {
	// Force DSN-resolution to return empty — t.Setenv handles
	// restoration automatically at test end.
	t.Setenv("CIPHERFLAG_TEST_DB", "")
	t.Setenv("CIPHERFLAG_TEST_DB_DSN", "")
	t.Setenv("CIPHERFLAG_TEST_DSN", "")

	resetRegistry(t)
	scopedDSN.Store("")

	cleanup := Acquire(context.Background(), "internal/noop")
	t.Cleanup(cleanup)

	if v, ok := scopedDSN.Load().(string); ok && v != "" {
		t.Errorf("scopedDSN should remain empty when DSN() is empty; got %q", v)
	}
}
