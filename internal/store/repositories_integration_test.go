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
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// newTestRepo connects to the test DB, runs migrations, truncates the
// repository + provider tables, seeds two providers (so tests that filter
// by provider can use distinct IDs), and returns the store + the seeded
// provider IDs. The seeding became necessary in 6.1b-1 when migration 014
// added the FK from repositories.provider_id to providers.id.
func newTestRepo(t *testing.T) (*PostgresStore, [3]string, func()) {
	t.Helper()
	dsn := testdb.Require(t)
	ctx := context.Background()
	s, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "TRUNCATE providers, repositories CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	// Seed three providers so each test can pick fresh provider IDs.
	var pids [3]string
	for i, kind := range []string{"github", "gitlab", "bitbucket"} {
		p := &model.Provider{
			Kind:          kind,
			BaseURL:       "https://test-" + kind + ".example",
			AuthSecretRef: "env:TEST",
		}
		if err := s.UpsertProvider(ctx, p); err != nil {
			t.Fatalf("seed provider %d: %v", i, err)
		}
		pids[i] = p.ID
	}
	return s, pids, func() {
		_, _ = s.pool.Exec(ctx, "TRUNCATE providers, repositories CASCADE")
		s.Close()
	}
}

func TestUpsertRepository_InsertThenUpdate(t *testing.T) {
	s, pids, done := newTestRepo(t)
	defer done()
	ctx := context.Background()

	r := &model.Repository{
		ProviderID:      pids[0],
		URL:             "https://github.com/acme/widget",
		DefaultBranch:   "main",
		DefaultScanMode: "enrichment",
		Tags:            map[string]string{"env": "prod"},
	}
	if err := s.UpsertRepository(ctx, r); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if r.ID == "" {
		t.Fatal("expected ID to be populated after insert")
	}
	id := r.ID
	r.DefaultBranch = "develop"
	r.LastScannedSHA = "abc123"
	now := time.Now().UTC()
	r.LastScanAt = &now
	if err := s.UpsertRepository(ctx, r); err != nil {
		t.Fatalf("update: %v", err)
	}
	if r.ID != id {
		t.Errorf("ID changed on update: was %s, now %s", id, r.ID)
	}
	got, err := s.GetRepository(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if got.DefaultBranch != "develop" || got.LastScannedSHA != "abc123" {
		t.Errorf("update not persisted: got %+v", got)
	}
}

func TestFindRepositoryByURL_Uniqueness(t *testing.T) {
	s, pids, done := newTestRepo(t)
	defer done()
	ctx := context.Background()

	pid := pids[1]
	r1 := &model.Repository{ProviderID: pid, URL: "https://g.example/x/y", DefaultBranch: "main", DefaultScanMode: "enrichment"}
	if err := s.UpsertRepository(ctx, r1); err != nil {
		t.Fatalf("insert r1: %v", err)
	}
	got, err := s.FindRepositoryByURL(ctx, pid, "https://g.example/x/y")
	if err != nil || got == nil {
		t.Fatalf("find: %v", err)
	}
	if got.ID != r1.ID {
		t.Errorf("find returned %s, want %s", got.ID, r1.ID)
	}
	missing, err := s.FindRepositoryByURL(ctx, pid, "https://g.example/does/not/exist")
	if err != nil {
		t.Fatalf("find-missing: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil on missing, got %+v", missing)
	}
}

func TestListRepositories_FilterByProvider(t *testing.T) {
	s, pids, done := newTestRepo(t)
	defer done()
	ctx := context.Background()

	pidA := pids[0]
	pidB := pids[1]
	urls := []string{"u-1", "u-2", "u-3"}
	providers := []string{pidA, pidA, pidB}
	for i := range urls {
		if err := s.UpsertRepository(ctx, &model.Repository{
			ProviderID: providers[i], URL: urls[i], DefaultBranch: "main", DefaultScanMode: "enrichment",
		}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	all, err := s.ListRepositories(ctx, "", 100, 0)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("want 3 total, got %d", len(all))
	}
	aOnly, err := s.ListRepositories(ctx, pidA, 100, 0)
	if err != nil {
		t.Fatalf("list a: %v", err)
	}
	if len(aOnly) != 2 {
		t.Errorf("want 2 for pidA, got %d", len(aOnly))
	}
}

func TestDeleteRepository_Idempotent(t *testing.T) {
	s, pids, done := newTestRepo(t)
	defer done()
	ctx := context.Background()
	r := &model.Repository{ProviderID: pids[2], URL: "u", DefaultBranch: "main", DefaultScanMode: "enrichment"}
	if err := s.UpsertRepository(ctx, r); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := s.DeleteRepository(ctx, r.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteRepository(ctx, r.ID); err != nil {
		t.Errorf("second delete should be no-op, got %v", err)
	}
	got, err := s.GetRepository(ctx, r.ID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}
}
