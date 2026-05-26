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

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

func newTestProv(t *testing.T) (*PostgresStore, func()) {
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
	// Cascades remove repositories too (fk_repositories_provider ON DELETE CASCADE).
	if _, err := s.pool.Exec(ctx, "TRUNCATE providers, repositories RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s, func() {
		_, _ = s.pool.Exec(ctx, "TRUNCATE providers, repositories RESTART IDENTITY CASCADE")
		s.Close()
	}
}

func TestUpsertProvider_InsertThenUpdate(t *testing.T) {
	s, done := newTestProv(t)
	defer done()
	ctx := context.Background()

	p := &model.Provider{
		Kind:          "github",
		BaseURL:       "https://github.com",
		AuthSecretRef: "env:GITHUB_PAT",
		DisplayName:   "Prod Org",
	}
	if err := s.UpsertProvider(ctx, p); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if p.ID == "" {
		t.Fatal("expected ID populated")
	}
	id := p.ID

	p.DisplayName = "Prod Org (renamed)"
	p.AuthSecretRef = "env:GITHUB_PAT_NEW"
	if err := s.UpsertProvider(ctx, p); err != nil {
		t.Fatalf("update: %v", err)
	}
	if p.ID != id {
		t.Errorf("ID changed on update: was %s, now %s", id, p.ID)
	}

	got, err := s.GetProvider(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if got.DisplayName != "Prod Org (renamed)" || got.AuthSecretRef != "env:GITHUB_PAT_NEW" {
		t.Errorf("update not persisted: got %+v", got)
	}
}

func TestFindProviderByKindURL(t *testing.T) {
	s, done := newTestProv(t)
	defer done()
	ctx := context.Background()

	p := &model.Provider{Kind: "gitlab", BaseURL: "https://gitlab.example", AuthSecretRef: "env:X"}
	if err := s.UpsertProvider(ctx, p); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := s.FindProviderByKindURL(ctx, "gitlab", "https://gitlab.example")
	if err != nil || got == nil {
		t.Fatalf("find: %v", err)
	}
	if got.ID != p.ID {
		t.Errorf("find returned %s, want %s", got.ID, p.ID)
	}
	missing, err := s.FindProviderByKindURL(ctx, "github", "https://github.com")
	if err != nil {
		t.Fatalf("find-missing: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil on missing, got %+v", missing)
	}
}

func TestListProviders_OrderByCreatedAt(t *testing.T) {
	s, done := newTestProv(t)
	defer done()
	ctx := context.Background()

	for _, kind := range []string{"github", "gitlab", "bitbucket"} {
		if err := s.UpsertProvider(ctx, &model.Provider{
			Kind:          kind,
			BaseURL:       "https://" + kind + ".example",
			AuthSecretRef: "env:X",
		}); err != nil {
			t.Fatalf("insert %s: %v", kind, err)
		}
	}
	all, err := s.ListProviders(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("want 3 providers, got %d", len(all))
	}
}

func TestDeleteProvider_CascadesToRepositories(t *testing.T) {
	s, done := newTestProv(t)
	defer done()
	ctx := context.Background()

	p := &model.Provider{Kind: "github", BaseURL: "https://github.com", AuthSecretRef: "env:X"}
	if err := s.UpsertProvider(ctx, p); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	r := &model.Repository{ProviderID: p.ID, URL: "https://github.com/a/b", DefaultBranch: "main", DefaultScanMode: "enrichment"}
	if err := s.UpsertRepository(ctx, r); err != nil {
		t.Fatalf("insert repo: %v", err)
	}
	if err := s.DeleteProvider(ctx, p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err := s.GetRepository(ctx, r.ID)
	if err != nil {
		t.Fatalf("get repo after provider delete: %v", err)
	}
	if got != nil {
		t.Errorf("expected repo cascade-deleted, got %+v", got)
	}
}
