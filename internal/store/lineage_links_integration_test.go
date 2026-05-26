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

func newTestLineage(t *testing.T) (*PostgresStore, func()) {
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
	if _, err := s.pool.Exec(ctx, "TRUNCATE lineage_links"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s, func() {
		_, _ = s.pool.Exec(ctx, "TRUNCATE lineage_links")
		s.Close()
	}
}

func TestCreateLineageLink_InsertAndIdempotent(t *testing.T) {
	s, done := newTestLineage(t)
	defer done()
	ctx := context.Background()

	l := &model.LineageLink{
		FromAssetType: "repository", FromAssetID: "repo-1",
		ToAssetType: "certificate", ToAssetID: "sha256:aa",
		LinkType: "cert_fingerprint_match", Confidence: 1.0,
		Evidence: map[string]any{"commit_sha": "abc", "path": "a.pem"},
	}
	if err := s.CreateLineageLink(ctx, l); err != nil {
		t.Fatalf("create: %v", err)
	}
	if l.ID == "" {
		t.Fatal("expected ID populated")
	}
	// Re-create with same tuple — must not error, must not duplicate.
	dup := &model.LineageLink{
		FromAssetType: "repository", FromAssetID: "repo-1",
		ToAssetType: "certificate", ToAssetID: "sha256:aa",
		LinkType: "cert_fingerprint_match", Confidence: 1.0,
	}
	if err := s.CreateLineageLink(ctx, dup); err != nil {
		t.Fatalf("create dup: %v", err)
	}
	n, err := s.CountLineageLinks(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 row, got %d", n)
	}
}

func TestListLineageFromAndTo(t *testing.T) {
	s, done := newTestLineage(t)
	defer done()
	ctx := context.Background()

	for _, l := range []*model.LineageLink{
		{FromAssetType: "repository", FromAssetID: "repo-1", ToAssetType: "certificate", ToAssetID: "sha256:aa", LinkType: "cert_fingerprint_match", Confidence: 1.0},
		{FromAssetType: "repository", FromAssetID: "repo-1", ToAssetType: "ssh_key", ToAssetID: "sha256:bb", LinkType: "ssh_key_fingerprint_match", Confidence: 1.0},
		{FromAssetType: "repository", FromAssetID: "repo-2", ToAssetType: "certificate", ToAssetID: "sha256:aa", LinkType: "cert_fingerprint_match", Confidence: 1.0},
	} {
		if err := s.CreateLineageLink(ctx, l); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	repo1, err := s.ListLineageFrom(ctx, "repository", "repo-1")
	if err != nil {
		t.Fatalf("list from repo-1: %v", err)
	}
	if len(repo1) != 2 {
		t.Errorf("want 2 links from repo-1, got %d", len(repo1))
	}

	certAA, err := s.ListLineageTo(ctx, "certificate", "sha256:aa")
	if err != nil {
		t.Fatalf("list to cert aa: %v", err)
	}
	if len(certAA) != 2 {
		t.Errorf("want 2 links to cert aa, got %d", len(certAA))
	}
}
