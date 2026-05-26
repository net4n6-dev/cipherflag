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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

func newTestCache(t *testing.T) (*PostgresStore, func()) {
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
	if _, err := s.pool.Exec(ctx, "TRUNCATE repo_scan_cache"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s, func() {
		_, _ = s.pool.Exec(ctx, "TRUNCATE repo_scan_cache")
		s.Close()
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestCacheEntry_PutAndGet(t *testing.T) {
	s, done := newTestCache(t)
	defer done()
	ctx := context.Background()

	sha := mustHex("0001020304050607080900010203040506070809000102030405060708090001")
	entry := &model.RepoScanCacheEntry{
		BlobSHA:           sha,
		RuleVersion:       "v1",
		PromptContentHash: "",
		ScanMode:          "deterministic_only",
		AssetType:         model.AssetTypeRepository,
		FindingsJSON:      []byte(`[]`),
		TokenCost:         0,
	}
	if err := s.PutCacheEntry(ctx, entry); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, err := s.GetCacheEntry(ctx, sha, "v1", "", "deterministic_only", model.AssetTypeRepository)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected hit, got nil")
	}
	if !bytes.Equal(got.BlobSHA, sha) {
		t.Errorf("blob_sha mismatch")
	}
	if string(got.FindingsJSON) != `[]` {
		t.Errorf("findings_json mismatch: %q", got.FindingsJSON)
	}
}

func TestCacheEntry_MissOnWrongKey(t *testing.T) {
	s, done := newTestCache(t)
	defer done()
	ctx := context.Background()

	sha := mustHex("0001020304050607080900010203040506070809000102030405060708090001")
	_ = s.PutCacheEntry(ctx, &model.RepoScanCacheEntry{
		BlobSHA: sha, RuleVersion: "v1", PromptContentHash: "",
		ScanMode: "deterministic_only", AssetType: model.AssetTypeRepository,
		FindingsJSON: []byte(`[]`),
	})

	cases := []struct {
		name string
		key  []string
	}{
		{"wrong rule version", []string{"v2", "", "deterministic_only", model.AssetTypeRepository}},
		{"wrong prompt hash", []string{"v1", "xx", "deterministic_only", model.AssetTypeRepository}},
		{"wrong scan mode", []string{"v1", "", "enrichment", model.AssetTypeRepository}},
		{"wrong asset type", []string{"v1", "", "deterministic_only", model.AssetTypeContainerImage}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.GetCacheEntry(ctx, sha, tc.key[0], tc.key[1], tc.key[2], tc.key[3])
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got != nil {
				t.Errorf("expected miss for %v, got hit", tc.key)
			}
		})
	}
}

func TestCacheEntry_PutIsIdempotent(t *testing.T) {
	s, done := newTestCache(t)
	defer done()
	ctx := context.Background()

	sha := mustHex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
	first := &model.RepoScanCacheEntry{BlobSHA: sha, RuleVersion: "v1", ScanMode: "deterministic_only", AssetType: model.AssetTypeRepository, FindingsJSON: []byte(`[{"a":1}]`)}
	if err := s.PutCacheEntry(ctx, first); err != nil {
		t.Fatalf("put1: %v", err)
	}
	second := &model.RepoScanCacheEntry{BlobSHA: sha, RuleVersion: "v1", ScanMode: "deterministic_only", AssetType: model.AssetTypeRepository, FindingsJSON: []byte(`[{"a":2}]`)}
	if err := s.PutCacheEntry(ctx, second); err != nil {
		t.Fatalf("put2: %v", err)
	}
	got, _ := s.GetCacheEntry(ctx, sha, "v1", "", "deterministic_only", model.AssetTypeRepository)
	// Postgres normalises JSONB whitespace, so compare semantically.
	var parsed []map[string]any
	if err := json.Unmarshal(got.FindingsJSON, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed) != 1 || parsed[0]["a"].(float64) != 2 {
		t.Errorf("expected overwrite to a:2; got %q (%+v)", got.FindingsJSON, parsed)
	}
}

// TestRepoScanCache_AssetTypeDiscriminator verifies that Layer 6.2a's
// asset_type column is part of the primary key: a 'repository' row and a
// 'container_image' row with otherwise-identical keys both survive, and
// each retrieves independently.
func TestRepoScanCache_AssetTypeDiscriminator(t *testing.T) {
	s, done := newTestCache(t)
	defer done()
	ctx := context.Background()

	sha := mustHex("cafebabe00000000000000000000000000000000000000000000000000000001")

	repoEntry := &model.RepoScanCacheEntry{
		BlobSHA:           sha,
		RuleVersion:       "v1",
		PromptContentHash: "",
		ScanMode:          "deterministic_only",
		AssetType:         model.AssetTypeRepository,
		FindingsJSON:      []byte(`[{"origin":"repo"}]`),
	}
	if err := s.PutCacheEntry(ctx, repoEntry); err != nil {
		t.Fatalf("put repo: %v", err)
	}

	containerEntry := &model.RepoScanCacheEntry{
		BlobSHA:           sha,
		RuleVersion:       "v1",
		PromptContentHash: "",
		ScanMode:          "deterministic_only",
		AssetType:         model.AssetTypeContainerImage,
		FindingsJSON:      []byte(`[{"origin":"container"}]`),
	}
	if err := s.PutCacheEntry(ctx, containerEntry); err != nil {
		t.Fatalf("put container: %v", err)
	}

	gotRepo, err := s.GetCacheEntry(ctx, sha, "v1", "", "deterministic_only", model.AssetTypeRepository)
	if err != nil {
		t.Fatalf("get repo: %v", err)
	}
	if gotRepo == nil {
		t.Fatal("expected repo entry to survive the container insert")
	}
	if gotRepo.AssetType != model.AssetTypeRepository {
		t.Errorf("want asset_type=%q, got %q", model.AssetTypeRepository, gotRepo.AssetType)
	}
	var repoParsed []map[string]any
	if err := json.Unmarshal(gotRepo.FindingsJSON, &repoParsed); err != nil {
		t.Fatalf("unmarshal repo findings: %v", err)
	}
	if len(repoParsed) != 1 || repoParsed[0]["origin"] != "repo" {
		t.Errorf("repo cache body was overwritten: %s", gotRepo.FindingsJSON)
	}

	gotContainer, err := s.GetCacheEntry(ctx, sha, "v1", "", "deterministic_only", model.AssetTypeContainerImage)
	if err != nil {
		t.Fatalf("get container: %v", err)
	}
	if gotContainer == nil {
		t.Fatal("expected container entry to survive alongside the repo row")
	}
	if gotContainer.AssetType != model.AssetTypeContainerImage {
		t.Errorf("want asset_type=%q, got %q", model.AssetTypeContainerImage, gotContainer.AssetType)
	}
	var containerParsed []map[string]any
	if err := json.Unmarshal(gotContainer.FindingsJSON, &containerParsed); err != nil {
		t.Fatalf("unmarshal container findings: %v", err)
	}
	if len(containerParsed) != 1 || containerParsed[0]["origin"] != "container" {
		t.Errorf("container cache body wrong: %s", gotContainer.FindingsJSON)
	}
}
