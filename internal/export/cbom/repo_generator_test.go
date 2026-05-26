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

package cbom

import (
	"context"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

// fakeRepoStore implements only ListRepositoryFindings — the only method
// GenerateForRepo needs.
type fakeRepoStore struct {
	resp []store.RepoFindingRow
	err  error
}

func (f *fakeRepoStore) ListRepositoryFindings(ctx context.Context, q store.RepoFindingQuery) ([]store.RepoFindingRow, error) {
	return f.resp, f.err
}

func TestGenerateForRepo_EmptyFindingsReturnsEmptyBOM(t *testing.T) {
	g := NewGenerator()
	bom, err := g.GenerateForRepo(context.Background(), &fakeRepoStore{}, "repo-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if bom == nil {
		t.Fatal("BOM nil")
	}
	if bom.Components != nil && len(*bom.Components) != 0 {
		t.Errorf("expected 0 components for empty findings, got %d", len(*bom.Components))
	}
	if bom.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("want spec 1.6, got %v", bom.SpecVersion)
	}
}

func TestGenerateForRepo_OneB3MD5_ProducesAlgorithmComponent(t *testing.T) {
	g := NewGenerator()
	store := &fakeRepoStore{resp: []store.RepoFindingRow{
		{
			RepoID:   "repo-1",
			RuleID:   "CRYPTO-WEAK-HASH-MD5",
			Bucket:   "B3",
			Path:     "auth.go",
			Severity: "High",
			Raw: map[string]any{
				"rule_id":  "CRYPTO-WEAK-HASH-MD5",
				"bucket":   "B3",
				"path":     "auth.go",
				"severity": "High",
				"cbom": map[string]any{
					"algorithm": "MD5",
					"evidence_occurrences": []any{
						map[string]any{"path": "auth.go", "line": float64(7)},
					},
				},
			},
		},
	}}
	bom, err := g.GenerateForRepo(context.Background(), store, "repo-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatal("expected >=1 component for one B3 MD5 finding")
	}
	var hasMD5 bool
	for _, c := range *bom.Components {
		// v1.3.5 canonical normalisation: algoToComponent now resolves
		// the raw name through the PQC catalog, so "MD5" → canonical
		// "md5" for intra-BOM dedup stability across casings.
		if c.CryptoProperties != nil && c.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm && c.Name == "md5" {
			hasMD5 = true
		}
	}
	if !hasMD5 {
		t.Errorf("expected md5 algorithm component; got %+v", *bom.Components)
	}
}

func TestGenerateForRepo_DedupsByAlgorithm(t *testing.T) {
	g := NewGenerator()
	store := &fakeRepoStore{resp: []store.RepoFindingRow{
		{Bucket: "B3", Raw: map[string]any{"bucket": "B3", "cbom": map[string]any{"algorithm": "MD5"}}},
		{Bucket: "B3", Raw: map[string]any{"bucket": "B3", "cbom": map[string]any{"algorithm": "MD5"}}},
	}}
	bom, _ := g.GenerateForRepo(context.Background(), store, "repo-1")
	count := 0
	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.CryptoProperties != nil && c.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("expected 1 dedup'd MD5 component, got %d", count)
	}
}

func TestGenerateForRepo_IgnoresNonB3Findings(t *testing.T) {
	g := NewGenerator()
	store := &fakeRepoStore{resp: []store.RepoFindingRow{
		{Bucket: "B1", Raw: map[string]any{"bucket": "B1", "rule_id": "KEY-MAT-PRIVKEY-IN-REPO"}},
		{Bucket: "B4", Raw: map[string]any{"bucket": "B4", "rule_id": "TLS-CFG-PROTOCOL-WEAK"}},
	}}
	bom, _ := g.GenerateForRepo(context.Background(), store, "repo-1")
	if bom.Components != nil && len(*bom.Components) != 0 {
		t.Errorf("non-B3 findings should not produce CBOM components; got %d", len(*bom.Components))
	}
}

func TestGenerateForRepo_AggregatesEvidenceOccurrences(t *testing.T) {
	g := NewGenerator()
	store := &fakeRepoStore{resp: []store.RepoFindingRow{
		{Bucket: "B3", Raw: map[string]any{
			"bucket": "B3",
			"path":   "auth.go",
			"cbom": map[string]any{
				"algorithm":            "MD5",
				"evidence_occurrences": []any{map[string]any{"path": "auth.go", "line": float64(7)}},
			},
		}},
		{Bucket: "B3", Raw: map[string]any{
			"bucket": "B3",
			"path":   "session.go",
			"cbom": map[string]any{
				"algorithm":            "MD5",
				"evidence_occurrences": []any{map[string]any{"path": "session.go", "line": float64(42)}},
			},
		}},
	}}
	bom, _ := g.GenerateForRepo(context.Background(), store, "repo-1")
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("want 1 dedup'd component; got %v", bom.Components)
	}
	c := (*bom.Components)[0]
	if c.Evidence == nil || c.Evidence.Occurrences == nil {
		t.Fatal("expected Evidence.Occurrences populated")
	}
	if len(*c.Evidence.Occurrences) != 2 {
		t.Errorf("expected 2 occurrences (auth.go + session.go), got %d", len(*c.Evidence.Occurrences))
	}
}
