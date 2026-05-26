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

	"github.com/net4n6-dev/cipherflag/internal/config"
)

func TestMatchAssetByHostIDs_ExplicitMatch(t *testing.T) {
	s := Scope{HostIDs: []string{"aaa", "bbb"}}
	if !s.MatchAssetByHostIDs([]string{"bbb", "ccc"}, "certificate") {
		t.Error("expected match on explicit host ID overlap")
	}
}

func TestMatchAssetByHostIDs_NoOverlap(t *testing.T) {
	s := Scope{HostIDs: []string{"aaa"}}
	if s.MatchAssetByHostIDs([]string{"bbb"}, "certificate") {
		t.Error("expected no match when host IDs do not overlap")
	}
}

func TestMatchAssetByHostIDs_AssetTypeFilter(t *testing.T) {
	s := Scope{HostIDs: []string{"aaa"}, AssetTypes: []string{"certificate"}}
	if s.MatchAssetByHostIDs([]string{"aaa"}, "ssh_key") {
		t.Error("expected no match when asset type is excluded by scope filter")
	}
	if !s.MatchAssetByHostIDs([]string{"aaa"}, "certificate") {
		t.Error("expected match for explicitly allowed asset type")
	}
}

func TestMatchAssetByHostIDs_EmptyAssetTypes(t *testing.T) {
	s := Scope{HostIDs: []string{"aaa"}, AssetTypes: nil}
	if !s.MatchAssetByHostIDs([]string{"aaa"}, "ssh_key") {
		t.Error("empty AssetTypes should match all types")
	}
}

func TestMatchAssetByHostIDs_EmptyProvenance(t *testing.T) {
	s := Scope{HostIDs: []string{"aaa"}}
	if s.MatchAssetByHostIDs(nil, "certificate") {
		t.Error("expected no match for asset with no provenance")
	}
}

func TestScopesFromConfig_Roundtrip(t *testing.T) {
	cfgs := []config.ScopeConfig{
		{Name: "prod", HostPatterns: []string{"web-*"}, MinRiskScore: 10},
		{Name: "dmz", HostIDs: []string{"uuid-1"}},
	}
	scopes := ScopesFromConfig(cfgs)
	if len(scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(scopes))
	}
	if scopes[0].Name != "prod" || scopes[0].MinRiskScore != 10 {
		t.Errorf("scope[0] roundtrip failed: %+v", scopes[0])
	}
	if scopes[1].HostIDs[0] != "uuid-1" {
		t.Errorf("scope[1] HostIDs roundtrip failed: %+v", scopes[1])
	}
}

type fakePatternStore struct {
	patternIDs []string
}

func (f *fakePatternStore) GetHostIDsByPatterns(_ context.Context, _ []string) ([]string, error) {
	return f.patternIDs, nil
}

func TestResolveHostIDsForScope_MergesPatternAndExplicit(t *testing.T) {
	s := Scope{
		HostIDs:      []string{"explicit-1"},
		HostPatterns: []string{"web-*"},
	}
	fake := &fakePatternStore{patternIDs: []string{"pattern-2", "explicit-1"}}
	ids, err := resolveHostIDsForScope(context.Background(), fake, &s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 unique IDs (deduped), got %d: %v", len(ids), ids)
	}
}

func TestResolveHostIDsForScope_NoPatterns(t *testing.T) {
	s := Scope{HostIDs: []string{"h1", "h2"}}
	fake := &fakePatternStore{}
	ids, err := resolveHostIDsForScope(context.Background(), fake, &s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 explicit IDs, got %d", len(ids))
	}
}
