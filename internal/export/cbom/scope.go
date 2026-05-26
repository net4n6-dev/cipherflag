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

	"github.com/net4n6-dev/cipherflag/internal/config"
)

// Scope is the runtime representation of a config.ScopeConfig.
// HostIDs are the explicit UUIDs; HostPatterns are expanded at generation time.
type Scope struct {
	Name         string
	HostPatterns []string
	HostIDs      []string
	AssetTypes   []string // empty = all four types (cert/ssh_key/library/config)
	MinRiskScore int
	Sinks        []config.SinkConfig
}

// MatchAssetByHostIDs returns true if any of the asset's provenance hosts
// intersect this scope AND the asset type is allowed by the scope filter.
// Called in the event-driven notification path.
func (s *Scope) MatchAssetByHostIDs(hostIDs []string, assetType string) bool {
	if len(hostIDs) == 0 {
		return false
	}
	// Check asset type filter (empty = all)
	if len(s.AssetTypes) > 0 {
		allowed := false
		for _, at := range s.AssetTypes {
			if at == assetType {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	// Check host ID overlap
	scopeSet := make(map[string]struct{}, len(s.HostIDs))
	for _, id := range s.HostIDs {
		scopeSet[id] = struct{}{}
	}
	for _, id := range hostIDs {
		if _, ok := scopeSet[id]; ok {
			return true
		}
	}
	return false
}

// ScopesFromConfig converts config.ScopeConfig slices to Scope slices.
func ScopesFromConfig(cfgs []config.ScopeConfig) []Scope {
	scopes := make([]Scope, len(cfgs))
	for i, c := range cfgs {
		scopes[i] = Scope{
			Name:         c.Name,
			HostPatterns: c.HostPatterns,
			HostIDs:      c.HostIDs,
			AssetTypes:   c.AssetTypes,
			MinRiskScore: c.MinRiskScore,
			Sinks:        c.Sinks,
		}
	}
	return scopes
}

// hostIDResolver is the minimal store interface needed by resolveHostIDsForScope.
// store.CryptoStore satisfies this interface.
type hostIDResolver interface {
	GetHostIDsByPatterns(ctx context.Context, patterns []string) ([]string, error)
}

// resolveHostIDsForScope returns the union of explicitly listed host IDs and
// IDs resolved from hostname glob patterns. Called once per Generate invocation
// so new hosts flow in automatically on each cycle.
func resolveHostIDsForScope(ctx context.Context, r hostIDResolver, s *Scope) ([]string, error) {
	set := make(map[string]struct{}, len(s.HostIDs))
	for _, id := range s.HostIDs {
		set[id] = struct{}{}
	}
	if len(s.HostPatterns) > 0 {
		patternIDs, err := r.GetHostIDsByPatterns(ctx, s.HostPatterns)
		if err != nil {
			return nil, err
		}
		for _, id := range patternIDs {
			set[id] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for id := range set {
		result = append(result, id)
	}
	return result, nil
}
