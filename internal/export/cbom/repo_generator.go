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
	"fmt"
	"sort"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

// repoFindingsLister is the narrow store interface GenerateForRepo needs.
// store.PostgresStore satisfies it via ListRepositoryFindings (added in 6.1b-4).
type repoFindingsLister interface {
	ListRepositoryFindings(ctx context.Context, q store.RepoFindingQuery) ([]store.RepoFindingRow, error)
}

// GenerateForRepo produces a CycloneDX 1.6 BOM containing one algorithm
// component per unique algorithm referenced by B3 findings on the given
// repository. Each algorithm component aggregates evidence.occurrences
// across every B3 finding that referenced it.
//
// Returns an empty BOM (zero components) when the repo has no health
// report or no B3 findings — callers should not treat that as an error.
func (g *Generator) GenerateForRepo(ctx context.Context, st repoFindingsLister, repoID string) (*cdx.BOM, error) {
	rows, err := st.ListRepositoryFindings(ctx, store.RepoFindingQuery{
		RepoID:  repoID,
		Buckets: []string{"B3"},
		Limit:   10000, // a single repo with >10k crypto-API call sites is exceptional
	})
	if err != nil {
		return nil, fmt.Errorf("cbom: list repo findings: %w", err)
	}

	components := findingsToAlgoComponents(rows)

	// Compute dependency edges for algorithm components (protocol→algo edges
	// if any protocol components were assembled). Repo-scoped BOMs contain
	// only algorithm components so cert_issuance edges never fire here;
	// noopIssuanceLookup is correct and avoids pulling a store reference into
	// this narrow repoFindingsLister path.
	inBom := buildBOMRefSet(components)
	inScope := func(ref string) bool { return inBom[ref] }
	deps := computeDependencies(components, noopIssuanceLookup{}, inScope)
	components = annotateUnresolvedAndInferred(components, deps, inBom, noopIssuanceLookup{})

	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.SerialNumber = "urn:uuid:" + uuid.New().String()
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "cipherflag",
				Version: cbomVersion,
			}},
		},
		Component: &cdx.Component{
			Type:   cdx.ComponentTypeApplication,
			BOMRef: "repo:" + repoID,
			Name:   "repository " + repoID,
		},
	}
	if len(components) > 0 {
		bom.Components = &components
	}
	if len(deps) > 0 {
		bom.Dependencies = &deps
	}
	logAlgorithmDrift(components, "repo:"+repoID)
	logUnresolvedDeps(components, "repo:"+repoID)

	// Opt-in JSF signing — same pattern as Generate.
	// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13 Step 5.
	if g.signer != nil {
		if err := SignBOM(bom, g.signer); err != nil {
			return nil, fmt.Errorf("cbom: sign BOM: %w", err)
		}
	}
	return bom, nil
}

// findingsToAlgoComponents walks B3 findings, dedups by canonical algorithm
// name, and produces one CycloneDX algorithm component per unique algorithm
// with aggregated evidence.occurrences.
func findingsToAlgoComponents(rows []store.RepoFindingRow) []cdx.Component {
	type bucket struct {
		comp        cdx.Component
		occurrences []cdx.EvidenceOccurrence
	}
	byAlgo := map[string]*bucket{}
	order := []string{}

	for _, row := range rows {
		if row.Bucket != "B3" {
			continue
		}
		raw := row.Raw
		cbomMap, ok := raw["cbom"].(map[string]any)
		if !ok {
			continue
		}
		algo, _ := cbomMap["algorithm"].(string)
		if algo == "" {
			continue
		}
		b, ok := byAlgo[algo]
		if !ok {
			c := algoToComponent(algo)
			b = &bucket{comp: c}
			byAlgo[algo] = b
			order = append(order, algo)
		}
		// Aggregate occurrences from cbom.evidence_occurrences, or fall back
		// to the finding's own (path) when the inner list is missing.
		if occs, ok := cbomMap["evidence_occurrences"].([]any); ok {
			for _, o := range occs {
				occMap, ok := o.(map[string]any)
				if !ok {
					continue
				}
				path, _ := occMap["path"].(string)
				line, _ := occMap["line"].(float64)
				b.occurrences = append(b.occurrences, cdx.EvidenceOccurrence{
					Location: fmt.Sprintf("%s:%d", path, int(line)),
				})
			}
		} else if row.Path != "" {
			b.occurrences = append(b.occurrences, cdx.EvidenceOccurrence{
				Location: row.Path,
			})
		}
	}

	// Sort `order` so emitted component ordering depends only on the set of
	// algorithms present, not on the scanner's JSONB iteration order. Mirrors
	// the determinism guards in generator.go (commit 15c2c92) and
	// application.go (commit fe432d4); harmless today because the rich seed has
	// one B3 finding per repo, load-bearing the moment a multi-finding repo
	// lands.
	sort.Strings(order)
	out := make([]cdx.Component, 0, len(order))
	for _, algo := range order {
		b := byAlgo[algo]
		if len(b.occurrences) > 0 {
			occs := b.occurrences
			b.comp.Evidence = &cdx.Evidence{Occurrences: &occs}
		}
		out = append(out, b.comp)
	}
	return out
}
