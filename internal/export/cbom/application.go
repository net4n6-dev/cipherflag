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
	"strconv"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// GenerateForApplication produces a CycloneDX 1.6 BOM scoped to a single
// application-tag. Reuses Generator.mapRow so crypto-asset component
// semantics match the host-scoped CBOM path byte-for-byte — operators
// importing both into the same BOM-consumer see consistent shapes.
//
// Implements AQ-CE-02 at application grain. See
// docs/analyst-question-catalog.md §Domain 9.
func (g *Generator) GenerateForApplication(ctx context.Context, st store.CryptoStore, tag string) (*cdx.BOM, error) {
	rows, err := st.ListApplicationScopeAssets(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("cbom: list assets for application %q: %w", tag, err)
	}

	var components []cdx.Component
	// enrichedAlgos deduplicates algorithm components by BOMRef, preserving
	// the first (enriched) version seen — same semantics as generator.go.
	enrichedAlgos := make(map[string]cdx.Component)
	// algoSources and libEntries mirror the generator.go accumulation pattern
	// for executionEnvironment and certificationLevel post-enrichment.
	algoSources := make(map[string][]string)
	type libEntry struct{ name, version string }
	var libEntries []libEntry

	for _, row := range rows {
		comp, algoComps, err := g.mapRow(ctx, st, row)
		if err != nil {
			// Don't fail the whole export on one bad asset — emit what we
			// can and let the operator review.
			continue
		}
		if comp != nil {
			components = append(components, *comp)
		}
		for _, ac := range algoComps {
			if _, seen := enrichedAlgos[ac.BOMRef]; !seen {
				enrichedAlgos[ac.BOMRef] = ac
			}
			algoSources[ac.BOMRef] = append(algoSources[ac.BOMRef], row.Sources...)
		}
		if row.LibraryName != "" {
			libEntries = append(libEntries, libEntry{row.LibraryName, row.LibraryVersion})
		}
	}

	// Post-enrichment: set executionEnvironment and certificationLevel.
	// Mirrors generator.go step 4 — same monomorphic-only policy.
	for bomRef, ac := range enrichedAlgos {
		canonical := bomRef
		if len(bomRef) > 5 && bomRef[:5] == "algo:" {
			canonical = bomRef[5:]
		}
		execEnv := reduceExecEnv(algoSources[bomRef])
		if ac.CryptoProperties == nil {
			ac.CryptoProperties = &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm}
		}
		if ac.CryptoProperties.AlgorithmProperties == nil {
			ac.CryptoProperties.AlgorithmProperties = &cdx.CryptoAlgorithmProperties{}
		}
		ac.CryptoProperties.AlgorithmProperties.ExecutionEnvironment = execEnv
		var observations []AlgorithmObservation
		for _, lib := range libEntries {
			observations = append(observations, AlgorithmObservation{
				Algorithm: canonical,
				Library:   lib.name,
				FIPSLevel: g.libraryFIPSLevel(lib.name, lib.version),
			})
		}
		certLevel := certificationLevelForAlgo(canonical, observations)
		if certLevel != cdx.CryptoCertificationLevelNone {
			ac.CryptoProperties.AlgorithmProperties.CertificationLevel = &[]cdx.CryptoCertificationLevel{certLevel}
		}
		enrichedAlgos[bomRef] = ac
	}

	// One algorithm component per unique canonical name (enriched).
	// Sort by BOMRef so output order is stable across runs — `enrichedAlgos`
	// is a Go map (non-deterministic iteration) and the resulting
	// components[] slice flows straight into MarshalSignedBOM, so unsorted
	// emit produces a different byte sequence (and a different JSF
	// signature) per invocation. JCS canonicalisation only sorts object
	// keys, not array elements, so the sort here is the only thing keeping
	// the signed bytes reproducible. Same fix as generator.go (commit
	// 15c2c92) — surfaced while implementing TestGolden_GenerateForApplication
	// (L4-E Task 6).
	algoRefs := make([]string, 0, len(enrichedAlgos))
	for ref := range enrichedAlgos {
		algoRefs = append(algoRefs, ref)
	}
	sort.Strings(algoRefs)
	for _, ref := range algoRefs {
		components = append(components, enrichedAlgos[ref])
	}

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
		// The root application component identifies the application tag.
		// Treat the tag as the FISMA system identifier for OMB M-23-02
		// cross-reference purposes (see OMB §II.A field 1).
		Component: &cdx.Component{
			Type:   cdx.ComponentTypeApplication,
			BOMRef: "application:" + tag,
			Name:   tag,
			Properties: &[]cdx.Property{
				{Name: "cipherflag:application.tag", Value: tag},
				{Name: "cipherflag:application.asset_count", Value: strconv.Itoa(len(rows))},
				{Name: "cipherflag:application.fisma_id_alias", Value: tag},
			},
		},
	}

	// Build scope membership: only refs whose component appears in this BOM.
	inBom := buildBOMRefSet(components)
	inScope := func(ref string) bool { return inBom[ref] }

	// Compute dependency graph and annotate components.
	lookup := issuanceLookupForStore(ctx, st)
	deps := computeDependencies(components, lookup, inScope)
	components = annotateUnresolvedAndInferred(components, deps, inBom, lookup)

	if len(components) > 0 {
		bom.Components = &components
	}
	if len(deps) > 0 {
		bom.Dependencies = &deps
	}
	logAlgorithmDrift(components, "application:"+tag)
	logUnresolvedDeps(components, "application:"+tag)

	// Opt-in JSF signing — same pattern as Generate.
	// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13 Step 5.
	if g.signer != nil {
		if err := SignBOM(bom, g.signer); err != nil {
			return nil, fmt.Errorf("cbom: sign BOM: %w", err)
		}
	}
	return bom, nil
}
