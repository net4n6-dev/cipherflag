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

// Generator reads from a CryptoStore and produces a *cdx.BOM.
// Safe to call concurrently from multiple goroutines once constructed.
// signer is nil when [cbom.signing] enabled = false (the default).
// libraryFIPSLevel is called during algorithm-property enrichment to look
// up whether a given (libraryName, version) pair has a FIPS-validated build;
// it returns a CDX wire-format string ("fips140-3-l1", …) or "" when not
// validated. Never nil — NewGenerator installs the scoring-package default.
type Generator struct {
	signer           Signer // nil → no signing
	libraryFIPSLevel func(name, version string) string
}

// Generate produces a CycloneDX 1.6 BOM for the given scope. (The target format
// is 1.7, but cyclonedx-go v0.10.0 caps at 1.6; upgrade the assignment below
// when the library adds SpecVersion1_7.)
func (g *Generator) Generate(ctx context.Context, st store.CryptoStore, scope *Scope) (*cdx.BOM, error) {
	// 1. Resolve scope host IDs (patterns → UUIDs).
	hostIDs, err := resolveHostIDsForScope(ctx, st, scope)
	if err != nil {
		return nil, fmt.Errorf("cbom: resolve hosts for scope %q: %w", scope.Name, err)
	}

	// 2. Fetch matching asset health rows.
	rows, err := st.ListScopeAssets(ctx, store.ScopeAssetQuery{
		HostIDs:      hostIDs,
		AssetTypes:   scope.AssetTypes,
		MinRiskScore: scope.MinRiskScore,
	})
	if err != nil {
		return nil, fmt.Errorf("cbom: list scope assets for %q: %w", scope.Name, err)
	}

	// 3. Map each row to a CycloneDX component; collect referenced algo BOM refs.
	var components []cdx.Component
	// enrichedAlgos deduplicates algorithm components by BOMRef, preserving
	// the first (enriched) version seen. Cert-sourced components carry
	// padding; later duplicates (e.g. from SSH keys using the same algo)
	// are dropped in favour of the already-stored enriched one.
	enrichedAlgos := make(map[string]cdx.Component)
	// algoSources tracks every asset_provenance.source seen for each algo BOMRef,
	// used to derive CryptoExecutionEnvironment via reduceExecEnv.
	algoSources := make(map[string][]string)
	// libEntries collects (LibraryName, LibraryVersion) from every crypto_library
	// row in scope; used to build AlgorithmObservations in the post-enrichment pass.
	type libEntry struct{ name, version string }
	var libEntries []libEntry

	for _, row := range rows {
		comp, algoComps, err := g.mapRow(ctx, st, row)
		if err != nil {
			return nil, fmt.Errorf("cbom: map %s %s: %w", row.AssetType, row.AssetID, err)
		}
		if comp != nil {
			components = append(components, *comp)
		}
		for _, ac := range algoComps {
			if _, seen := enrichedAlgos[ac.BOMRef]; !seen {
				enrichedAlgos[ac.BOMRef] = ac
			}
			// Accumulate sources for every algo component this row contributes.
			algoSources[ac.BOMRef] = append(algoSources[ac.BOMRef], row.Sources...)
		}
		// Collect library metadata for FIPS observation pass.
		if row.LibraryName != "" {
			libEntries = append(libEntries, libEntry{row.LibraryName, row.LibraryVersion})
		}
	}

	// 4. Post-enrichment: set executionEnvironment and certificationLevel on
	//    each algorithm component using the accumulated source and library data.
	//
	//    executionEnvironment: reduce all provenance sources seen for this algo
	//    to a single conservative enum — hardware only when all agree.
	//
	//    certificationLevel: monomorphic-only policy (certificationLevelForAlgo).
	//    Library observations are built from libEntries collected above; every
	//    library in scope is treated as a potential implementation of every algo
	//    in scope, which is the granularity the current data model supports.
	for bomRef, ac := range enrichedAlgos {
		// Derive canonical name from BOMRef (format: "algo:<canonical>").
		canonical := bomRef
		if len(bomRef) > 5 && bomRef[:5] == "algo:" {
			canonical = bomRef[5:]
		}

		// executionEnvironment from accumulated sources.
		execEnv := reduceExecEnv(algoSources[bomRef])
		if ac.CryptoProperties == nil {
			ac.CryptoProperties = &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm}
		}
		if ac.CryptoProperties.AlgorithmProperties == nil {
			ac.CryptoProperties.AlgorithmProperties = &cdx.CryptoAlgorithmProperties{}
		}
		ac.CryptoProperties.AlgorithmProperties.ExecutionEnvironment = execEnv

		// Build AlgorithmObservations from library entries in scope.
		var observations []AlgorithmObservation
		for _, lib := range libEntries {
			fipsLevel := g.libraryFIPSLevel(lib.name, lib.version)
			observations = append(observations, AlgorithmObservation{
				Algorithm: canonical,
				Library:   lib.name,
				FIPSLevel: fipsLevel,
			})
		}
		certLevel := certificationLevelForAlgo(canonical, observations)
		if certLevel != cdx.CryptoCertificationLevelNone {
			ac.CryptoProperties.AlgorithmProperties.CertificationLevel = &[]cdx.CryptoCertificationLevel{certLevel}
		}

		enrichedAlgos[bomRef] = ac
	}

	// 5. Emit one algorithm component per unique canonical name (enriched).
	// Sort by BOMRef so output order is stable across runs — `enrichedAlgos`
	// is a Go map (non-deterministic iteration) and the resulting
	// components[] slice flows straight into MarshalSignedBOM, so unsorted
	// emit produces a different byte sequence (and a different JSF
	// signature) per invocation. JCS canonicalisation only sorts object
	// keys, not array elements, so the sort here is the only thing keeping
	// the signed bytes reproducible.
	algoRefs := make([]string, 0, len(enrichedAlgos))
	for ref := range enrichedAlgos {
		algoRefs = append(algoRefs, ref)
	}
	sort.Strings(algoRefs)
	for _, ref := range algoRefs {
		components = append(components, enrichedAlgos[ref])
	}

	// 6. Assemble BOM.
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6 // cyclonedx-go v0.10.0 caps at 1.6; upgrade when library adds 1.7
	bom.SerialNumber = "urn:uuid:" + uuid.New().String()

	hostCount := len(hostIDs)
	assetCount := len(rows)
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
			BOMRef: "scope:" + scope.Name,
			Name:   scope.Name,
			Properties: &[]cdx.Property{
				{Name: "cipherflag:scope.host_count", Value: strconv.Itoa(hostCount)},
				{Name: "cipherflag:scope.asset_count", Value: strconv.Itoa(assetCount)},
			},
		},
	}

	// 6b. Compute dependency graph from assembled components.
	lookup := issuanceLookupForStore(ctx, st)
	deps := computeDependencies(components, lookup, func(string) bool { return true })

	// 6c. Annotate components with unresolved/inferred dep signals.
	inBom := buildBOMRefSet(components)
	components = annotateUnresolvedAndInferred(components, deps, inBom, lookup)

	if len(components) > 0 {
		bom.Components = &components
	}
	if len(deps) > 0 {
		bom.Dependencies = &deps
	}

	logAlgorithmDrift(components, "scope:"+scope.Name)
	logUnresolvedDeps(components, "scope:"+scope.Name)

	// Opt-in JSF signing: sign after the BOM is fully assembled so the
	// signature covers components + dependencies.
	// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13 Step 5.
	if g.signer != nil {
		if err := SignBOM(bom, g.signer); err != nil {
			return nil, fmt.Errorf("cbom: sign BOM: %w", err)
		}
	}
	return bom, nil
}

// mapRow loads the full asset record and converts it to a CycloneDX component.
// The second return value is the slice of enriched algorithm components that
// should be added to the BOM alongside the asset component. These are keyed
// by BOMRef and deduplicated by the caller; callers must use the first
// version seen for a given BOMRef (cert-sourced components carry padding that
// a subsequent duplicate sourced from an SSH key would lack).
func (g *Generator) mapRow(ctx context.Context, st store.CryptoStore, row store.ScopeAssetRow) (*cdx.Component, []cdx.Component, error) {
	r := &row.Report
	switch row.AssetType {
	case "certificate":
		cert, err := st.GetCertificate(ctx, row.AssetID)
		if err != nil {
			return nil, nil, err
		}
		if cert == nil {
			return nil, nil, nil
		}
		comp := certToComponent(cert, r)
		// certSigAlgoComponent produces a padding-enriched algorithm component
		// for the cert's signature algorithm. This is the wiring point for
		// Task 10 padding support — the padding field is only set here, where
		// the signature scheme is known.
		algoComp := certSigAlgoComponent(cert)
		return &comp, []cdx.Component{algoComp}, nil

	case "ssh_key":
		key, err := st.GetSSHKey(ctx, row.AssetID)
		if err != nil {
			return nil, nil, err
		}
		if key == nil {
			return nil, nil, nil
		}
		comp := sshKeyToComponent(key, r)
		sshRef := bomRefForSSHKeyType(key.KeyType)
		sshCanonical := sshRef // used as raw name when the algo component is built
		if len(sshRef) > 5 && sshRef[:5] == "algo:" {
			sshCanonical = sshRef[5:]
		}
		algoComp := algoToComponent(sshCanonical)
		return &comp, []cdx.Component{algoComp}, nil

	case "crypto_library":
		lib, err := st.GetCryptoLibrary(ctx, row.AssetID)
		if err != nil {
			return nil, nil, err
		}
		if lib == nil {
			return nil, nil, nil
		}
		comp := libToComponent(lib, r)
		return &comp, nil, nil

	case "crypto_config":
		cfg, err := st.GetCryptoConfig(ctx, row.AssetID)
		if err != nil {
			return nil, nil, err
		}
		if cfg == nil {
			return nil, nil, nil
		}
		comp := configToComponent(cfg, r)
		return &comp, nil, nil

	default:
		return nil, nil, nil
	}
}
