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

import cdx "github.com/CycloneDX/cyclonedx-go"

// AlgorithmObservation describes one (algorithm, library, fips_level)
// triple from an algorithm's provenance trail. The caller assembles the
// slice by joining asset_provenance data with the FIPS-validation map.
// FIPSLevel uses the CDX wire-format strings (e.g. "fips140-3-l1");
// empty string means the library is not FIPS-validated for this observation.
type AlgorithmObservation struct {
	Algorithm string
	Library   string
	FIPSLevel string // "fips140-3-l1" | "fips140-3-l2" | ... | "" (not validated)
}

// certificationLevelForAlgo returns the CycloneDX certification level for
// the given algorithm only when ALL observations of that algorithm agree on
// the same non-empty FIPS level (monomorphic). Any disagreement — mixed
// FIPS levels, or any observation without a FIPS level — returns None so
// we don't overclaim a certification that doesn't cover the full usage
// surface.
//
// Observations whose Algorithm field doesn't match algo are ignored, which
// allows a single pre-joined slice to be queried for each algorithm in turn.
func certificationLevelForAlgo(algo string, observations []AlgorithmObservation) cdx.CryptoCertificationLevel {
	if len(observations) == 0 {
		return cdx.CryptoCertificationLevelNone
	}
	// level is the agreed-upon FIPS level across all matching observations.
	// "" means "not yet seen any observation for this algo".
	// seenAny tracks whether we found at least one observation for algo.
	var level string
	seenAny := false
	for _, o := range observations {
		if o.Algorithm != algo {
			continue
		}
		if !seenAny {
			seenAny = true
			level = o.FIPSLevel
			continue
		}
		if o.FIPSLevel != level {
			return cdx.CryptoCertificationLevelNone // disagreement
		}
	}
	if !seenAny {
		return cdx.CryptoCertificationLevelNone
	}
	return mapFIPSStringToCDX(level)
}

// mapFIPSStringToCDX converts a CDX wire-format FIPS level string to the
// corresponding CryptoCertificationLevel constant. Returns None for any
// unrecognised or empty input — callers must not assume a default.
func mapFIPSStringToCDX(s string) cdx.CryptoCertificationLevel {
	switch s {
	case "fips140-3-l1":
		return cdx.CryptoCertificationLevelFIPS140_3_L1
	case "fips140-3-l2":
		return cdx.CryptoCertificationLevelFIPS140_3_L2
	case "fips140-3-l3":
		return cdx.CryptoCertificationLevelFIPS140_3_L3
	case "fips140-3-l4":
		return cdx.CryptoCertificationLevelFIPS140_3_L4
	case "fips140-2-l1":
		return cdx.CryptoCertificationLevelFIPS140_2_L1
	case "fips140-2-l2":
		return cdx.CryptoCertificationLevelFIPS140_2_L2
	case "fips140-2-l3":
		return cdx.CryptoCertificationLevelFIPS140_2_L3
	case "fips140-2-l4":
		return cdx.CryptoCertificationLevelFIPS140_2_L4
	case "fips140-1-l1":
		return cdx.CryptoCertificationLevelFIPS140_1_L1
	case "fips140-1-l2":
		return cdx.CryptoCertificationLevelFIPS140_1_L2
	case "fips140-1-l3":
		return cdx.CryptoCertificationLevelFIPS140_1_L3
	case "fips140-1-l4":
		return cdx.CryptoCertificationLevelFIPS140_1_L4
	default:
		return cdx.CryptoCertificationLevelNone
	}
}
