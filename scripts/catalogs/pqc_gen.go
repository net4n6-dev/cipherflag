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

// pqc_gen.go contains shared types and logic for refresh-pqc.go.
// The entry-point (func main) lives in refresh-pqc.go which carries
// //go:build ignore so `go build ./...` skips it while `go test ./...`
// still compiles the test file plus these helpers.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// pqcWatchlist mirrors watchlists/pqc.yaml.
type pqcWatchlist struct {
	Overrides []pqcEntry        `yaml:"overrides"`
	Classical []pqcEntry        `yaml:"classical"`
	Synonyms  []synonymCategory `yaml:"synonyms"`
}

type pqcEntry struct {
	Canonical     string `yaml:"canonical"`
	Status        string `yaml:"status"`
	Category      string `yaml:"category"`
	Source        string `yaml:"source"`
	SecurityLevel uint8  `yaml:"security_level"`
}

type synonymCategory struct {
	Canonical string   `yaml:"canonical"`
	Aliases   []string `yaml:"aliases"`
}

// nistFipsAlgorithms — hardcoded entries from FIPS 203/204/205.
// SecurityLevel values match the NIST PQC categories: ML-KEM/SLH-DSA use
// levels 1/3/5 (s vs f for SLH-DSA is a speed/size trade, not a level),
// ML-DSA uses 2/3/5.
var nistFipsAlgorithms = []pqcEntry{
	{Canonical: "ml-kem-512", Status: "QuantumSafe", Category: "pqc-kem", SecurityLevel: 1, Source: "https://csrc.nist.gov/pubs/fips/203/final"},
	{Canonical: "ml-kem-768", Status: "QuantumSafe", Category: "pqc-kem", SecurityLevel: 3, Source: "https://csrc.nist.gov/pubs/fips/203/final"},
	{Canonical: "ml-kem-1024", Status: "QuantumSafe", Category: "pqc-kem", SecurityLevel: 5, Source: "https://csrc.nist.gov/pubs/fips/203/final"},
	{Canonical: "ml-dsa-44", Status: "QuantumSafe", Category: "pqc-sig", SecurityLevel: 2, Source: "https://csrc.nist.gov/pubs/fips/204/final"},
	{Canonical: "ml-dsa-65", Status: "QuantumSafe", Category: "pqc-sig", SecurityLevel: 3, Source: "https://csrc.nist.gov/pubs/fips/204/final"},
	{Canonical: "ml-dsa-87", Status: "QuantumSafe", Category: "pqc-sig", SecurityLevel: 5, Source: "https://csrc.nist.gov/pubs/fips/204/final"},
	{Canonical: "slh-dsa-sha2-128s", Status: "QuantumSafe", Category: "pqc-sig", SecurityLevel: 1, Source: "https://csrc.nist.gov/pubs/fips/205/final"},
	{Canonical: "slh-dsa-sha2-128f", Status: "QuantumSafe", Category: "pqc-sig", SecurityLevel: 1, Source: "https://csrc.nist.gov/pubs/fips/205/final"},
	{Canonical: "slh-dsa-sha2-192s", Status: "QuantumSafe", Category: "pqc-sig", SecurityLevel: 3, Source: "https://csrc.nist.gov/pubs/fips/205/final"},
	{Canonical: "slh-dsa-sha2-192f", Status: "QuantumSafe", Category: "pqc-sig", SecurityLevel: 3, Source: "https://csrc.nist.gov/pubs/fips/205/final"},
	{Canonical: "slh-dsa-sha2-256s", Status: "QuantumSafe", Category: "pqc-sig", SecurityLevel: 5, Source: "https://csrc.nist.gov/pubs/fips/205/final"},
	{Canonical: "slh-dsa-sha2-256f", Status: "QuantumSafe", Category: "pqc-sig", SecurityLevel: 5, Source: "https://csrc.nist.gov/pubs/fips/205/final"},
}

// ietfHybridAlgorithms — IETF draft hybrid KEMs.
var ietfHybridAlgorithms = []pqcEntry{
	{Canonical: "x25519-ml-kem-768", Status: "QuantumHybrid", Category: "kex", Source: "https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/"},
	{Canonical: "secp256r1-ml-kem-768", Status: "QuantumHybrid", Category: "kex", Source: "https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/"},
}

func loadPqcWatchlist(path string) (*pqcWatchlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wl pqcWatchlist
	if err := yaml.Unmarshal(data, &wl); err != nil {
		return nil, err
	}
	return &wl, nil
}

// mergeAllPqcSources merges NIST FIPS + IETF hybrids + watchlist overrides +
// watchlist classical into a single canonical-keyed map. Later entries win
// on duplicate keys (overrides > IETF > NIST; classical defaults to manual Source).
func mergeAllPqcSources(wl *pqcWatchlist) map[string]pqcEntry {
	merged := make(map[string]pqcEntry)
	for _, e := range nistFipsAlgorithms {
		merged[e.Canonical] = e
	}
	for _, e := range ietfHybridAlgorithms {
		merged[e.Canonical] = e
	}
	for _, e := range wl.Overrides {
		merged[e.Canonical] = e
	}
	for _, e := range wl.Classical {
		if e.Source == "" {
			e.Source = "manual"
		}
		merged[e.Canonical] = e
	}
	return merged
}

// normalizeCategoryConst maps the YAML category string to the Go const name.
func normalizeCategoryConst(c string) string {
	switch c {
	case "pqc-kem":
		return "PQCKEM"
	case "pqc-sig":
		return "PQCSig"
	case "asymmetric":
		return "Asymmetric"
	case "symmetric":
		return "Symmetric"
	case "hash":
		return "Hash"
	case "signature":
		return "Signature"
	case "kex":
		return "KEX"
	case "kdf":
		return "KDF"
	}
	return c
}

// renderPqcCatalog emits the `canonical` map declaration. SecurityLevel
// is omitted when zero to keep classical entries terse.
func renderPqcCatalog(keys []string, entries map[string]pqcEntry) string {
	var sb strings.Builder
	sb.WriteString("// canonical is the authoritative map of recognised algorithm names to\n")
	sb.WriteString("// their Classification. Generated — see scripts/catalogs/refresh-pqc.go.\n")
	sb.WriteString("var canonical = map[string]Classification{\n")
	for _, k := range keys {
		e := entries[k]
		if e.SecurityLevel != 0 {
			fmt.Fprintf(&sb, "\t%q: {Status: %s, Canonical: %q, Category: Category%s, SecurityLevel: %d, Source: %q},\n",
				k, e.Status, e.Canonical, normalizeCategoryConst(e.Category), e.SecurityLevel, e.Source)
		} else {
			fmt.Fprintf(&sb, "\t%q: {Status: %s, Canonical: %q, Category: Category%s, Source: %q},\n",
				k, e.Status, e.Canonical, normalizeCategoryConst(e.Category), e.Source)
		}
	}
	sb.WriteString("}\n")
	return sb.String()
}

// renderPqcSynonyms emits the `synonyms` map declaration.
// Only aliases from the watchlist are included — canonical keys are NOT
// self-mapped here, because catalog_test.go's
// TestSynonyms_NoCircularReferences requires the synonym and canonical
// key sets to be disjoint (Classify falls through to the canonical map
// when no synonym matches, so self-mappings are redundant anyway).
// The canonicals argument is retained for parameter-symmetry and for
// alias validation by callers.
func renderPqcSynonyms(catSyns []synonymCategory, canonicals map[string]pqcEntry) string {
	_ = canonicals // kept for symmetry / future alias-validation hooks
	syn := make(map[string]string)
	for _, cs := range catSyns {
		for _, alias := range cs.Aliases {
			syn[strings.ToLower(alias)] = cs.Canonical
		}
	}

	keys := make([]string, 0, len(syn))
	for k := range syn {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("// synonyms maps alternative spellings to canonical keys.\n")
	sb.WriteString("// Generated — see scripts/catalogs/refresh-pqc.go.\n")
	sb.WriteString("var synonyms = map[string]string{\n")
	for _, k := range keys {
		fmt.Fprintf(&sb, "\t%q: %q,\n", k, syn[k])
	}
	sb.WriteString("}\n")
	return sb.String()
}
