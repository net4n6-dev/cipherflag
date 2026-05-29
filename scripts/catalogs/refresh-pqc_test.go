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

package main

import (
	"strings"
	"testing"
)

func TestNormalizeCategoryConst(t *testing.T) {
	cases := map[string]string{
		"pqc-kem":    "PQCKEM",
		"pqc-sig":    "PQCSig",
		"asymmetric": "Asymmetric",
		"symmetric":  "Symmetric",
		"hash":       "Hash",
		"signature":  "Signature",
		"kex":        "KEX",
		"kdf":        "KDF",
	}
	for in, want := range cases {
		if got := normalizeCategoryConst(in); got != want {
			t.Errorf("normalizeCategoryConst(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderPqcCatalog_NistMlKemPresent(t *testing.T) {
	entries := map[string]pqcEntry{
		"ml-kem-768": {Canonical: "ml-kem-768", Status: "QuantumSafe", Category: "pqc-kem", Source: "https://csrc.nist.gov/pubs/fips/203/final"},
	}
	body := renderPqcCatalog([]string{"ml-kem-768"}, entries)
	if !strings.Contains(body, `"ml-kem-768"`) {
		t.Errorf("output missing ml-kem-768: %s", body)
	}
	if !strings.Contains(body, "CategoryPQCKEM") {
		t.Errorf("output missing CategoryPQCKEM: %s", body)
	}
	if !strings.Contains(body, "csrc.nist.gov/pubs/fips/203/final") {
		t.Errorf("output missing source URL: %s", body)
	}
}

func TestRenderPqcSynonyms_WatchlistAliasesOnly(t *testing.T) {
	// Self-mappings would break TestSynonyms_NoCircularReferences in
	// internal/analysis/pqc/catalog_test.go (which requires synonym keys
	// and canonical keys to be disjoint), so the generator must NOT emit
	// them — Classify falls through to canonical lookup on synonym miss.
	canonicals := map[string]pqcEntry{
		"rsa":        {Canonical: "rsa"},
		"ml-kem-768": {Canonical: "ml-kem-768"},
	}
	syns := []synonymCategory{
		{Canonical: "ml-kem-768", Aliases: []string{"kyber768"}},
	}
	body := renderPqcSynonyms(syns, canonicals)
	if strings.Contains(body, `"rsa": "rsa"`) {
		t.Errorf("unexpected self-mapping for rsa in synonyms: %s", body)
	}
	if strings.Contains(body, `"ml-kem-768": "ml-kem-768"`) {
		t.Errorf("unexpected self-mapping for ml-kem-768 in synonyms: %s", body)
	}
	if !strings.Contains(body, `"kyber768": "ml-kem-768"`) {
		t.Errorf("missing kyber768 alias: %s", body)
	}
}

func TestMergeAllPqcSources_NistFipsPresent(t *testing.T) {
	wl := &pqcWatchlist{}
	merged := mergeAllPqcSources(wl)
	if _, ok := merged["ml-kem-768"]; !ok {
		t.Error("merge missing ml-kem-768 (NIST FIPS)")
	}
	if _, ok := merged["x25519-ml-kem-768"]; !ok {
		t.Error("merge missing x25519-ml-kem-768 (IETF hybrid)")
	}
}

func TestMergeAllPqcSources_ClassicalDefaultsToManual(t *testing.T) {
	wl := &pqcWatchlist{
		Classical: []pqcEntry{
			{Canonical: "rsa", Status: "QuantumVulnerable", Category: "asymmetric"},
		},
	}
	merged := mergeAllPqcSources(wl)
	rsa := merged["rsa"]
	if rsa.Source != "manual" {
		t.Errorf("classical rsa.Source = %q, want \"manual\"", rsa.Source)
	}
}
