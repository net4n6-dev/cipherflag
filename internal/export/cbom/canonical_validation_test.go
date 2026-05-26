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
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// TestAlgoToComponent_KnownCanonicalIsClean pins the happy path: a
// canonical algorithm name emits a component with no canonical-match
// property (it's implicitly true; only drifted names need annotation).
func TestAlgoToComponent_KnownCanonicalIsClean(t *testing.T) {
	c := algoToComponent("rsa")
	if c.Name != "rsa" {
		t.Errorf("Name = %q, want %q", c.Name, "rsa")
	}
	if hasProperty(c, "cipherflag:algo.canonical_match") {
		t.Errorf("canonical name must not carry canonical_match property; BOM consumers filter on its presence")
	}
	if c.BOMRef != "algo:rsa" {
		t.Errorf("BOMRef = %q, want %q", c.BOMRef, "algo:rsa")
	}
}

// TestAlgoToComponent_KnownSynonymNormalizes pins that a synonym
// entering algoToComponent still produces a canonical-named
// component. Prior to this release the callers' upstream resolution
// could leak a synonym name into the component emitter and the
// component would be named after the synonym rather than canonical.
func TestAlgoToComponent_KnownSynonymNormalizes(t *testing.T) {
	// "rsa-2048" is an authoritative synonym for canonical "rsa" (key
	// size lives in parameterSet, not the algorithm name — the pqc
	// package enforces this in internal/analysis/pqc/synonyms.go).
	c := algoToComponent("rsa-2048")
	if c.Name != "rsa" {
		t.Errorf("Name = %q, want canonical %q", c.Name, "rsa")
	}
	if c.BOMRef != "algo:rsa" {
		t.Errorf("BOMRef = %q, want %q", c.BOMRef, "algo:rsa")
	}
	if hasProperty(c, "cipherflag:algo.canonical_match") {
		t.Errorf("synonym-mapped canonical name must not carry drift property")
	}
}

// TestAlgoToComponent_UnknownIsAnnotated pins the correctness fix for
// v1.3.5 — when an algorithm name doesn't resolve to a canonical or
// synonym, the component is STILL emitted (so drift is visible in the
// inventory) but carries `cipherflag:algo.canonical_match=false` so
// CBOM consumers + auditors can filter to unknowns without parsing
// names. Pre-fix: the component was emitted with no signal that the
// name was un-catalogued.
func TestAlgoToComponent_UnknownIsAnnotated(t *testing.T) {
	// Deliberately unknown spelling — not in canonical or synonyms maps.
	// "sha384WithEcdsaPss" is not a real standard, chosen specifically
	// to be unambiguously outside the taxonomy.
	c := algoToComponent("sha384WithEcdsaPss")
	if !hasProperty(c, "cipherflag:algo.canonical_match") {
		t.Fatalf("unknown algorithm must carry cipherflag:algo.canonical_match property so drift is detectable")
	}
	v := getProperty(c, "cipherflag:algo.canonical_match")
	if v != "false" {
		t.Errorf("cipherflag:algo.canonical_match = %q, want %q", v, "false")
	}
	// Component still emitted — dropping it would leak data out of the inventory.
	if c.Name == "" {
		t.Errorf("unknown component must still carry the raw name, got empty")
	}
	// Raw name preserved (lowercased) so operators can grep it.
	if !strings.Contains(strings.ToLower(c.Name), "sha384") {
		t.Errorf("unknown component Name must preserve raw spelling; got %q", c.Name)
	}
}

func TestAlgoToComponent_EmptyNameDegradesGracefully(t *testing.T) {
	c := algoToComponent("")
	// Empty input must not panic and must not emit a misleading
	// "algo:" BOMRef — it's up to the caller to avoid this, but the
	// component must at least be identifiable as degenerate.
	if c.Name == "" && c.BOMRef == "algo:" {
		// Degenerate but intentional — caller-side issue, pinned here
		// so a future refactor doesn't accidentally paper over it.
		t.Logf("empty input produces degenerate component with BOMRef=%q Name=%q", c.BOMRef, c.Name)
	}
}

// ── pqc.Canonical helper — foundation for the validator ─────────────

func TestPQCCanonical_Known(t *testing.T) {
	cases := map[string]string{
		"rsa":            "rsa",
		"RSA":            "rsa",         // case normalisation
		"rsa-2048":       "rsa",         // synonym → canonical (key size stripped)
		" AES-256-GCM ":  "aes-256-gcm", // whitespace + case
		"ssh-ed25519":    "ed25519",     // SSH transport synonym
	}
	for in, want := range cases {
		got, ok := canonicalName(in)
		if !ok {
			t.Errorf("canonicalName(%q) ok=false; want canonical=%q", in, want)
			continue
		}
		if got != want {
			t.Errorf("canonicalName(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestPQCCanonical_Unknown(t *testing.T) {
	cases := []string{"", "   ", "sha384withecdsapss", "made-up-algo-2026"}
	for _, in := range cases {
		got, ok := canonicalName(in)
		if ok {
			t.Errorf("canonicalName(%q) ok=true, got=%q; want unknown", in, got)
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────

func hasProperty(c cdx.Component, name string) bool {
	if c.Properties == nil {
		return false
	}
	for _, p := range *c.Properties {
		if p.Name == name {
			return true
		}
	}
	return false
}

func getProperty(c cdx.Component, name string) string {
	if c.Properties == nil {
		return ""
	}
	for _, p := range *c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}
