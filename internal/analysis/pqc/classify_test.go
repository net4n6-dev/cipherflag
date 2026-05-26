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

package pqc

import (
	"testing"
)

func TestClassify_KnownCanonical(t *testing.T) {
	got := Classify("rsa")
	want := Classification{
		Status:    QuantumVulnerable,
		Canonical: "rsa",
		Category:  CategoryAsymmetric,
	}
	if got != want {
		t.Errorf("Classify(rsa) = %+v, want %+v", got, want)
	}
}

func TestClassify_KnownSynonym(t *testing.T) {
	got := Classify("ssh-rsa")
	want := Classification{
		Status:    QuantumVulnerable,
		Canonical: "rsa",
		Category:  CategoryAsymmetric,
	}
	if got != want {
		t.Errorf("Classify(ssh-rsa) = %+v, want %+v", got, want)
	}
}

func TestClassify_UnknownReturnsUnknown(t *testing.T) {
	got := Classify("fake-algorithm-xyz")
	want := Classification{Status: QuantumUnknown}
	if got != want {
		t.Errorf("Classify(fake) = %+v, want %+v (all-empty, Unknown)", got, want)
	}
}

func TestClassify_NormalisesCase(t *testing.T) {
	expected := Classify("rsa")

	for _, input := range []string{"RSA", "Rsa", "rSa", "  rsa  ", "\tRSA\n"} {
		if got := Classify(input); got != expected {
			t.Errorf("Classify(%q) = %+v, want %+v (case/whitespace should normalise)", input, got, expected)
		}
	}
}

func TestClassify_EmptyInputReturnsUnknown(t *testing.T) {
	got := Classify("")
	if got.Status != QuantumUnknown {
		t.Errorf("Classify(\"\") = %+v, want QuantumUnknown", got)
	}
	if got.Canonical != "" || got.Category != "" {
		t.Errorf("Classify(\"\") returned non-empty canonical/category: %+v", got)
	}
}

func TestClassify_WhitespaceOnlyReturnsUnknown(t *testing.T) {
	got := Classify("   \t\n  ")
	if got.Status != QuantumUnknown {
		t.Errorf("whitespace-only = %+v, want QuantumUnknown", got)
	}
}

func TestStatusOf_DelegatesToClassify(t *testing.T) {
	if got := StatusOf("rsa"); got != QuantumVulnerable {
		t.Errorf("StatusOf(rsa) = %v, want QuantumVulnerable", got)
	}
	if got := StatusOf("ml-kem-768"); got != QuantumSafe {
		t.Errorf("StatusOf(ml-kem-768) = %v, want QuantumSafe", got)
	}
	if got := StatusOf("x25519-ml-kem-768"); got != QuantumHybrid {
		t.Errorf("StatusOf(x25519-ml-kem-768) = %v, want QuantumHybrid", got)
	}
	if got := StatusOf("aes-128"); got != QuantumWeakened {
		t.Errorf("StatusOf(aes-128) = %v, want QuantumWeakened", got)
	}
	if got := StatusOf("not-a-real-algorithm"); got != QuantumUnknown {
		t.Errorf("StatusOf(not-a-real) = %v, want QuantumUnknown", got)
	}
}

func TestClassify_SynonymResolvesToCanonical(t *testing.T) {
	// ssh-ed25519 is a synonym for ed25519 — the result's Canonical field
	// must be the canonical name ("ed25519"), not the variant spelling.
	got := Classify("ssh-ed25519")
	if got.Canonical != "ed25519" {
		t.Errorf("Classify(ssh-ed25519).Canonical = %q, want ed25519", got.Canonical)
	}
}

func TestClassify_KyberResolvesToMLKEM(t *testing.T) {
	// Pre-standardisation PQC names should resolve to their NIST-standard
	// canonical form.
	got := Classify("kyber768")
	if got.Canonical != "ml-kem-768" {
		t.Errorf("Classify(kyber768).Canonical = %q, want ml-kem-768", got.Canonical)
	}
	if got.Status != QuantumSafe {
		t.Errorf("Classify(kyber768).Status = %v, want QuantumSafe", got.Status)
	}
}
