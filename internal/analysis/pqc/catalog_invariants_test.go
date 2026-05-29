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
	"net/url"
	"strings"
	"testing"
)

func TestCatalog_AllEntriesHaveCanonicalAndStatus(t *testing.T) {
	for key, c := range canonical {
		if c.Canonical == "" {
			t.Errorf("entry %q has empty Canonical", key)
		}
		if c.Status == "" {
			t.Errorf("entry %q has empty Status", key)
		}
	}
}

func TestSynonyms_AllPointToValidCanonical(t *testing.T) {
	for alias, target := range synonyms {
		if _, ok := canonical[target]; !ok {
			t.Errorf("synonym %q → %q but %q is not in canonical map", alias, target, target)
		}
	}
}

func TestCatalog_AllSourceURLsWellFormed(t *testing.T) {
	for key, c := range canonical {
		if c.Source == "" || c.Source == "manual" {
			continue
		}
		if !strings.HasPrefix(c.Source, "https://") {
			t.Errorf("entry %q has non-https Source: %q", key, c.Source)
			continue
		}
		if _, err := url.Parse(c.Source); err != nil {
			t.Errorf("entry %q has unparseable Source %q: %v", key, c.Source, err)
		}
	}
}

func TestCatalog_AllStatusAndCategoryEnumerated(t *testing.T) {
	validStatus := map[QuantumStatus]bool{
		QuantumVulnerable: true,
		QuantumWeakened:   true,
		QuantumSafe:       true,
		QuantumHybrid:     true,
		QuantumUnknown:    true,
	}
	validCategory := map[Category]bool{
		CategoryAsymmetric: true,
		CategorySymmetric:  true,
		CategoryHash:       true,
		CategorySignature:  true,
		CategoryKEX:        true,
		CategoryKDF:        true,
		CategoryPQCKEM:     true,
		CategoryPQCSig:     true,
	}
	for key, c := range canonical {
		if !validStatus[c.Status] {
			t.Errorf("entry %q has unknown Status: %q", key, c.Status)
		}
		if c.Category != "" && !validCategory[c.Category] {
			t.Errorf("entry %q has unknown Category: %q", key, c.Category)
		}
	}
}
