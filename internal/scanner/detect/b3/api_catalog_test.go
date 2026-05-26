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

package b3

import (
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// TestCatalog_AllEntriesValid checks the catalog invariants: every rule
// has a non-empty rule_id, severity in the valid set, language in
// {go, python, java}, and at least one identifying field (Import or
// ClassName) populated.
func TestCatalog_AllEntriesValid(t *testing.T) {
	if len(Catalog) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := map[string]bool{}
	for i, r := range Catalog {
		if r.RuleID == "" {
			t.Errorf("entry %d: empty rule_id", i)
		}
		if !finding.IsValidSeverity(r.Severity) {
			t.Errorf("entry %d (%s): invalid severity %q", i, r.RuleID, r.Severity)
		}
		switch r.Language {
		case LangGo, LangPython, LangJava:
		default:
			t.Errorf("entry %d (%s): invalid language %q", i, r.RuleID, r.Language)
		}
		if r.Import == "" && r.ClassName == "" {
			t.Errorf("entry %d (%s): need Import or ClassName", i, r.RuleID)
		}
		key := string(r.Language) + "|" + r.RuleID + "|" + r.Import + "|" + r.ClassName + "|" + r.Selector + "|" + r.AlgorithmString + "|" + r.Mode
		if seen[key] {
			t.Errorf("entry %d (%s): duplicate key %q", i, r.RuleID, key)
		}
		seen[key] = true
	}
}

// TestCatalog_CoversBaselineWeakAlgorithms ensures the catalog has at
// least one rule for each baseline weak algorithm we promised in the spec.
func TestCatalog_CoversBaselineWeakAlgorithms(t *testing.T) {
	want := map[string]bool{
		"CRYPTO-WEAK-HASH-MD5":    false,
		"CRYPTO-WEAK-HASH-SHA1":   false,
		"CRYPTO-WEAK-CIPHER-DES":  false,
		"CRYPTO-WEAK-CIPHER-3DES": false,
		"CRYPTO-WEAK-CIPHER-RC4":  false,
		"CRYPTO-WEAK-MODE-ECB":    false,
	}
	for _, r := range Catalog {
		if _, ok := want[r.RuleID]; ok {
			want[r.RuleID] = true
		}
	}
	for ruleID, found := range want {
		if !found {
			t.Errorf("baseline rule %s not present in catalog", ruleID)
		}
	}
}

// TestRulesByLanguage_Filters returns only entries for the requested language.
func TestRulesByLanguage_Filters(t *testing.T) {
	goRules := RulesByLanguage(LangGo)
	for _, r := range goRules {
		if r.Language != LangGo {
			t.Errorf("RulesByLanguage(go) returned %v", r.Language)
		}
	}
	if len(goRules) == 0 {
		t.Fatal("expected at least one Go rule")
	}
}
