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

package store

import (
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestAdaptFindings_NativeHealthFindingShape(t *testing.T) {
	raw := []byte(`[
		{
			"rule_id": "EXP-002",
			"title": "Certificate expired",
			"severity": "Critical",
			"category": "expiration",
			"detail": "expired 14 days ago",
			"remediation": "renew immediately",
			"deduction": 50,
			"immediate_fail": true
		}
	]`)
	got := adaptFindings(raw)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.RuleID != "EXP-002" || f.Title != "Certificate expired" || f.Deduction != 50 {
		t.Errorf("scorer fields not round-tripped: %+v", f)
	}
	if !f.ImmediateFail {
		t.Errorf("immediate_fail lost")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("Severity = %q; expected Critical", f.Severity)
	}
	if f.Category != model.CategoryExpiration {
		t.Errorf("Category = %q; expected expiration", f.Category)
	}
}

func TestAdaptFindings_ScannerShapeEnrichment(t *testing.T) {
	raw := []byte(`[
		{"rule_id": "B1-PEM-PRIVKEY", "severity": "Critical", "bucket": "B1", "path": "deploy/prod.pem"},
		{"rule_id": "B3-DES", "severity": "High", "bucket": "B3", "path": "src/legacy.go"},
		{"rule_id": "B4-NGINX-WEAK-CIPHER", "severity": "Medium", "bucket": "B4", "path": "etc/nginx.conf"},
		{"rule_id": "B5-OPENSSL", "severity": "Low", "bucket": "B5", "path": "lib/libssl.so.1"}
	]`)
	got := adaptFindings(raw)
	if len(got) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(got))
	}

	cases := []struct {
		ruleID     string
		wantCat    model.FindingCategory
		wantDeduct int
	}{
		{"B1-PEM-PRIVKEY", model.CategoryGovernance, 50},
		{"B3-DES", model.CategoryCipher, 30},
		{"B4-NGINX-WEAK-CIPHER", model.CategoryProtocol, 15},
		{"B5-OPENSSL", model.CategoryCipher, 5},
	}
	for _, tc := range cases {
		var f *model.HealthFinding
		for i := range got {
			if got[i].RuleID == tc.ruleID {
				f = &got[i]
				break
			}
		}
		if f == nil {
			t.Errorf("rule %q missing from adapted output", tc.ruleID)
			continue
		}
		if f.Category != tc.wantCat {
			t.Errorf("%s Category = %q; want %q", tc.ruleID, f.Category, tc.wantCat)
		}
		if f.Deduction != tc.wantDeduct {
			t.Errorf("%s Deduction = %d; want %d", tc.ruleID, f.Deduction, tc.wantDeduct)
		}
		if f.Title != tc.ruleID {
			t.Errorf("%s Title = %q; want rule_id fallback %q", tc.ruleID, f.Title, tc.ruleID)
		}
		if f.Remediation == "" {
			t.Errorf("%s Remediation empty — evidence pack will show blank cells", tc.ruleID)
		}
	}
}

func TestAdaptFindings_NativeShapeNotRewritten(t *testing.T) {
	// Regression guard: a scoring-engine finding that happens to carry
	// explicit Title/Category/Deduction must not be overwritten by the
	// scanner-shape enrichment path. (In practice scoring-engine
	// findings don't have a `bucket` key, so the enrichment branch is
	// not taken — but pin it.)
	raw := []byte(`[{
		"rule_id": "EXP-002",
		"title": "Explicit title",
		"severity": "Critical",
		"category": "expiration",
		"detail": "explicit detail",
		"remediation": "explicit remediation",
		"deduction": 50
	}]`)
	got := adaptFindings(raw)
	if got[0].Title != "Explicit title" || got[0].Detail != "explicit detail" ||
		got[0].Remediation != "explicit remediation" || got[0].Deduction != 50 {
		t.Errorf("native fields overwritten by enrichment: %+v", got[0])
	}
}

func TestAdaptFindings_NullAndMalformedTolerated(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"null":            []byte(`null`),
		"not-an-array":    []byte(`{"not": "an array"}`),
		"garbage":         []byte(`{{{not json`),
		"missing-rule_id": []byte(`[{"severity": "High", "bucket": "B3"}]`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			got := adaptFindings(raw)
			if got != nil && len(got) != 0 {
				t.Errorf("expected nil or empty for %s, got %d findings", name, len(got))
			}
		})
	}
}

func TestAdaptFindings_ScopeDeadlineRoundTrip(t *testing.T) {
	raw := []byte(`[{
		"rule_id": "EXP-002",
		"severity": "Critical",
		"deduction": 50,
		"scope_deadline": "2026-10-01T00:00:00Z"
	}]`)
	got := adaptFindings(raw)
	if len(got) != 1 || got[0].ScopeDeadline == nil {
		t.Fatalf("scope_deadline lost: %+v", got)
	}
	if got[0].ScopeDeadline.Year() != 2026 || got[0].ScopeDeadline.Month() != 10 {
		t.Errorf("scope_deadline parsed wrong: %v", got[0].ScopeDeadline)
	}
}
