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

// TestAggregateTopRules_IncludesScannerFindings pins the correctness
// guarantee that repo-scanner findings contribute to the "top
// contributing rules" ranking on application detail pages.
//
// Root cause: the scanner writes a JSON array of
// internal/scanner/finding.FindingRecord into
// asset_health_reports.findings. Its schema is a superset of
// model.HealthFinding on (rule_id, severity) but lacks
// title/category/detail/remediation/deduction. A permissive
// json.Unmarshal into []HealthFinding succeeds but leaves Deduction=0,
// so aggregateTopRules's `if f.Deduction <= 0 { continue }` silently
// drops every scanner finding.
//
// Before the v1.3.1 fix this test FAILS (aggregate length == 0 for
// scanner-shape input). After the fix scanner findings surface with a
// synthesized deduction derived from their severity.
func TestAggregateTopRules_IncludesScannerFindings(t *testing.T) {
	// A scanner-shape findings column as it lives in Postgres today:
	// produced by convertFindingsIntoReport() in
	// internal/scanner/pipeline/pipeline.go which marshals a
	// []finding.FindingRecord.
	scannerJSON := []byte(`[
		{
			"rule_id": "B1-PEM-PRIVKEY",
			"severity": "Critical",
			"bucket": "B1",
			"path": "deploy/keys/prod.pem",
			"detected_by": ["det:b1-pem-privkey"],
			"confidence": 1.0,
			"scan_id": "scan-uuid-1"
		},
		{
			"rule_id": "B3-MD5",
			"severity": "High",
			"bucket": "B3",
			"path": "src/hash.go",
			"detected_by": ["det:b3-md5"],
			"confidence": 1.0,
			"scan_id": "scan-uuid-1"
		}
	]`)

	// Exercise the real store read path (adaptFindings) rather than
	// calling json.Unmarshal directly — the silent-swallow bug is in
	// field mapping, not JSON parsing, so the test must go through the
	// adapter to be meaningful.
	findings := adaptFindings(scannerJSON)
	if len(findings) != 2 {
		t.Fatalf("expected 2 adapted findings, got %d", len(findings))
	}

	rows := []ScopeAssetRow{{
		AssetType: "repository",
		AssetID:   "repo-uuid-1",
		Report: model.AssetHealthReport{
			Grade:    "F",
			Score:    40,
			Findings: findings,
		},
	}}

	contribs := aggregateTopRules(rows)
	if len(contribs) == 0 {
		t.Fatalf("expected scanner findings to surface in top-contributing rules, got 0 — repo-scanner findings are invisible to /applications/{tag} score-delta decomposition")
	}

	seen := map[string]RuleContribution{}
	for _, c := range contribs {
		seen[c.RuleID] = c
	}

	b1, ok := seen["B1-PEM-PRIVKEY"]
	if !ok {
		t.Errorf("expected B1-PEM-PRIVKEY (Critical committed-key material) in contributions, got keys=%v", keysOf(seen))
	} else {
		if b1.TotalDeduction <= 0 {
			t.Errorf("B1-PEM-PRIVKEY TotalDeduction = %d; expected > 0 so it affects top-rules ranking", b1.TotalDeduction)
		}
		if b1.Severity != "Critical" {
			t.Errorf("B1-PEM-PRIVKEY Severity = %q; expected %q", b1.Severity, "Critical")
		}
	}

	b3, ok := seen["B3-MD5"]
	if !ok {
		t.Errorf("expected B3-MD5 (High crypto-API-misuse) in contributions, got keys=%v", keysOf(seen))
	} else {
		if b3.TotalDeduction <= 0 {
			t.Errorf("B3-MD5 TotalDeduction = %d; expected > 0", b3.TotalDeduction)
		}
		if b1, ok := seen["B1-PEM-PRIVKEY"]; ok && b3.TotalDeduction >= b1.TotalDeduction {
			t.Errorf("expected Critical > High for synthesized deductions; got B1=%d B3=%d", b1.TotalDeduction, b3.TotalDeduction)
		}
	}
}

// TestAggregateTopRules_HealthFindingsUnchanged pins that the normal
// scorer-produced HealthFinding path (explicit Deduction set by e.g.
// the cert scorer) still works unchanged after the scanner-adapter
// fix. Regression guard — we must not double-count or drop these.
func TestAggregateTopRules_HealthFindingsUnchanged(t *testing.T) {
	rows := []ScopeAssetRow{{
		AssetType: "certificate",
		AssetID:   "fp-abc",
		Report: model.AssetHealthReport{
			Grade: "C",
			Score: 65,
			Findings: []model.HealthFinding{
				{RuleID: "EXP-002", Title: "Expired", Severity: model.SeverityCritical, Category: model.CategoryExpiration, Deduction: 50},
				{RuleID: "KEY-001", Title: "Weak key", Severity: model.SeverityHigh, Category: model.CategoryKeyStrength, Deduction: 30},
				{RuleID: "KEY-005", Title: "Positive indicator", Severity: model.SeverityInfo, Category: model.CategoryKeyStrength, Deduction: 0},
			},
		},
	}}

	contribs := aggregateTopRules(rows)
	if len(contribs) != 2 {
		t.Fatalf("expected 2 contribs (KEY-005 excluded as Deduction=0), got %d", len(contribs))
	}
	if contribs[0].RuleID != "EXP-002" {
		t.Errorf("expected EXP-002 first (higher deduction 50 > 30), got %q", contribs[0].RuleID)
	}
	if contribs[0].TotalDeduction != 50 {
		t.Errorf("EXP-002 TotalDeduction = %d; expected 50 (unchanged)", contribs[0].TotalDeduction)
	}
}

func keysOf(m map[string]RuleContribution) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
