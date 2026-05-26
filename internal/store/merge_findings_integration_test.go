//go:build integration

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
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// TestMergeFindingsForAsset covers the three required scenarios:
//  1. Empty case — no existing row → INSERT with new findings only.
//  2. Merge case — existing row with rule X and rule Y findings; merging new rule X
//     findings preserves rule Y and replaces rule X.
//  3. Idempotent re-emit — calling MergeFindingsForAsset twice with the same
//     finding produces exactly one copy (not duplicated).
func TestMergeFindingsForAsset(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	const (
		assetType = "host"
		assetID   = "test-host-merge-uuid"
		ruleX     = "RULE-X"
		ruleY     = "RULE-Y"
	)

	findingX1 := model.HealthFinding{
		RuleID:   ruleX,
		Title:    "Rule X finding v1",
		Severity: model.SeverityHigh,
		Category: model.CategoryGovernance,
		Detail:   "detail x1",
	}
	findingX2 := model.HealthFinding{
		RuleID:   ruleX,
		Title:    "Rule X finding v2",
		Severity: model.SeverityHigh,
		Category: model.CategoryGovernance,
		Detail:   "detail x2",
	}
	findingY := model.HealthFinding{
		RuleID:   ruleY,
		Title:    "Rule Y finding",
		Severity: model.SeverityMedium,
		Category: model.CategoryKeyStrength,
		Detail:   "detail y",
	}

	t.Run("empty case — INSERT with new findings only", func(t *testing.T) {
		// No pre-existing row. MergeFindingsForAsset should INSERT a row
		// containing exactly the supplied findings.
		if err := st.MergeFindingsForAsset(ctx, assetType, assetID+"-empty", []model.HealthFinding{findingX1}); err != nil {
			t.Fatalf("MergeFindingsForAsset: %v", err)
		}

		report, err := st.GetAssetHealthReport(ctx, assetType, assetID+"-empty")
		if err != nil {
			t.Fatalf("GetAssetHealthReport: %v", err)
		}
		if report == nil {
			t.Fatal("expected a report, got nil")
		}
		if len(report.Findings) != 1 {
			t.Fatalf("findings count = %d, want 1; findings = %+v", len(report.Findings), report.Findings)
		}
		if report.Findings[0].RuleID != ruleX {
			t.Errorf("finding[0].RuleID = %q, want %q", report.Findings[0].RuleID, ruleX)
		}
		if report.Findings[0].Detail != findingX1.Detail {
			t.Errorf("finding[0].Detail = %q, want %q", report.Findings[0].Detail, findingX1.Detail)
		}
	})

	t.Run("merge case — rule X replaced, rule Y preserved", func(t *testing.T) {
		aid := assetID + "-merge"

		// Seed the row with rule X v1 + rule Y findings via SaveAssetHealthReport.
		seedReport := &model.AssetHealthReport{
			AssetType: assetType,
			AssetID:   aid,
			Findings:  []model.HealthFinding{findingX1, findingY},
		}
		if err := st.SaveAssetHealthReport(ctx, seedReport); err != nil {
			t.Fatalf("seed SaveAssetHealthReport: %v", err)
		}

		// Merge: replace rule X with v2, leave rule Y untouched.
		if err := st.MergeFindingsForAsset(ctx, assetType, aid, []model.HealthFinding{findingX2}); err != nil {
			t.Fatalf("MergeFindingsForAsset: %v", err)
		}

		report, err := st.GetAssetHealthReport(ctx, assetType, aid)
		if err != nil {
			t.Fatalf("GetAssetHealthReport: %v", err)
		}
		if report == nil {
			t.Fatal("expected a report, got nil")
		}
		if len(report.Findings) != 2 {
			t.Fatalf("findings count = %d, want 2; findings = %+v", len(report.Findings), report.Findings)
		}

		// Both rule_ids must be present exactly once.
		byRule := make(map[string]model.HealthFinding, 2)
		for _, f := range report.Findings {
			byRule[f.RuleID] = f
		}

		xFound, ok := byRule[ruleX]
		if !ok {
			t.Fatalf("rule X finding missing after merge; got %+v", report.Findings)
		}
		if xFound.Detail != findingX2.Detail {
			t.Errorf("rule X detail = %q, want %q (old detail was %q)", xFound.Detail, findingX2.Detail, findingX1.Detail)
		}

		if _, ok := byRule[ruleY]; !ok {
			t.Fatalf("rule Y finding was clobbered after merge; got %+v", report.Findings)
		}
	})

	t.Run("idempotent re-emit — no duplication", func(t *testing.T) {
		aid := assetID + "-idempotent"

		// First emit.
		if err := st.MergeFindingsForAsset(ctx, assetType, aid, []model.HealthFinding{findingX1}); err != nil {
			t.Fatalf("first MergeFindingsForAsset: %v", err)
		}
		// Second emit with the identical finding.
		if err := st.MergeFindingsForAsset(ctx, assetType, aid, []model.HealthFinding{findingX1}); err != nil {
			t.Fatalf("second MergeFindingsForAsset: %v", err)
		}

		report, err := st.GetAssetHealthReport(ctx, assetType, aid)
		if err != nil {
			t.Fatalf("GetAssetHealthReport: %v", err)
		}
		if report == nil {
			t.Fatal("expected a report, got nil")
		}
		if len(report.Findings) != 1 {
			t.Fatalf("findings count = %d after idempotent re-emit, want 1; findings = %+v", len(report.Findings), report.Findings)
		}
		if report.Findings[0].RuleID != ruleX {
			t.Errorf("finding[0].RuleID = %q, want %q", report.Findings[0].RuleID, ruleX)
		}
	})
}
