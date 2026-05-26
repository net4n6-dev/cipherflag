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
	"encoding/json"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// adaptFindings parses the asset_health_reports.findings JSONB column
// and produces a model.HealthFinding slice. It understands two on-disk
// shapes that have accumulated over the project's life:
//
//  1. Native HealthFinding rows written by the scoring engine (cert
//     scorer, library scorer, protocol scorer, etc.). These populate
//     rule_id / title / severity / category / detail / remediation /
//     deduction / scope_deadline directly.
//
//  2. Scanner FindingRecord rows written by the Git-repo scanner
//     (internal/scanner/pipeline/pipeline.go::convertFindingsIntoReport).
//     These populate rule_id / severity / bucket / path / scan_id /
//     detected_by but lack title / category / detail / remediation /
//     deduction. They are detected by the presence of the `bucket` key.
//
// For shape (2) we synthesize the missing HealthFinding fields so
// scanner findings participate in downstream ranking (top-contributing
// rules on /applications/{tag}, evidence-pack findings.json) instead
// of silently dropping out at `if Deduction <= 0 { continue }` gates.
// The synthesized deduction is derived from severity; it does not
// alter the stored score (which the scanner already computed at write
// time) — it only determines rank-ordering among peer findings.
//
// Unparseable input returns nil rather than erroring; individual rows
// that are unparseable are skipped. One malformed finding must not
// break an application's detail page.
func adaptFindings(raw []byte) []model.HealthFinding {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil
	}
	out := make([]model.HealthFinding, 0, len(arr))
	for _, m := range arr {
		hf := mapOneFinding(m)
		if hf.RuleID == "" {
			continue
		}
		out = append(out, hf)
	}
	return out
}

func mapOneFinding(m map[string]any) model.HealthFinding {
	hf := model.HealthFinding{}
	if s, ok := m["rule_id"].(string); ok {
		hf.RuleID = s
	}
	if s, ok := m["title"].(string); ok {
		hf.Title = s
	}
	if s, ok := m["severity"].(string); ok {
		hf.Severity = model.Severity(s)
	}
	if s, ok := m["category"].(string); ok {
		hf.Category = model.FindingCategory(s)
	}
	if s, ok := m["detail"].(string); ok {
		hf.Detail = s
	}
	if s, ok := m["remediation"].(string); ok {
		hf.Remediation = s
	}
	if n, ok := m["deduction"].(float64); ok {
		hf.Deduction = int(n)
	}
	if b, ok := m["immediate_fail"].(bool); ok {
		hf.ImmediateFail = b
	}
	if s, ok := m["scope_deadline"].(string); ok && s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			hf.ScopeDeadline = &t
		}
	}

	// Scanner-shape enrichment — only fills blanks, never overwrites.
	if bucket, ok := m["bucket"].(string); ok && bucket != "" {
		if hf.Title == "" {
			hf.Title = hf.RuleID
		}
		if hf.Category == "" {
			hf.Category = categoryFromBucket(bucket)
		}
		if hf.Detail == "" {
			if p, ok := m["path"].(string); ok {
				hf.Detail = p
			}
		}
		if hf.Deduction == 0 {
			hf.Deduction = deductionFromSeverity(hf.Severity)
		}
		if hf.Remediation == "" {
			hf.Remediation = remediationFromBucket(bucket)
		}
	}
	return hf
}

// categoryFromBucket maps scanner bucket codes to HealthFinding
// categories so scanner findings group with semantically-related
// scoring-engine findings in downstream aggregation.
//
//	B1 — committed key material → governance (hygiene / ops issue)
//	B3 — crypto-API usage (MD5/SHA-1/DES calls) → cipher
//	B4 — TLS/crypto config files → protocol
//	B5 — binary-level crypto library detection → cipher
func categoryFromBucket(bucket string) model.FindingCategory {
	switch bucket {
	case "B1":
		return model.CategoryGovernance
	case "B3":
		return model.CategoryCipher
	case "B4":
		return model.CategoryProtocol
	case "B5":
		return model.CategoryCipher
	}
	return ""
}

// deductionFromSeverity synthesizes a ranking-stable point impact for
// scanner findings. Values parallel the scoring-engine's own severity
// tiers (50/30/15/5/0) so mixed aggregations across scanner + scorer
// findings rank by true impact rather than by which subsystem wrote
// them. The value is not persisted — read-time only.
func deductionFromSeverity(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 50
	case model.SeverityHigh:
		return 30
	case model.SeverityMedium:
		return 15
	case model.SeverityLow:
		return 5
	case model.SeverityInfo:
		return 0
	}
	return 0
}

// remediationFromBucket produces a short operator-actionable hint for
// scanner findings that lack a scorer-written remediation string.
// Generic-by-design: specific remediation requires a rule-level
// catalog (follow-on) — this is a safety net so the evidence-pack
// findings bundle never emits an empty remediation cell for scanner
// findings.
func remediationFromBucket(bucket string) string {
	switch bucket {
	case "B1":
		return "Rotate the exposed key material, purge from git history (git-filter-repo / BFG), and add the path pattern to secret-scanning baseline."
	case "B3":
		return "Replace the weak/legacy algorithm call with a modern equivalent. See the rule's CBOM occurrence list for call sites."
	case "B4":
		return "Harden the config file to remove weak ciphers / protocols. Cross-reference the vendor's current baseline (e.g., Mozilla SSL Config Generator for nginx/apache)."
	case "B5":
		return "Upgrade or replace the detected library with a supported version that meets the project's crypto-posture baseline."
	}
	return ""
}
