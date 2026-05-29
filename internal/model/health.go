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

package model

import "time"

type Grade string

const (
	GradeAPlus Grade = "A+"
	GradeA     Grade = "A"
	GradeB     Grade = "B"
	GradeC     Grade = "C"
	GradeD     Grade = "D"
	GradeF     Grade = "F"
)

type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
)

type FindingCategory string

const (
	CategoryExpiration    FindingCategory = "expiration"
	CategoryKeyStrength   FindingCategory = "key_strength"
	CategorySignature     FindingCategory = "signature"
	CategoryChain         FindingCategory = "chain"
	CategoryRevocation    FindingCategory = "revocation"
	CategoryTransparency  FindingCategory = "transparency"
	CategoryProtocol      FindingCategory = "protocol"
	CategoryCipher        FindingCategory = "cipher"
	CategoryWildcard      FindingCategory = "wildcard"
	CategoryAgility       FindingCategory = "agility"
	CategoryGovernance    FindingCategory = "governance"
)

type HealthFinding struct {
	RuleID      string          `json:"rule_id"`
	Title       string          `json:"title"`
	Severity    Severity        `json:"severity"`
	Category    FindingCategory `json:"category"`
	Detail      string          `json:"detail"`
	Remediation string          `json:"remediation"`
	Deduction   int             `json:"deduction"`
	ImmediateFail bool          `json:"immediate_fail,omitempty"`

	// ScopeDeadline is the date by which this finding must be remediated.
	// Populated by scorers for deadline-eligible rule families (cert
	// expiry uses cert.NotAfter; library CVE rules use scored_at +
	// severity-based interval). Nil when no deadline applies.
	// Powers AQ-AP-02 (docs/analyst-question-catalog.md §Domain 9).
	ScopeDeadline *time.Time `json:"scope_deadline,omitempty"`

	// Evidence is a free-form map for finding-specific provenance data.
	// For catalog-derived findings (LIB-003, LIB-005), includes "source_url"
	// pointing at the upstream catalog record so operators can click through
	// to verify the deduction. Matches the pattern at internal/model/lineage.go.
	Evidence map[string]any `json:"evidence,omitempty"`
}

type HealthReport struct {
	CertFingerprint string         `json:"cert_fingerprint"`
	Grade           Grade          `json:"grade"`
	Score           int            `json:"score"`
	Findings        []HealthFinding `json:"findings"`
	ScoredAt        time.Time      `json:"scored_at"`
}

// ScoreToGrade converts a numeric score to a letter grade.
func ScoreToGrade(score int, immediateFail bool) Grade {
	if immediateFail || score < 20 {
		return GradeF
	}
	if score < 50 {
		return GradeD
	}
	if score < 70 {
		return GradeC
	}
	if score < 85 {
		return GradeB
	}
	if score < 95 {
		return GradeA
	}
	return GradeAPlus
}
