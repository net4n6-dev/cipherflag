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
