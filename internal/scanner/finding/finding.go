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

// Package finding defines the canonical scanner finding record. Detectors
// produce FindingRecord values; the pipeline merges + emits them as JSONB
// entries inside asset_health_reports.findings (spec §7 amended schema).
package finding

// Severity tiers (spec §6).
const (
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
	SeverityInfo     = "Info"
)

// Buckets (spec §6).
const (
	BucketB1 = "B1" // committed key material
	BucketB3 = "B3" // crypto API usage -> CBOM (6.1c)
	BucketB4 = "B4" // TLS / crypto config files
	BucketB5 = "B5" // binary-level crypto library detection (6.2b)
)

var validSeverities = map[string]struct{}{
	SeverityCritical: {}, SeverityHigh: {}, SeverityMedium: {},
	SeverityLow: {}, SeverityInfo: {},
}

func IsValidSeverity(s string) bool {
	_, ok := validSeverities[s]
	return ok
}

// FindingRecord is the canonical JSONB schema for a single finding row.
// Shape matches spec §7 (amended 2026-04-14b). All fields that are empty
// for deterministic-only findings are omitted via `omitempty`.
type FindingRecord struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Bucket      string `json:"bucket"`
	Path        string `json:"path"`
	LineRange   [2]int `json:"line_range,omitempty"` // 1-based inclusive; [0,0] omits
	ByteRange   [2]int `json:"byte_range,omitempty"` // 0-based half-open [start, end); [0,0] omits
	CommitSHA   string `json:"commit_sha,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // SHA-256 SPKI for certs, OpenSSH-SHA256 for SSH keys

	DetectedBy        []string `json:"detected_by"`       // ['det:<rule_id>', 'llm:<prompt_id>@<version>']
	ModelAttribution  string   `json:"model_attribution"` // 'deterministic' | 'anthropic:...' | ...
	Confidence        float64  `json:"confidence"`
	LLMTokensSpent    int      `json:"llm_tokens_spent,omitempty"`
	PromptID          string   `json:"prompt_id,omitempty"`
	PromptVersion     string   `json:"prompt_version,omitempty"`
	PromptContentHash string   `json:"prompt_content_hash,omitempty"`

	LicenseID string `json:"license_id,omitempty"`
	ScanID    string `json:"scan_id"`

	// CBOM carries algorithm metadata for B3 findings; zero for B1/B4.
	// Populated by 6.1c.
	CBOM *CBOMInfo `json:"cbom,omitempty"`

	// Evidence is detector-specific extra context (e.g. filename inside a JAR,
	// matched-line excerpt for a config). Stays optional; readers treat as opaque.
	Evidence map[string]any `json:"evidence,omitempty"`
}

// CBOMInfo is populated by B3 detectors in 6.1c. Included here so the
// FindingRecord shape is stable from v1 onward — zero-value today.
type CBOMInfo struct {
	Algorithm          string       `json:"algorithm,omitempty"`
	Mode               string       `json:"mode,omitempty"`
	Padding            string       `json:"padding,omitempty"`
	KeySizeBits        int          `json:"key_size_bits,omitempty"`
	OID                string       `json:"oid,omitempty"`
	EvidenceOccurrence []Occurrence `json:"evidence_occurrences,omitempty"`
}

type Occurrence struct {
	Path      string `json:"path"`
	Line      int    `json:"line"`
	CommitSHA string `json:"commit_sha,omitempty"`
}
