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

package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingRecord_JSONRoundTrip(t *testing.T) {
	orig := FindingRecord{
		RuleID:      "KEY-MAT-PRIVKEY-IN-REPO",
		Severity:    SeverityCritical,
		Bucket:      BucketB1,
		Path:        "secrets/prod.key",
		LineRange:   [2]int{1, 28},
		CommitSHA:   "abc123",
		Fingerprint: "sha256:4f3e",

		DetectedBy:       []string{"det:KEY-MAT-PRIVKEY-IN-REPO"},
		ModelAttribution: "deterministic",
		Confidence:       0.98,
		ScanID:           "scan-1",
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got FindingRecord
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RuleID != "KEY-MAT-PRIVKEY-IN-REPO" || got.Severity != SeverityCritical || got.Confidence != 0.98 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestFindingRecord_OmitsZeroOptionalFields(t *testing.T) {
	r := FindingRecord{
		RuleID:   "X",
		Severity: SeverityHigh,
		Bucket:   BucketB4,
		Path:     "a",
	}
	b, _ := json.Marshal(r)
	s := string(b)
	for _, unwanted := range []string{
		`"llm_tokens_spent"`, `"prompt_id"`, `"prompt_version"`,
		`"prompt_content_hash"`, `"license_id"`, `"fingerprint"`,
	} {
		if strings.Contains(s, unwanted) {
			t.Errorf("expected %s omitted, got %s", unwanted, s)
		}
	}
}

func TestSeverity_IsValid(t *testing.T) {
	for _, s := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if !IsValidSeverity(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"", "critical", "FATAL"} {
		if IsValidSeverity(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}
