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

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHealthFinding_EvidenceOmitemptyAndRoundTrips(t *testing.T) {
	// Absent Evidence must not appear in JSON (backward compat).
	bare := HealthFinding{RuleID: "LIB-003", Title: "x", Severity: SeverityHigh}
	b, err := json.Marshal(bare)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "evidence") {
		t.Errorf("empty Evidence leaked into JSON: %s", b)
	}

	// Present Evidence round-trips under the "evidence" key.
	withEv := HealthFinding{RuleID: "LIB-003", Evidence: map[string]any{"source_url": "https://endoflife.date/openssl"}}
	b2, _ := json.Marshal(withEv)
	if !strings.Contains(string(b2), `"evidence"`) || !strings.Contains(string(b2), "endoflife.date/openssl") {
		t.Errorf("Evidence missing from JSON: %s", b2)
	}
	var back HealthFinding
	if err := json.Unmarshal(b2, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Evidence["source_url"] != "https://endoflife.date/openssl" {
		t.Errorf("round-trip lost source_url: %#v", back.Evidence)
	}
}
