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

package cbom

import (
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestBuildCipherFlagProps_Namespace(t *testing.T) {
	r := &model.AssetHealthReport{
		Grade: "B", Score: 80, RiskScore: 30,
		PQCStatus: "safe", ScoredAt: time.Now(),
		Compliance:  map[string]string{},
		RiskFactors: map[string]int{},
	}
	props := buildCipherFlagProps(r)
	for _, p := range props {
		if !strings.HasPrefix(p.Name, "cipherflag:") {
			t.Errorf("property %q missing cipherflag: namespace", p.Name)
		}
	}
}

func TestBuildCipherFlagProps_IntegerStringification(t *testing.T) {
	r := &model.AssetHealthReport{
		Grade: "F", Score: 10, RiskScore: 99,
		PQCStatus: "vulnerable", ScoredAt: time.Now(),
		Compliance:  map[string]string{},
		RiskFactors: map[string]int{"algo_weakness": 75},
	}
	props := buildCipherFlagProps(r)
	propMap := make(map[string]string, len(props))
	for _, p := range props {
		propMap[p.Name] = p.Value
	}
	if propMap["cipherflag:score"] != "10" {
		t.Errorf("score = %q, want \"10\"", propMap["cipherflag:score"])
	}
	if propMap["cipherflag:risk_score"] != "99" {
		t.Errorf("risk_score = %q, want \"99\"", propMap["cipherflag:risk_score"])
	}
	if propMap["cipherflag:risk_factor.algo_weakness"] != "75" {
		t.Errorf("risk factor missing or wrong: %v", propMap)
	}
}

func TestBuildCipherFlagProps_EmptyMaps(t *testing.T) {
	r := &model.AssetHealthReport{
		Grade: "A", Score: 100, RiskScore: 0,
		PQCStatus: "safe", ScoredAt: time.Now(),
		Compliance:  nil,
		RiskFactors: nil,
		Findings:    nil,
	}
	// Should not panic
	props := buildCipherFlagProps(r)
	if len(props) < 5 {
		t.Errorf("expected at least 5 core properties, got %d", len(props))
	}
}
