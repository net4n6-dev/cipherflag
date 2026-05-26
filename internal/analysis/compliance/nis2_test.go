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

package compliance

import (
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestNIS2_FailOnCritical(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{Severity: model.SeverityCritical, Category: model.CategoryKeyStrength}},
	}
	if got := evaluateNIS2(r); got != StatusFail {
		t.Errorf("Critical → %s, want fail", got)
	}
}

func TestNIS2_PartialOnHigh(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{Severity: model.SeverityHigh, Category: model.CategoryCipher}},
	}
	if got := evaluateNIS2(r); got != StatusPartial {
		t.Errorf("High → %s, want partial", got)
	}
}

func TestNIS2_PassOnMedium(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{Severity: model.SeverityMedium}},
	}
	if got := evaluateNIS2(r); got != StatusPass {
		t.Errorf("Medium → %s, want pass (NIS2 only escalates at High)", got)
	}
}

func TestNIS2_PassOnEmpty(t *testing.T) {
	if got := evaluateNIS2(&model.AssetHealthReport{}); got != StatusPass {
		t.Errorf("empty → %s, want pass", got)
	}
}

func TestNIS2_CriticalDominatesHigh(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{
			{Severity: model.SeverityCritical},
			{Severity: model.SeverityHigh},
		},
	}
	if got := evaluateNIS2(r); got != StatusFail {
		t.Errorf("Critical + High → %s, want fail", got)
	}
}

func TestNIS2_CategoryAgnostic(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{Severity: model.SeverityCritical, Category: model.CategoryGovernance}},
	}
	if got := evaluateNIS2(r); got != StatusFail {
		t.Errorf("Critical/Governance → %s, want fail (category-agnostic)", got)
	}
}
