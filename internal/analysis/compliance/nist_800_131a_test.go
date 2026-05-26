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

func TestNIST_FailOnSSH001(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "SSH-001", Severity: model.SeverityCritical, Category: model.CategoryKeyStrength}},
	}
	if got := evaluateNIST800_131A(r); got != StatusFail {
		t.Errorf("SSH-001 → %s, want fail", got)
	}
}

func TestNIST_FailOnSSH002(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "SSH-002", Severity: model.SeverityHigh, Category: model.CategoryKeyStrength}},
	}
	if got := evaluateNIST800_131A(r); got != StatusFail {
		t.Errorf("SSH-002 → %s, want fail", got)
	}
}

func TestNIST_FailOnLIB003(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "LIB-003", Severity: model.SeverityHigh, Category: model.CategoryAgility}},
	}
	if got := evaluateNIST800_131A(r); got != StatusFail {
		t.Errorf("LIB-003 → %s, want fail", got)
	}
}

func TestNIST_FailOnCriticalCertFinding(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "EXP-001", Severity: model.SeverityCritical, Category: model.CategoryKeyStrength}},
	}
	if got := evaluateNIST800_131A(r); got != StatusFail {
		t.Errorf("Critical in KeyStrength → %s, want fail", got)
	}
}

func TestNIST_PartialOnSSH003(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "SSH-003", Severity: model.SeverityMedium, Category: model.CategoryKeyStrength}},
	}
	if got := evaluateNIST800_131A(r); got != StatusPartial {
		t.Errorf("SSH-003 alone → %s, want partial", got)
	}
}

func TestNIST_PartialOnMediumCertFinding(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{Severity: model.SeverityMedium, Category: model.CategorySignature}},
	}
	if got := evaluateNIST800_131A(r); got != StatusPartial {
		t.Errorf("Medium in Signature → %s, want partial", got)
	}
}

func TestNIST_PassOnEmptyFindings(t *testing.T) {
	r := &model.AssetHealthReport{Findings: nil}
	if got := evaluateNIST800_131A(r); got != StatusPass {
		t.Errorf("empty findings → %s, want pass", got)
	}
}

func TestNIST_PassOnInfoOnlyFindings(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{{RuleID: "SSH-008", Severity: model.SeverityInfo}},
	}
	if got := evaluateNIST800_131A(r); got != StatusPass {
		t.Errorf("Info-only findings → %s, want pass", got)
	}
}

func TestNIST_FailDominatesPartial(t *testing.T) {
	r := &model.AssetHealthReport{
		Findings: []model.HealthFinding{
			{RuleID: "SSH-002", Severity: model.SeverityHigh, Category: model.CategoryKeyStrength},
			{RuleID: "SSH-003", Severity: model.SeverityMedium, Category: model.CategoryKeyStrength},
		},
	}
	if got := evaluateNIST800_131A(r); got != StatusFail {
		t.Errorf("fail+partial → %s, want fail", got)
	}
}
