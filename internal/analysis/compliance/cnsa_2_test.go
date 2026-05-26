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

	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestCNSA_PassOnSafe(t *testing.T) {
	r := &model.AssetHealthReport{PQCStatus: string(pqc.QuantumSafe)}
	if got := evaluateCNSA2Generic(r); got != StatusPass {
		t.Errorf("safe → %s, want pass", got)
	}
}

func TestCNSA_PassOnHybrid(t *testing.T) {
	r := &model.AssetHealthReport{PQCStatus: string(pqc.QuantumHybrid)}
	if got := evaluateCNSA2Generic(r); got != StatusPass {
		t.Errorf("hybrid → %s, want pass", got)
	}
}

func TestCNSA_PartialOnWeakened(t *testing.T) {
	r := &model.AssetHealthReport{PQCStatus: string(pqc.QuantumWeakened)}
	if got := evaluateCNSA2Generic(r); got != StatusPartial {
		t.Errorf("weakened → %s, want partial", got)
	}
}

func TestCNSA_FailOnVulnerable(t *testing.T) {
	r := &model.AssetHealthReport{PQCStatus: string(pqc.QuantumVulnerable)}
	if got := evaluateCNSA2Generic(r); got != StatusFail {
		t.Errorf("vulnerable → %s, want fail", got)
	}
}

func TestCNSA_UnknownOnUnknown(t *testing.T) {
	r := &model.AssetHealthReport{PQCStatus: string(pqc.QuantumUnknown)}
	if got := evaluateCNSA2Generic(r); got != StatusUnknown {
		t.Errorf("unknown → %s, want unknown", got)
	}
}

func TestCNSA_UnknownOnEmpty(t *testing.T) {
	r := &model.AssetHealthReport{PQCStatus: ""}
	if got := evaluateCNSA2Generic(r); got != StatusUnknown {
		t.Errorf("empty → %s, want unknown", got)
	}
}

func TestCNSA_Library_FailOnLIB004(t *testing.T) {
	r := &model.AssetHealthReport{
		PQCStatus: string(pqc.QuantumSafe),
		Findings:  []model.HealthFinding{{RuleID: "LIB-004"}},
	}
	if got := evaluateCNSA2Library(r); got != StatusFail {
		t.Errorf("LIB-004 → %s, want fail (overrides PQC status)", got)
	}
}

func TestCNSA_Library_PassOnLIB005WithoutLIB004(t *testing.T) {
	r := &model.AssetHealthReport{
		PQCStatus: string(pqc.QuantumSafe),
		Findings:  []model.HealthFinding{{RuleID: "LIB-005"}},
	}
	if got := evaluateCNSA2Library(r); got != StatusPass {
		t.Errorf("LIB-005 without LIB-004 → %s, want pass", got)
	}
}

func TestCNSA_Library_GenericFallback(t *testing.T) {
	r := &model.AssetHealthReport{PQCStatus: string(pqc.QuantumVulnerable)}
	if got := evaluateCNSA2Library(r); got != StatusFail {
		t.Errorf("fallback vulnerable → %s, want fail", got)
	}
}

func TestCNSA_Config_AlwaysUnknown(t *testing.T) {
	for _, pqcStatus := range []string{
		string(pqc.QuantumSafe),
		string(pqc.QuantumVulnerable),
		string(pqc.QuantumHybrid),
		"",
	} {
		r := &model.AssetHealthReport{PQCStatus: pqcStatus}
		if got := evaluateCNSA2Config(r); got != StatusUnknown {
			t.Errorf("config with PQCStatus=%s → %s, want unknown", pqcStatus, got)
		}
	}
}
