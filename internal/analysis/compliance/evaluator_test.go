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

func TestHasSeverityIn(t *testing.T) {
	findings := []model.HealthFinding{
		{RuleID: "A", Severity: model.SeverityCritical},
		{RuleID: "B", Severity: model.SeverityMedium},
	}
	if !hasSeverityIn(findings, model.SeverityCritical) {
		t.Error("should match Critical")
	}
	if !hasSeverityIn(findings, model.SeverityMedium) {
		t.Error("should match Medium")
	}
	if !hasSeverityIn(findings, model.SeverityCritical, model.SeverityHigh) {
		t.Error("should match Critical (first in variadic)")
	}
	if hasSeverityIn(findings, model.SeverityLow) {
		t.Error("should not match Low (not present)")
	}
	if hasSeverityIn(nil, model.SeverityCritical) {
		t.Error("empty findings should never match")
	}
}

func TestHasRuleID(t *testing.T) {
	findings := []model.HealthFinding{
		{RuleID: "SSH-001"},
		{RuleID: "LIB-003"},
	}
	if !hasRuleID(findings, "SSH-001") {
		t.Error("should find SSH-001")
	}
	if !hasRuleID(findings, "LIB-003", "FAKE") {
		t.Error("variadic should succeed when any ID matches")
	}
	if hasRuleID(findings, "CFG-001") {
		t.Error("should not find missing CFG-001")
	}
}

func TestHasSeverityInCategories(t *testing.T) {
	findings := []model.HealthFinding{
		{RuleID: "A", Severity: model.SeverityHigh, Category: model.CategoryKeyStrength},
		{RuleID: "B", Severity: model.SeverityCritical, Category: model.CategoryGovernance},
	}
	if !hasSeverityInCategories(findings, []model.Severity{model.SeverityHigh}, []model.FindingCategory{model.CategoryKeyStrength}) {
		t.Error("should match High in KeyStrength")
	}
	if hasSeverityInCategories(findings, []model.Severity{model.SeverityCritical}, []model.FindingCategory{model.CategoryKeyStrength}) {
		t.Error("should not match Critical (only in Governance, not KeyStrength)")
	}
}

func TestEvaluateCertificate_PopulatesAllFrameworks(t *testing.T) {
	r := &model.AssetHealthReport{
		Compliance: map[string]string{},
		PQCStatus:  "vulnerable",
	}
	cert := &model.Certificate{
		KeyAlgorithm:       model.KeyAlgorithm("RSA"),
		SignatureAlgorithm: model.SignatureAlgorithm("SHA256-RSA"),
	}
	EvaluateCertificate(r, cert)

	for _, framework := range []string{
		FrameworkNIST800_131A,
		FrameworkFIPS_140_3, FrameworkCNSA_2, FrameworkNIS2,
	} {
		if v, ok := r.Compliance[framework]; !ok || v == "" {
			t.Errorf("Compliance[%q] missing or empty", framework)
		}
	}
}

func TestEvaluateSSHKey_PopulatesAllFrameworks(t *testing.T) {
	r := &model.AssetHealthReport{Compliance: map[string]string{}, PQCStatus: "vulnerable"}
	k := &model.SSHKey{KeyType: "ssh-ed25519"}
	EvaluateSSHKey(r, k)

	for _, framework := range []string{
		FrameworkNIST800_131A,
		FrameworkFIPS_140_3, FrameworkCNSA_2, FrameworkNIS2,
	} {
		if v, ok := r.Compliance[framework]; !ok || v == "" {
			t.Errorf("Compliance[%q] missing or empty", framework)
		}
	}
	if r.Compliance[FrameworkFIPS_140_3] != StatusFail {
		t.Errorf("FIPS status = %s, want fail", r.Compliance[FrameworkFIPS_140_3])
	}
}

func TestEvaluateLibrary_PopulatesAllFrameworks(t *testing.T) {
	r := &model.AssetHealthReport{Compliance: map[string]string{}, PQCStatus: "safe"}
	lib := &model.CryptoLibrary{LibraryName: "openssl", Version: "3.0.8"}
	EvaluateLibrary(r, lib)
	for _, framework := range []string{
		FrameworkNIST800_131A,
		FrameworkFIPS_140_3, FrameworkCNSA_2, FrameworkNIS2,
	} {
		if v, ok := r.Compliance[framework]; !ok || v == "" {
			t.Errorf("Compliance[%q] missing or empty", framework)
		}
	}
}

func TestEvaluateConfig_PopulatesAllFrameworks(t *testing.T) {
	r := &model.AssetHealthReport{Compliance: map[string]string{}}
	cfg := &model.CryptoConfig{ConfigType: "sshd"}
	EvaluateConfig(r, cfg)
	for _, framework := range []string{
		FrameworkNIST800_131A,
		FrameworkFIPS_140_3, FrameworkCNSA_2, FrameworkNIS2,
	} {
		if v, ok := r.Compliance[framework]; !ok || v == "" {
			t.Errorf("Compliance[%q] missing or empty", framework)
		}
	}
	if r.Compliance[FrameworkCNSA_2] != StatusUnknown {
		t.Errorf("CNSA for config = %s, want unknown", r.Compliance[FrameworkCNSA_2])
	}
}

func TestEvaluate_InitialisesNilComplianceMap(t *testing.T) {
	r := &model.AssetHealthReport{Compliance: nil}
	cert := &model.Certificate{KeyAlgorithm: model.KeyAlgorithm("RSA")}
	EvaluateCertificate(r, cert)
	if r.Compliance == nil {
		t.Error("Compliance map should be non-nil after Evaluate")
	}
}

func TestEvaluate_NilAssetPointerNoPanic(t *testing.T) {
	// Public API must be a silent no-op for nil inputs. Guards future
	// callers outside the dispatcher (sweeps, test helpers, handlers).
	r := &model.AssetHealthReport{Compliance: map[string]string{}}
	EvaluateCertificate(r, nil)
	EvaluateSSHKey(r, nil)
	EvaluateLibrary(r, nil)
	EvaluateConfig(r, nil)

	// Also handle nil report (must not panic, must not allocate).
	EvaluateCertificate(nil, &model.Certificate{})
	EvaluateSSHKey(nil, &model.SSHKey{})
	EvaluateLibrary(nil, &model.CryptoLibrary{})
	EvaluateConfig(nil, &model.CryptoConfig{})
}
