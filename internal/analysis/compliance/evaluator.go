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

import "github.com/net4n6-dev/cipherflag/internal/model"

// hasSeverityIn returns true if any finding's severity matches one of
// the provided severities.
func hasSeverityIn(findings []model.HealthFinding, severities ...model.Severity) bool {
	for _, f := range findings {
		for _, s := range severities {
			if f.Severity == s {
				return true
			}
		}
	}
	return false
}

// hasRuleID returns true if any finding's RuleID matches one of the
// provided IDs.
func hasRuleID(findings []model.HealthFinding, ids ...string) bool {
	for _, f := range findings {
		for _, id := range ids {
			if f.RuleID == id {
				return true
			}
		}
	}
	return false
}

// hasSeverityInCategories returns true if any finding has a severity in
// `severities` AND a category in `categories`. Used by frameworks that
// only care about crypto-category findings (PCI, NIST).
func hasSeverityInCategories(
	findings []model.HealthFinding,
	severities []model.Severity,
	categories []model.FindingCategory,
) bool {
	for _, f := range findings {
		sevMatch := false
		for _, s := range severities {
			if f.Severity == s {
				sevMatch = true
				break
			}
		}
		if !sevMatch {
			continue
		}
		for _, c := range categories {
			if f.Category == c {
				return true
			}
		}
	}
	return false
}

// The four public entry points (EvaluateCertificate, EvaluateSSHKey,
// EvaluateLibrary, EvaluateConfig) are defined later in this file once
// each framework's evaluator is in place. See tasks 2–6.

// EvaluateCertificate populates report.Compliance with per-framework
// status for a certificate. Reads findings + PQCStatus from report and
// cert for direct framework-specific checks.
func EvaluateCertificate(r *model.AssetHealthReport, cert *model.Certificate) {
	if r == nil || cert == nil {
		return
	}
	if r.Compliance == nil {
		r.Compliance = map[string]string{}
	}
	r.Compliance[FrameworkNIST800_131A] = evaluateNIST800_131A(r)
	r.Compliance[FrameworkFIPS_140_3] = evaluateFIPS140_3Certificate(r, cert)
	r.Compliance[FrameworkCNSA_2] = evaluateCNSA2Generic(r)
	r.Compliance[FrameworkNIS2] = evaluateNIS2(r)
}

// EvaluateSSHKey — same pattern for SSH keys.
func EvaluateSSHKey(r *model.AssetHealthReport, k *model.SSHKey) {
	if r == nil || k == nil {
		return
	}
	if r.Compliance == nil {
		r.Compliance = map[string]string{}
	}
	r.Compliance[FrameworkNIST800_131A] = evaluateNIST800_131A(r)
	r.Compliance[FrameworkFIPS_140_3] = evaluateFIPS140_3SSHKey(r, k)
	r.Compliance[FrameworkCNSA_2] = evaluateCNSA2Generic(r)
	r.Compliance[FrameworkNIS2] = evaluateNIS2(r)
}

// EvaluateLibrary — same pattern for libraries.
func EvaluateLibrary(r *model.AssetHealthReport, lib *model.CryptoLibrary) {
	if r == nil || lib == nil {
		return
	}
	if r.Compliance == nil {
		r.Compliance = map[string]string{}
	}
	r.Compliance[FrameworkNIST800_131A] = evaluateNIST800_131A(r)
	r.Compliance[FrameworkFIPS_140_3] = evaluateFIPS140_3Library(r)
	r.Compliance[FrameworkCNSA_2] = evaluateCNSA2Library(r)
	r.Compliance[FrameworkNIS2] = evaluateNIS2(r)
}

// EvaluateConfig — same pattern for configs. CNSA 2.0 returns Unknown.
func EvaluateConfig(r *model.AssetHealthReport, cfg *model.CryptoConfig) {
	if r == nil || cfg == nil {
		return
	}
	if r.Compliance == nil {
		r.Compliance = map[string]string{}
	}
	r.Compliance[FrameworkNIST800_131A] = evaluateNIST800_131A(r)
	r.Compliance[FrameworkFIPS_140_3] = evaluateFIPS140_3Config(r)
	r.Compliance[FrameworkCNSA_2] = evaluateCNSA2Config(r)
	r.Compliance[FrameworkNIS2] = evaluateNIS2(r)
}

// EvaluateProtocol — same pattern for protocol endpoints. CNSA 2.0
// returns Unknown in v1 (see evaluateCNSA2Protocol).
func EvaluateProtocol(r *model.AssetHealthReport, ep *model.ProtocolEndpoint) {
	if r == nil || ep == nil {
		return
	}
	if r.Compliance == nil {
		r.Compliance = map[string]string{}
	}
	r.Compliance[FrameworkNIST800_131A] = evaluateNIST800_131A(r)
	r.Compliance[FrameworkFIPS_140_3] = evaluateFIPS140_3Protocol(r, ep)
	r.Compliance[FrameworkCNSA_2] = evaluateCNSA2Protocol(r)
	r.Compliance[FrameworkNIS2] = evaluateNIS2(r)
}
