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

// evaluateNIST800_131A evaluates a scored asset against NIST SP 800-131A
// Rev 2 (key-size + algorithm approval — pre-quantum focus).
//
// fail: SSH-001 (DSA deprecated), SSH-002 (RSA < 2048), LIB-003 (EOL
//
//	library), or any Critical severity in KeyStrength/Signature/Chain.
//
// partial: SSH-003 (RSA < 3072), or Medium severity in KeyStrength/Signature.
// pass: otherwise.
func evaluateNIST800_131A(r *model.AssetHealthReport) string {
	nistFailCategories := []model.FindingCategory{
		model.CategoryKeyStrength,
		model.CategorySignature,
		model.CategoryChain,
	}
	nistFailRuleIDs := []string{"SSH-001", "SSH-002", "LIB-003"}

	// fail: any specific rule ID, or any Critical finding in fail categories.
	if hasRuleID(r.Findings, nistFailRuleIDs...) {
		return StatusFail
	}
	if hasSeverityInCategories(r.Findings, []model.Severity{model.SeverityCritical}, nistFailCategories) {
		return StatusFail
	}

	// partial: SSH-003 or Medium in KeyStrength/Signature.
	nistPartialCategories := []model.FindingCategory{
		model.CategoryKeyStrength,
		model.CategorySignature,
	}
	if hasRuleID(r.Findings, "SSH-003") {
		return StatusPartial
	}
	if hasSeverityInCategories(r.Findings, []model.Severity{model.SeverityMedium}, nistPartialCategories) {
		return StatusPartial
	}

	return StatusPass
}
