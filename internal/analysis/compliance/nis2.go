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

// evaluateNIS2 evaluates a scored asset against EU NIS2 directive
// cryptographic requirements. NIS2 is governance-focused and doesn't
// specify algorithms — this per-asset evaluation proxies for the
// broader organisational obligation.
//
// fail: any Critical severity finding (any category).
// partial: any High severity finding (any category; no fail trigger).
// pass: otherwise.
func evaluateNIS2(r *model.AssetHealthReport) string {
	if hasSeverityIn(r.Findings, model.SeverityCritical) {
		return StatusFail
	}
	if hasSeverityIn(r.Findings, model.SeverityHigh) {
		return StatusPartial
	}
	return StatusPass
}
