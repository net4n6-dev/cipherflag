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
	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// evaluateCNSA2Generic is the base CNSA 2.0 evaluation driven by
// PQCStatus. Used for certificates and SSH keys directly; libraries
// and configs have their own wrappers that may override this result.
func evaluateCNSA2Generic(r *model.AssetHealthReport) string {
	switch r.PQCStatus {
	case string(pqc.QuantumSafe), string(pqc.QuantumHybrid):
		return StatusPass
	case string(pqc.QuantumWeakened):
		return StatusPartial
	case string(pqc.QuantumVulnerable):
		return StatusFail
	case string(pqc.QuantumUnknown), "":
		return StatusUnknown
	}
	return StatusUnknown
}

// evaluateCNSA2Library overlays library-specific rules: LIB-004 forces
// fail regardless of PQCStatus (the library is the source of PQC
// capability; non-capable libraries cannot support CNSA 2.0 migration).
func evaluateCNSA2Library(r *model.AssetHealthReport) string {
	if hasRuleID(r.Findings, "LIB-004") {
		return StatusFail
	}
	if hasRuleID(r.Findings, "LIB-005") {
		return StatusPass
	}
	return evaluateCNSA2Generic(r)
}

// evaluateCNSA2Config — configs don't have aggregate PQC status.
// Per-algorithm analysis stays in CFG-003 findings, not compliance.
func evaluateCNSA2Config(r *model.AssetHealthReport) string {
	return StatusUnknown
}

// evaluateCNSA2Protocol — v1 returns Unknown. Protocol observations
// don't currently carry a PQC kex signal; per-algorithm analysis lives
// in PROTO findings, not an aggregate status.
func evaluateCNSA2Protocol(r *model.AssetHealthReport) string {
	return StatusUnknown
}
