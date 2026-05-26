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

// Package compliance evaluates scored assets against regulatory frameworks
// and populates AssetHealthReport.Compliance. Runs inline with scoring
// via the scoring dispatcher — no separate trigger, no separate storage.
//
// Evaluation is total: evaluators never return errors. Unknown or absent
// inputs produce StatusUnknown or leave the compliance map unchanged.
package compliance

// Framework IDs — the keys written into report.Compliance.
const (
	FrameworkNIST800_131A = "nist_800_131a"
	FrameworkPCI_DSS_4    = "pci_dss_4"
	FrameworkFIPS_140_3   = "fips_140_3"
	FrameworkCNSA_2       = "cnsa_2"
	FrameworkNIS2         = "nis2"
)

// Status values written as compliance map values.
const (
	StatusPass          = "pass"
	StatusPartial       = "partial"
	StatusFail          = "fail"
	StatusUnknown       = "unknown"
	StatusNotApplicable = "not_applicable"
)
