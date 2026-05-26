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
	"sort"
	"strconv"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// buildCipherFlagProps converts an AssetHealthReport into CycloneDX properties
// using the "cipherflag:" namespace. CycloneDX consumers that do not understand
// this namespace simply ignore these properties — standards compliance preserved.
//
// Map iteration is sorted by key so the emitted properties[] order is stable
// across runs. JCS canonicalisation sorts object keys but preserves array
// order, so unsorted map iteration would produce a different byte sequence
// (and a different JSF signature) per invocation — see Generator.Generate
// for the matching algorithm-component sort.
func buildCipherFlagProps(r *model.AssetHealthReport) []cdx.Property {
	props := []cdx.Property{
		{Name: "cipherflag:grade", Value: r.Grade},
		{Name: "cipherflag:score", Value: strconv.Itoa(r.Score)},
		{Name: "cipherflag:risk_score", Value: strconv.Itoa(r.RiskScore)},
		{Name: "cipherflag:pqc_status", Value: r.PQCStatus},
		{Name: "cipherflag:scored_at", Value: r.ScoredAt.UTC().Format(time.RFC3339)},
	}
	complianceKeys := make([]string, 0, len(r.Compliance))
	for fw := range r.Compliance {
		complianceKeys = append(complianceKeys, fw)
	}
	sort.Strings(complianceKeys)
	for _, fw := range complianceKeys {
		props = append(props, cdx.Property{
			Name:  "cipherflag:compliance." + fw,
			Value: r.Compliance[fw],
		})
	}
	riskKeys := make([]string, 0, len(r.RiskFactors))
	for factor := range r.RiskFactors {
		riskKeys = append(riskKeys, factor)
	}
	sort.Strings(riskKeys)
	for _, factor := range riskKeys {
		props = append(props, cdx.Property{
			Name:  "cipherflag:risk_factor." + factor,
			Value: strconv.Itoa(r.RiskFactors[factor]),
		})
	}
	for _, f := range r.Findings {
		props = append(props, cdx.Property{
			Name:  "cipherflag:finding." + f.RuleID,
			Value: string(f.Severity),
		})
	}
	return props
}
