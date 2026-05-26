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

package model

import "time"

// AssetHealthReport holds scoring results for any crypto asset type.
type AssetHealthReport struct {
	ID                string            `json:"id"`
	AssetType         string            `json:"asset_type"`
	AssetID           string            `json:"asset_id"`
	Grade             string            `json:"grade"`
	Score             int               `json:"score"`
	Findings          []HealthFinding   `json:"findings"`
	PQCStatus         string            `json:"pqc_status"`
	Compliance        map[string]string `json:"compliance"`
	RuleEngineVersion int               `json:"rule_engine_version"`
	ScoredAt          time.Time         `json:"scored_at"`
	RiskScore         int               `json:"risk_score"`
	RiskFactors       map[string]int    `json:"risk_factors"`

	// RawFindings is an escape hatch for callers (e.g. the repo scanner)
	// that need to persist a JSONB shape richer than HealthFinding can
	// represent — bucket, cbom sub-object, scanner-specific fields. When
	// non-nil, SaveAssetHealthReport writes RawFindings verbatim into the
	// findings column instead of marshaling Findings. Not serialised on
	// the wire (json:"-" — readers always see the canonical Findings).
	RawFindings []byte `json:"-"`
}
