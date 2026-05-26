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

// Package handler — findings.go
//
// Serves a single HealthFinding by its composite identity
// (asset_type, asset_id, rule_id). Findings have no stable primary key in
// the schema — they are JSONB rows inside asset_health_reports.findings —
// so the composite URL shape is the canonical way to deep-link to one.
//
// Powers AQ-AH-01 drill-down and the Finding detail page (Phase C of the
// Universal Detail Template rollout).
package handler

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

type findingsStore interface {
	GetAssetHealthReport(ctx context.Context, assetType, assetID string) (*model.AssetHealthReport, error)
}

// AssetFindingHandler serves individual findings.
type AssetFindingHandler struct {
	store findingsStore
}

// NewAssetFindingHandler constructs an AssetFindingHandler.
func NewAssetFindingHandler(s findingsStore) *AssetFindingHandler {
	return &AssetFindingHandler{store: s}
}

// FindingDetail is the API shape returned by GET /findings/{...}. It
// embeds the finding and carries enough context that the detail page can
// render Identity + Neighborhood + Evidence without additional round-trips.
type FindingDetail struct {
	// The matched finding itself.
	Finding model.HealthFinding `json:"finding"`
	// Composite identity the URL was built from.
	AssetType string `json:"asset_type"`
	AssetID   string `json:"asset_id"`
	RuleID    string `json:"rule_id"`
	// Containing asset's overall posture, for quick context framing.
	AssetGrade string `json:"asset_grade"`
	AssetScore int    `json:"asset_score"`
}

// Get handles GET /findings/{asset_type}/{asset_id}/{rule_id}.
// Returns 404 when the asset has no report OR when no finding with that
// rule_id is present on the report.
func (h *AssetFindingHandler) Get(w http.ResponseWriter, r *http.Request) {
	assetType := chi.URLParam(r, "asset_type")
	assetID := chi.URLParam(r, "asset_id")
	ruleID := chi.URLParam(r, "rule_id")

	if assetType == "" || assetID == "" || ruleID == "" {
		writeError(w, http.StatusBadRequest, "asset_type, asset_id, rule_id required")
		return
	}

	report, err := h.store.GetAssetHealthReport(r.Context(), assetType, assetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if report == nil {
		writeError(w, http.StatusNotFound, "no health report for this asset")
		return
	}

	// Linear scan — findings per report are O(10s), not worth indexing.
	// First match wins; rule_id is not strictly unique per report but
	// dedup-at-scoring-time makes duplicate rule_ids rare.
	for i := range report.Findings {
		if report.Findings[i].RuleID == ruleID {
			writeJSON(w, http.StatusOK, FindingDetail{
				Finding:    report.Findings[i],
				AssetType:  assetType,
				AssetID:    assetID,
				RuleID:     ruleID,
				AssetGrade: report.Grade,
				AssetScore: report.Score,
			})
			return
		}
	}

	writeError(w, http.StatusNotFound, "rule_id not present on this asset's health report")
}
