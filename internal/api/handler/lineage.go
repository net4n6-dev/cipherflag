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

// Package handler — lineage.go
//
// Polymorphic lineage fan-out endpoint. Given (asset_type, asset_id),
// returns every LineageLink where the asset appears as either the source
// (downstream edges) or the target (upstream edges). Powers the
// Neighborhood section of every entity detail page per
// docs/universal-detail-template.md §2.
package handler

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

type lineageStore interface {
	ListLineageFrom(ctx context.Context, fromAssetType, fromAssetID string) ([]model.LineageLink, error)
	ListLineageTo(ctx context.Context, toAssetType, toAssetID string) ([]model.LineageLink, error)
}

// LineageHandler serves lineage fan-out queries.
type LineageHandler struct {
	store lineageStore
}

// NewLineageHandler constructs a LineageHandler.
func NewLineageHandler(s lineageStore) *LineageHandler {
	return &LineageHandler{store: s}
}

// LineageResponse is the shape returned by GET /lineage/{asset_type}/{asset_id}.
//
// `upstream` edges point TO the queried asset (parents, sources, issuers,
// repos that leaked a key that ended up on this asset, etc.). `downstream`
// edges point FROM the queried asset (children, signed-by descendants,
// hosts it deploys to, etc.). Direction naming matches the detail-template
// Neighborhood conventions.
type LineageResponse struct {
	AssetType  string              `json:"asset_type"`
	AssetID    string              `json:"asset_id"`
	Upstream   []model.LineageLink `json:"upstream"`
	Downstream []model.LineageLink `json:"downstream"`
	Total      int                 `json:"total"`
}

// Get handles GET /lineage/{asset_type}/{asset_id}.
// Empty result sets are returned as empty arrays (never null).
func (h *LineageHandler) Get(w http.ResponseWriter, r *http.Request) {
	assetType := chi.URLParam(r, "asset_type")
	assetID := chi.URLParam(r, "asset_id")

	if assetType == "" || assetID == "" {
		writeError(w, http.StatusBadRequest, "asset_type and asset_id required")
		return
	}

	// Parallel-fetch both directions to halve wall-clock latency.
	// The two queries hit different B-tree indexes so there is no contention.
	type result struct {
		links []model.LineageLink
		err   error
	}
	downCh := make(chan result, 1)
	upCh := make(chan result, 1)

	go func() {
		links, err := h.store.ListLineageFrom(r.Context(), assetType, assetID)
		downCh <- result{links, err}
	}()
	go func() {
		links, err := h.store.ListLineageTo(r.Context(), assetType, assetID)
		upCh <- result{links, err}
	}()

	down := <-downCh
	up := <-upCh

	if down.err != nil {
		writeError(w, http.StatusInternalServerError, down.err.Error())
		return
	}
	if up.err != nil {
		writeError(w, http.StatusInternalServerError, up.err.Error())
		return
	}

	// Always return arrays, not null, so the frontend can render empty
	// states without null-checking.
	if down.links == nil {
		down.links = []model.LineageLink{}
	}
	if up.links == nil {
		up.links = []model.LineageLink{}
	}

	writeJSON(w, http.StatusOK, LineageResponse{
		AssetType:  assetType,
		AssetID:    assetID,
		Upstream:   up.links,
		Downstream: down.links,
		Total:      len(up.links) + len(down.links),
	})
}
