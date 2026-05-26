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

// Package handler — asset_ownership.go
//
// Endpoints for AQ-OP-01 (ownership resolver) at the per-asset
// grain:
//
//   GET    /api/v1/assets/{type}/{id}/ownership                       — viewer+
//   PUT    /api/v1/assets/{type}/{id}/ownership                       — admin
//   DELETE /api/v1/assets/{type}/{id}/ownership/{source}/{team}       — admin
//
// Plan: research/ownership-plan-v1.8.0.md §3 P2.
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// ownershipNoteMaxBytes caps operator-note evidence at 2KB — same
// rationale as v1.6.0 shadow-CA + v1.7.0 application-metadata notes.
const ownershipNoteMaxBytes = 2048

// allowedAssetTypes mirrors migration 028's aos_asset_type_check so
// the handler 400s on bad input before the DB layer ever sees it.
// Keep this list in sync with
// internal/store/migrations/028_asset_ownership_sightings.sql.
var allowedAssetTypes = map[string]bool{
	"certificate":       true,
	"ssh_key":           true,
	"crypto_library":    true,
	"crypto_config":     true,
	"protocol_endpoint": true,
	"host":              true,
	"repository":        true,
	// 'finding' is accepted on GET only — the resolver delegates to
	// the source asset (see §2.1). It's rejected on PUT/DELETE
	// because no sighting row is ever written with that asset_type.
}

// assetOwnershipStore is the narrow interface this handler needs.
type assetOwnershipStore interface {
	ResolveOwner(ctx context.Context, assetType, assetID string) (*store.OwnershipResolution, error)
	UpsertOwnershipSighting(ctx context.Context, sighting *store.OwnershipSighting) error
	DeleteOwnershipStamp(ctx context.Context, assetType, assetID, team string) error
}

// AssetOwnershipHandler serves the per-asset ownership endpoints.
type AssetOwnershipHandler struct{ store assetOwnershipStore }

// NewAssetOwnershipHandler constructs an AssetOwnershipHandler.
func NewAssetOwnershipHandler(s assetOwnershipStore) *AssetOwnershipHandler {
	return &AssetOwnershipHandler{store: s}
}

// Get handles GET /assets/{type}/{id}/ownership. Returns the full
// OwnershipResolution including Primary, CoOwners, and Alternatives.
// Unknown assets return 200 with `{"unknown": true}` rather than 404
// — "no sightings yet" is a legitimate response the UI renders as
// "No owner declared · [Declare]".
func (h *AssetOwnershipHandler) Get(w http.ResponseWriter, r *http.Request) {
	assetType := strings.TrimSpace(chi.URLParam(r, "type"))
	assetID := strings.TrimSpace(chi.URLParam(r, "id"))
	if assetType == "" || assetID == "" {
		writeError(w, http.StatusBadRequest, "type and id are required")
		return
	}
	// 'finding' is allowed on GET — resolver delegates to source asset.
	if !allowedAssetTypes[assetType] && assetType != "finding" {
		writeError(w, http.StatusBadRequest, "unknown asset_type: "+assetType)
		return
	}
	res, err := h.store.ResolveOwner(r.Context(), assetType, assetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ownershipStampRequest is the PUT body.
type ownershipStampRequest struct {
	Team        string `json:"team"`
	NamedOwner  string `json:"named_owner,omitempty"`
	BusinessSvc string `json:"business_svc,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Put handles PUT /assets/{type}/{id}/ownership (admin-only). Writes
// a direct-tier operator_stamp sighting. Re-sending the same
// (asset, team) merges into the existing row and bumps last_seen.
// The team auto-create hook in UpsertOwnershipSighting populates the
// teams registry skeleton as a side-effect.
func (h *AssetOwnershipHandler) Put(w http.ResponseWriter, r *http.Request) {
	assetType := strings.TrimSpace(chi.URLParam(r, "type"))
	assetID := strings.TrimSpace(chi.URLParam(r, "id"))
	if assetType == "" || assetID == "" {
		writeError(w, http.StatusBadRequest, "type and id are required")
		return
	}
	if !allowedAssetTypes[assetType] {
		writeError(w, http.StatusBadRequest, "unknown asset_type: "+assetType)
		return
	}
	var body ownershipStampRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	team := strings.TrimSpace(body.Team)
	if team == "" {
		writeError(w, http.StatusBadRequest, "team is required")
		return
	}
	if len(body.Note) > ownershipNoteMaxBytes {
		writeError(w, http.StatusBadRequest, "note exceeds 2048 bytes")
		return
	}

	evidence := map[string]any{}
	if body.Note != "" {
		evidence["note"] = body.Note
	}
	if u := middleware.GetUser(r.Context()); u != nil && u.ID != "" {
		evidence["stamped_by"] = u.ID
	}

	now := time.Now()
	err := h.store.UpsertOwnershipSighting(r.Context(), &store.OwnershipSighting{
		AssetType:   assetType,
		AssetID:     assetID,
		Team:        team,
		NamedOwner:  strings.TrimSpace(body.NamedOwner),
		BusinessSvc: strings.TrimSpace(body.BusinessSvc),
		Source:      "operator_stamp",
		Confidence:  "direct",
		FirstSeen:   now,
		LastSeen:    now,
		Evidence:    evidence,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"asset_type": assetType,
		"asset_id":   assetID,
		"team":       team,
		"status":     "stamped",
	})
}

// Delete handles
// DELETE /assets/{type}/{id}/ownership/{source}/{team} (admin-only).
// Source is validated to 'operator_stamp' — inferred / observed
// regenerate on next scan, so revoking them is pointless and
// returning 400 is clearer than a silent no-op.
func (h *AssetOwnershipHandler) Delete(w http.ResponseWriter, r *http.Request) {
	assetType := strings.TrimSpace(chi.URLParam(r, "type"))
	assetID := strings.TrimSpace(chi.URLParam(r, "id"))
	source := strings.TrimSpace(chi.URLParam(r, "source"))
	team := strings.TrimSpace(chi.URLParam(r, "team"))
	if assetType == "" || assetID == "" || source == "" || team == "" {
		writeError(w, http.StatusBadRequest, "type, id, source, and team are required")
		return
	}
	if !allowedAssetTypes[assetType] {
		writeError(w, http.StatusBadRequest, "unknown asset_type: "+assetType)
		return
	}
	if source != "operator_stamp" {
		writeError(w, http.StatusBadRequest,
			"only operator_stamp sightings are revokable; inferred/observed regenerate on scan")
		return
	}
	if err := h.store.DeleteOwnershipStamp(r.Context(), assetType, assetID, team); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"asset_type": assetType,
		"asset_id":   assetID,
		"team":       team,
		"status":     "revoked",
	})
}
