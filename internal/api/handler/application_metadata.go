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

// Package handler — application_metadata.go
//
// Endpoints for AQ-AH-04 (HNDL-protected data flag) + the
// per-application TTL registry it reads:
//
//   GET    /api/v1/applications/{tag}/metadata   — viewer+
//   PUT    /api/v1/applications/{tag}/metadata   — admin-only
//   DELETE /api/v1/applications/{tag}/metadata   — admin-only
//   GET    /api/v1/analysis/hndl[?horizon=YYYY]  — viewer+
//
// Plan: research/hndl-plan-v1.7.0.md §3 P2.
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// DefaultCRQCHorizonYear is the aggressive-IR anchor per plan §2.3 —
// CNSA 2.0 sets 2030 as the NSS transition date and NSS traffic is a
// primary HNDL target. Operators can override via ?horizon=<year>.
const DefaultCRQCHorizonYear = 2030

// noteMaxBytesApp caps operator-note payloads at 2KB. Same rationale
// as the v1.6.0 shadow-CA handler's cap — notes are memory aids, not
// audit evidence; anything longer is almost certainly pasted garbage.
const noteMaxBytesApp = 2048

// applicationMetadataStore is the narrow interface this handler needs.
// Keeps handler tests focused without implementing the full CryptoStore
// surface. ResolveOwnerBatch was added for v1.8.0 to enrich HNDL rows
// with owner_team + owner_confidence powering the "unowned" filter
// pill (§2.7).
type applicationMetadataStore interface {
	GetApplicationMetadata(ctx context.Context, tag string) (*store.ApplicationMetadata, error)
	ListApplicationMetadata(ctx context.Context) ([]store.ApplicationMetadata, error)
	UpsertApplicationMetadata(ctx context.Context, req *store.DeclareApplicationMetadataRequest) error
	DeleteApplicationMetadata(ctx context.Context, tag string) error
	ListHNDLAtRiskAssets(ctx context.Context, crqcHorizonYear int) ([]store.HNDLAtRiskAsset, error)
	ResolveOwnerBatch(ctx context.Context, refs []store.AssetRef) (map[store.AssetRef]*store.OwnershipResolution, error)
}

// ApplicationMetadataHandler serves the /applications/{tag}/metadata
// and /analysis/hndl endpoints.
type ApplicationMetadataHandler struct{ store applicationMetadataStore }

// NewApplicationMetadataHandler constructs an ApplicationMetadataHandler.
func NewApplicationMetadataHandler(s applicationMetadataStore) *ApplicationMetadataHandler {
	return &ApplicationMetadataHandler{store: s}
}

// Get handles GET /applications/{tag}/metadata. Returns 404 when no
// declaration exists — explicit not-found beats an empty 200 body
// because operators need to distinguish "no TTL declared yet" from
// "declaration failed to load".
func (h *ApplicationMetadataHandler) Get(w http.ResponseWriter, r *http.Request) {
	tag := strings.TrimSpace(chi.URLParam(r, "tag"))
	if tag == "" {
		writeError(w, http.StatusBadRequest, "tag is required")
		return
	}
	m, err := h.store.GetApplicationMetadata(r.Context(), tag)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if m == nil {
		writeError(w, http.StatusNotFound, "no metadata declared for this application")
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// upsertRequest is the PUT body.
type upsertRequest struct {
	DataTTLYears       *int       `json:"data_ttl_years,omitempty"`
	DataSensitiveUntil *time.Time `json:"data_sensitive_until,omitempty"`
	OwnerTeam          string     `json:"owner_team,omitempty"`
	Note               string     `json:"note,omitempty"`
}

// Put handles PUT /applications/{tag}/metadata (admin-only via
// middleware.RequireAdmin in server.go wiring). Upsert semantics —
// re-sending the same tag updates metadata without duplicating.
func (h *ApplicationMetadataHandler) Put(w http.ResponseWriter, r *http.Request) {
	tag := strings.TrimSpace(chi.URLParam(r, "tag"))
	if tag == "" {
		writeError(w, http.StatusBadRequest, "tag is required")
		return
	}
	var body upsertRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.DataTTLYears == nil && body.DataSensitiveUntil == nil {
		writeError(w, http.StatusBadRequest, "data_ttl_years or data_sensitive_until is required")
		return
	}
	if body.DataTTLYears != nil && (*body.DataTTLYears < 0 || *body.DataTTLYears > 100) {
		writeError(w, http.StatusBadRequest, "data_ttl_years must be between 0 and 100")
		return
	}
	if len(body.Note) > noteMaxBytesApp {
		writeError(w, http.StatusBadRequest, "note exceeds 2048 bytes")
		return
	}

	var addedBy string
	if u := middleware.GetUser(r.Context()); u != nil {
		addedBy = u.ID
	}

	err := h.store.UpsertApplicationMetadata(r.Context(), &store.DeclareApplicationMetadataRequest{
		Tag:                tag,
		DataTTLYears:       body.DataTTLYears,
		DataSensitiveUntil: body.DataSensitiveUntil,
		OwnerTeam:          strings.TrimSpace(body.OwnerTeam),
		Note:               body.Note,
		AddedBy:            addedBy,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tag":    tag,
		"status": "declared",
	})
}

// Delete handles DELETE /applications/{tag}/metadata (admin-only).
// Idempotent — deleting an unknown tag returns 200 with status=not_declared,
// matching v1.6.0 shadow-CA revoke semantics so repeat calls from the
// UI don't trigger confusing 404s.
func (h *ApplicationMetadataHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tag := strings.TrimSpace(chi.URLParam(r, "tag"))
	if tag == "" {
		writeError(w, http.StatusBadRequest, "tag is required")
		return
	}
	if err := h.store.DeleteApplicationMetadata(r.Context(), tag); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tag":    tag,
		"status": "revoked",
	})
}

// hndlRow is the response row for GET /analysis/hndl. Embeds the
// store-layer HNDLAtRiskAsset and adds v1.8.0 ownership fields
// (§2.7 — "unowned" filter pill is a client-side predicate against
// these two columns).
type hndlRow struct {
	store.HNDLAtRiskAsset
	OwnerTeam       string `json:"owner_team,omitempty"`
	OwnerConfidence string `json:"owner_confidence,omitempty"`
}

// ListHNDL handles GET /analysis/hndl[?horizon=YYYY]. Returns the
// full at-risk + unscoped list from the store, enriched with
// per-row ownership (v1.8.0 §2.7). Envelope carries the horizon
// actually used and the unowned_count summary so the UI can render
// the filter-pill badge without a second pass.
func (h *ApplicationMetadataHandler) ListHNDL(w http.ResponseWriter, r *http.Request) {
	horizon := DefaultCRQCHorizonYear
	if raw := strings.TrimSpace(r.URL.Query().Get("horizon")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "horizon must be a 4-digit year (e.g. 2030)")
			return
		}
		// Sanity bound — CRQC is a forward-looking concept; negative or
		// far-future years suggest a client bug. 2000..2100 is generous
		// enough for any realistic operator scenario.
		if n < 2000 || n > 2100 {
			writeError(w, http.StatusBadRequest, "horizon out of range (2000..2100)")
			return
		}
		horizon = n
	}

	base, err := h.store.ListHNDLAtRiskAssets(r.Context(), horizon)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	refs := make([]store.AssetRef, 0, len(base))
	for _, row := range base {
		refs = append(refs, store.AssetRef{AssetType: row.AssetType, AssetID: row.AssetID})
	}
	resolutions, err := h.store.ResolveOwnerBatch(r.Context(), refs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	rows := make([]hndlRow, 0, len(base))
	var atRisk, unscoped, unowned int
	for _, b := range base {
		row := hndlRow{HNDLAtRiskAsset: b}
		res := resolutions[store.AssetRef{AssetType: b.AssetType, AssetID: b.AssetID}]
		if res != nil && res.Primary != nil && !res.Unknown {
			row.OwnerTeam = res.Primary.Team
			row.OwnerConfidence = res.Primary.Confidence
		}
		// "unowned" predicate per §2.7: no sighting at all OR best
		// tier is observed-only (low-trust SSH-comment-level signal).
		if row.OwnerTeam == "" || row.OwnerConfidence == "observed" {
			unowned++
		}
		if b.Unscoped {
			unscoped++
		} else {
			atRisk++
		}
		rows = append(rows, row)
	}

	if rows == nil {
		rows = []hndlRow{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"assets":            rows,
		"total":             len(rows),
		"at_risk":           atRisk,
		"unscoped":          unscoped,
		"unowned":           unowned,
		"crqc_horizon_year": horizon,
	})
}
