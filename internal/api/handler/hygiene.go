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

// Package handler — hygiene.go
//
// Serves /api/v1/analysis/weak-algorithms. Closes AQ-AH-01 —
// *"Where is RSA-1024 / SHA-1 / 3DES / DSA / MD5 still in use —
// driveable as a ticket, not a dashboard?"* Per-algorithm location
// list with asset_id, host (when applicable), exposure flag.
//
// Response is a flat array of WeakAlgoOccurrence rows; the frontend
// groups by (algorithm_canonical, classification). Server-side
// grouping would be faster on the wire but less flexible for
// additional filters (classification toggle, asset-type multi-select)
// the operator page adds client-side.
package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

type hygieneStore interface {
	ListWeakAlgorithmOccurrences(ctx context.Context, filter store.WeakAlgoFilter) ([]store.WeakAlgoOccurrence, error)
}

// HygieneHandler serves AQ-AH-01.
type HygieneHandler struct{ store hygieneStore }

func NewHygieneHandler(s hygieneStore) *HygieneHandler {
	return &HygieneHandler{store: s}
}

// ListWeakAlgorithms handles GET /api/v1/analysis/weak-algorithms.
//
// Query params:
//
//	status=vulnerable,weakened — default both; comma-separated
//	type=certificate,ssh_key,… — default all; comma-separated
//	limit=N                    — 0 = no cap (default 2000)
//
// Response:
//
//	{ "occurrences": [...], "count": N }
//
// Always emits `occurrences: []` (not null) so the frontend renders
// an empty-state instead of a type error.
func (h *HygieneHandler) ListWeakAlgorithms(w http.ResponseWriter, r *http.Request) {
	filter := store.WeakAlgoFilter{Limit: 2000}

	if s := strings.TrimSpace(r.URL.Query().Get("status")); s != "" {
		for _, v := range strings.Split(s, ",") {
			switch strings.TrimSpace(strings.ToLower(v)) {
			case "vulnerable":
				filter.IncludeVulnerable = true
			case "weakened":
				filter.IncludeWeakened = true
			default:
				writeError(w, http.StatusBadRequest, "invalid status: must be one of vulnerable, weakened")
				return
			}
		}
	}

	if t := strings.TrimSpace(r.URL.Query().Get("type")); t != "" {
		allowed := map[string]bool{
			"certificate":       true,
			"ssh_key":           true,
			"crypto_library":    true,
			"crypto_config":     true,
			"protocol_endpoint": true,
		}
		for _, v := range strings.Split(t, ",") {
			trimmed := strings.TrimSpace(strings.ToLower(v))
			if !allowed[trimmed] {
				writeError(w, http.StatusBadRequest, "invalid type: must be one of certificate, ssh_key, crypto_library, crypto_config, protocol_endpoint")
				return
			}
			filter.AssetTypes = append(filter.AssetTypes, trimmed)
		}
	}

	if l := strings.TrimSpace(r.URL.Query().Get("limit")); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid limit: must be a non-negative integer")
			return
		}
		filter.Limit = n
	}

	occs, err := h.store.ListWeakAlgorithmOccurrences(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if occs == nil {
		occs = []store.WeakAlgoOccurrence{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"occurrences": occs,
		"count":       len(occs),
	})
}
