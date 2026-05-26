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

package handler

import (
	"net/http"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

type StatsHandler struct {
	store store.CryptoStore
}

func NewStatsHandler(s store.CryptoStore) *StatsHandler {
	return &StatsHandler{store: s}
}

func (h *StatsHandler) Summary(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetSummaryStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (h *StatsHandler) Ciphers(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetCipherStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (h *StatsHandler) PKITree(w http.ResponseWriter, r *http.Request) {
	tree, err := h.store.GetPKITree(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tree)
}

func (h *StatsHandler) Issuers(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetIssuerStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuers": stats})
}

func (h *StatsHandler) ExpiryTimeline(w http.ResponseWriter, r *http.Request) {
	timeline, err := h.store.GetExpiryTimeline(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, timeline)
}

func (h *StatsHandler) ChainFlow(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetChainFlow(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) Ownership(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetOwnershipStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) Deployment(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetDeploymentStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) CryptoPosture(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetCryptoPosture(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) ExpiryForecast(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetExpiryForecast(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) SourceLineage(w http.ResponseWriter, r *http.Request) {
	resp, err := h.store.GetSourceLineage(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *StatsHandler) LibraryDistribution(w http.ResponseWriter, r *http.Request) {
	items, err := h.store.GetLibraryDistribution(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (h *StatsHandler) SSHKeyAnalytics(w http.ResponseWriter, r *http.Request) {
	analytics, err := h.store.GetSSHKeyAnalytics(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analytics)
}
