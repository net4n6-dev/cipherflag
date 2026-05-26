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
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// cryptoConfigStore is the minimal store interface required by CryptoConfigHandler.
type cryptoConfigStore interface {
	GetCryptoConfig(ctx context.Context, id string) (*model.CryptoConfig, error)
	ListCryptoConfigs(ctx context.Context, query store.ConfigSearchQuery) (*store.ConfigSearchResult, error)
}

// CryptoConfigHandler handles crypto config asset endpoints.
type CryptoConfigHandler struct {
	store cryptoConfigStore
}

// NewCryptoConfigHandler constructs a CryptoConfigHandler.
func NewCryptoConfigHandler(s cryptoConfigStore) *CryptoConfigHandler {
	return &CryptoConfigHandler{store: s}
}

// List handles GET /crypto-configs
func (h *CryptoConfigHandler) List(w http.ResponseWriter, r *http.Request) {
	q := store.ConfigSearchQuery{
		HostID:     r.URL.Query().Get("host_id"),
		ConfigType: r.URL.Query().Get("config_type"),
		Status:     r.URL.Query().Get("status"),
		Search:     r.URL.Query().Get("search"),
		Limit:      50,
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 500 {
				n = 500
			}
			q.Limit = n
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		q.Offset, _ = strconv.Atoi(o)
	}

	result, err := h.store.ListCryptoConfigs(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Get handles GET /crypto-configs/{id}
func (h *CryptoConfigHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cfg, err := h.store.GetCryptoConfig(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg == nil {
		writeError(w, http.StatusNotFound, "crypto config not found")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}
