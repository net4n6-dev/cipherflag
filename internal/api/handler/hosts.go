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
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// hostStore is the minimal store interface required by HostHandler.
type hostStore interface {
	GetHost(ctx context.Context, id string) (*model.Host, error)
	ListHosts(ctx context.Context, query store.HostSearchQuery) (*store.HostSearchResult, error)
	ListSSHKeys(ctx context.Context, query store.SSHKeySearchQuery) (*store.SSHKeySearchResult, error)
	ListCryptoLibraries(ctx context.Context, query store.LibrarySearchQuery) (*store.LibrarySearchResult, error)
	ListCryptoConfigs(ctx context.Context, query store.ConfigSearchQuery) (*store.ConfigSearchResult, error)
	// CE-flavor: ListProtocolObservations is EE-only (Layer 4.1c).
}

// HostHandler handles host asset endpoints.
type HostHandler struct {
	store hostStore
}

// NewHostHandler constructs a HostHandler.
func NewHostHandler(s hostStore) *HostHandler {
	return &HostHandler{store: s}
}

// List handles GET /hosts
// Query params: os_family, source, status (mapped to HostType), limit, offset, q (search).
func (h *HostHandler) List(w http.ResponseWriter, r *http.Request) {
	q := store.HostSearchQuery{
		Search:   r.URL.Query().Get("q"),
		OSFamily: r.URL.Query().Get("os_family"),
		Source:   r.URL.Query().Get("source"),
		HostType: r.URL.Query().Get("status"),
		Limit:    50,
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

	result, err := h.store.ListHosts(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Get handles GET /hosts/{id}
func (h *HostHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := h.store.GetHost(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if host == nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	writeJSON(w, http.StatusOK, host)
}

// AssetItem is a unified representation of any asset type returned by ListAssets.
type AssetItem struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Label    string `json:"label"`
	Sublabel string `json:"sublabel,omitempty"`
}

// assetsResponse is the envelope returned by ListAssets.
type assetsResponse struct {
	Items []AssetItem `json:"items"`
	Total int         `json:"total"`
}

// ListAssets handles GET /hosts/{id}/assets
// Optional ?type filter: ssh_key, crypto_library, crypto_config.
// Without a type filter all three asset types are queried and merged.
// crypto_protocol is rejected with 400: that asset type is EE-only
// (Layer 4.1c protocol-endpoint scoring).
func (h *HostHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "id")
	typeFilter := r.URL.Query().Get("type")

	if typeFilter == "crypto_protocol" {
		writeError(w, http.StatusBadRequest, "crypto_protocol asset type is EE-only (Layer 4.1c)")
		return
	}

	ctx := r.Context()

	// Verify the host exists first.
	host, err := h.store.GetHost(ctx, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if host == nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}

	var items []AssetItem
	total := 0

	fanAll := typeFilter == ""

	if fanAll || typeFilter == "ssh_key" {
		res, err := h.store.ListSSHKeys(ctx, store.SSHKeySearchQuery{
			HostID: hostID,
			Limit:  1000,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, k := range res.Keys {
			items = append(items, AssetItem{
				Type:     "ssh_key",
				ID:       k.ID,
				Label:    fmt.Sprintf("%s key %s", k.KeyType, k.FingerprintSHA256),
				Sublabel: k.FingerprintSHA256,
			})
		}
		total += res.Total
	}

	if fanAll || typeFilter == "crypto_library" {
		res, err := h.store.ListCryptoLibraries(ctx, store.LibrarySearchQuery{
			HostID: hostID,
			Limit:  1000,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, lib := range res.Libraries {
			items = append(items, AssetItem{
				Type:     "crypto_library",
				ID:       lib.ID,
				Label:    fmt.Sprintf("%s %s", lib.LibraryName, lib.Version),
				Sublabel: lib.PackageName,
			})
		}
		total += res.Total
	}

	if fanAll || typeFilter == "crypto_config" {
		res, err := h.store.ListCryptoConfigs(ctx, store.ConfigSearchQuery{
			HostID: hostID,
			Limit:  1000,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, cfg := range res.Configs {
			items = append(items, AssetItem{
				Type:     "crypto_config",
				ID:       cfg.ID,
				Label:    cfg.ConfigType,
				Sublabel: cfg.FilePath,
			})
		}
		total += res.Total
	}

	// CE-flavor: crypto_protocol asset type is EE-only (Layer 4.1c).
	// The /hosts/{id}/assets endpoint omits protocol_observations rows.

	if items == nil {
		items = []AssetItem{}
	}

	writeJSON(w, http.StatusOK, assetsResponse{
		Items: items,
		Total: total,
	})
}
