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
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// ProviderStore is the narrow store surface this handler depends on. It is a
// subset of store.CryptoStore, declared here so handler tests can satisfy it
// with a ~50-line fake instead of hand-maintaining every CryptoStore method.
type ProviderStore interface {
	UpsertProvider(ctx context.Context, p *model.Provider) error
	GetProvider(ctx context.Context, id string) (*model.Provider, error)
	FindProviderByKindURL(ctx context.Context, kind, baseURL string) (*model.Provider, error)
	ListProviders(ctx context.Context) ([]model.Provider, error)
	DeleteProvider(ctx context.Context, id string) error
}

// ProvidersHandler implements the `/api/v1/repo/providers/*` endpoints.
// Layer 6.1b-4 will extend this handler with the `POST /{id}/discover` route.
type ProvidersHandler struct {
	store ProviderStore
}

func NewProvidersHandler(s ProviderStore) *ProvidersHandler {
	return &ProvidersHandler{store: s}
}

type createProviderRequest struct {
	Kind          string `json:"kind"`
	BaseURL       string `json:"base_url"`
	AuthSecretRef string `json:"auth_secret_ref"`
	DisplayName   string `json:"display_name,omitempty"`
}

// Create — POST /api/v1/repo/providers
func (h *ProvidersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	req.Kind = strings.TrimSpace(req.Kind)
	req.BaseURL = strings.TrimRight(strings.TrimSpace(req.BaseURL), "/")
	req.AuthSecretRef = strings.TrimSpace(req.AuthSecretRef)

	if req.Kind == "" {
		writeError(w, http.StatusBadRequest, "kind is required")
		return
	}
	if !model.IsValidProviderKind(req.Kind) {
		writeError(w, http.StatusBadRequest, "invalid provider kind "+req.Kind)
		return
	}
	if req.BaseURL == "" {
		writeError(w, http.StatusBadRequest, "base_url is required")
		return
	}
	if req.AuthSecretRef == "" {
		writeError(w, http.StatusBadRequest, "auth_secret_ref is required")
		return
	}

	// Duplicate check (409 Conflict is friendlier than hitting the UNIQUE
	// constraint and returning 500).
	if existing, err := h.store.FindProviderByKindURL(r.Context(), req.Kind, req.BaseURL); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if existing != nil {
		writeError(w, http.StatusConflict, "provider already exists for this kind + base_url")
		return
	}

	p := &model.Provider{
		Kind:          req.Kind,
		BaseURL:       req.BaseURL,
		AuthSecretRef: req.AuthSecretRef,
		DisplayName:   req.DisplayName,
	}
	if err := h.store.UpsertProvider(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// List — GET /api/v1/repo/providers
func (h *ProvidersHandler) List(w http.ResponseWriter, r *http.Request) {
	ps, err := h.store.ListProviders(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ps == nil {
		ps = []model.Provider{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": ps})
}

// Get — GET /api/v1/repo/providers/{id}
func (h *ProvidersHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	p, err := h.store.GetProvider(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p == nil {
		writeError(w, http.StatusNotFound, "provider not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// Delete — DELETE /api/v1/repo/providers/{id}
func (h *ProvidersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	if err := h.store.DeleteProvider(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
