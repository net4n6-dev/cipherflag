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
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/robfig/cron/v3"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// RepositoriesStore is the narrow interface this handler depends on.
type RepositoriesStore interface {
	GetProvider(ctx context.Context, id string) (*model.Provider, error)
	UpsertRepository(ctx context.Context, r *model.Repository) error
	GetRepository(ctx context.Context, id string) (*model.Repository, error)
	FindRepositoryByURL(ctx context.Context, providerID, url string) (*model.Repository, error)
	ListRepositories(ctx context.Context, providerID string, limit, offset int) ([]model.Repository, error)
	DeleteRepository(ctx context.Context, id string) error
}

type RepositoriesHandler struct{ store RepositoriesStore }

func NewRepositoriesHandler(s RepositoriesStore) *RepositoriesHandler {
	return &RepositoriesHandler{store: s}
}

type createRepoRequest struct {
	ProviderID      string            `json:"provider_id"`
	URL             string            `json:"url"`
	DefaultBranch   string            `json:"default_branch"`
	DefaultScanMode string            `json:"default_scan_mode"`
	ScheduleCron    string            `json:"schedule_cron,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	AuthSecretRef   string            `json:"auth_secret_ref,omitempty"`
}

// Cron parser shared across validate sites. Standard cron (5 fields) + descriptors.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

func (h *RepositoriesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createRepoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	req.URL = strings.TrimRight(strings.TrimSpace(req.URL), "/")

	if req.ProviderID == "" {
		writeError(w, http.StatusBadRequest, "provider_id required")
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "url required")
		return
	}
	if req.DefaultBranch == "" {
		req.DefaultBranch = "main"
	}
	if req.DefaultScanMode == "" {
		req.DefaultScanMode = model.ScanModeDeterministicOnly
	}
	if !model.IsValidScanMode(req.DefaultScanMode) {
		writeError(w, http.StatusBadRequest, "invalid default_scan_mode "+req.DefaultScanMode)
		return
	}
	if req.ScheduleCron != "" {
		if _, err := cronParser.Parse(req.ScheduleCron); err != nil {
			writeError(w, http.StatusBadRequest, "invalid schedule_cron: "+err.Error())
			return
		}
	}
	prov, err := h.store.GetProvider(r.Context(), req.ProviderID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if prov == nil {
		writeError(w, http.StatusBadRequest, "provider_id not found")
		return
	}
	if existing, err := h.store.FindRepositoryByURL(r.Context(), req.ProviderID, req.URL); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if existing != nil {
		writeError(w, http.StatusConflict, "repository already registered under this provider")
		return
	}
	repo := &model.Repository{
		ProviderID:      req.ProviderID,
		URL:             req.URL,
		DefaultBranch:   req.DefaultBranch,
		DefaultScanMode: req.DefaultScanMode,
		ScheduleCron:    req.ScheduleCron,
		Tags:            req.Tags,
		AuthSecretRef:   req.AuthSecretRef,
	}
	if err := h.store.UpsertRepository(r.Context(), repo); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, repo)
}

func (h *RepositoriesHandler) List(w http.ResponseWriter, r *http.Request) {
	providerID := r.URL.Query().Get("provider_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 100
	}
	out, err := h.store.ListRepositories(r.Context(), providerID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []model.Repository{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"repositories": out})
}

func (h *RepositoriesHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	got, err := h.store.GetRepository(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if got == nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	writeJSON(w, http.StatusOK, got)
}

type patchRepoRequest struct {
	ScheduleCron    *string            `json:"schedule_cron,omitempty"`
	DefaultScanMode *string            `json:"default_scan_mode,omitempty"`
	Tags            *map[string]string `json:"tags,omitempty"`
	AuthSecretRef   *string            `json:"auth_secret_ref,omitempty"`
}

func (h *RepositoriesHandler) Patch(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	existing, err := h.store.GetRepository(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	var req patchRepoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.ScheduleCron != nil {
		s := strings.TrimSpace(*req.ScheduleCron)
		if s != "" {
			if _, err := cronParser.Parse(s); err != nil {
				writeError(w, http.StatusBadRequest, "invalid schedule_cron: "+err.Error())
				return
			}
		}
		existing.ScheduleCron = s
	}
	if req.DefaultScanMode != nil {
		if !model.IsValidScanMode(*req.DefaultScanMode) {
			writeError(w, http.StatusBadRequest, "invalid default_scan_mode "+*req.DefaultScanMode)
			return
		}
		existing.DefaultScanMode = *req.DefaultScanMode
	}
	if req.Tags != nil {
		existing.Tags = *req.Tags
	}
	if req.AuthSecretRef != nil {
		existing.AuthSecretRef = *req.AuthSecretRef
	}
	if err := h.store.UpsertRepository(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, existing)
}

func (h *RepositoriesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	if err := h.store.DeleteRepository(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
