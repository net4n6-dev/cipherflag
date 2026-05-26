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

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type ScansStore interface {
	GetRepository(ctx context.Context, id string) (*model.Repository, error)
	EnqueueScanJob(ctx context.Context, j *model.ScanJob) error
	GetScanJob(ctx context.Context, id string) (*model.ScanJob, error)
	ListScanJobs(ctx context.Context, q store.ScanJobQuery) ([]model.ScanJob, error)
	CancelScanJob(ctx context.Context, id string) error
}

// AIRuntime is retained as a zero-valued placeholder so callers wired
// against the EE handler signature still compile. CE never sets
// Enabled=true; the pre-flight gate in Create() simply rejects any
// non-deterministic scan mode.
type AIRuntime struct {
	Enabled       bool
	Provider      string
	Model         string
	PerScanMaxUSD float64
}

// pricingTable is the EE-only pricing.Table type, opaque to CE.
// The constructor accepts `any` so server.go can pass nil without an
// import on the EE pricing package.
type pricingTable = any

type ScansHandler struct {
	store ScansStore
	aiCfg AIRuntime
}

// NewScansHandler — CE-flavor. The second arg matches the EE signature
// shape for source-level compatibility; the pricing table is ignored.
func NewScansHandler(s ScansStore, ai AIRuntime, _ pricingTable) *ScansHandler {
	return &ScansHandler{store: s, aiCfg: ai}
}

type createScanRequest struct {
	RepoID    string `json:"repo_id"`
	ScanMode  string `json:"scan_mode,omitempty"`
	BranchRef string `json:"branch_ref,omitempty"`
	Confirm   bool   `json:"confirm,omitempty"`
}

func (h *ScansHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if req.RepoID == "" {
		writeError(w, http.StatusBadRequest, "repo_id required")
		return
	}
	repo, err := h.store.GetRepository(r.Context(), req.RepoID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if repo == nil {
		writeError(w, http.StatusBadRequest, "repo not found")
		return
	}
	if req.ScanMode == "" {
		req.ScanMode = repo.DefaultScanMode
	}
	if req.ScanMode == "" {
		req.ScanMode = model.ScanModeDeterministicOnly
	}
	if !model.IsValidScanMode(req.ScanMode) {
		writeError(w, http.StatusBadRequest, "invalid scan_mode "+req.ScanMode)
		return
	}
	// CE-flavor: AI tier is EE-only. Any non-deterministic scan mode is
	// rejected with 409 Conflict — operators must explicitly select the
	// deterministic-only mode (default).
	if req.ScanMode != model.ScanModeDeterministicOnly {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":     "AI-enriched scan modes require CipherFlag EE",
			"scan_mode": req.ScanMode,
		})
		return
	}
	if req.BranchRef == "" {
		req.BranchRef = repo.DefaultBranch
	}
	j := &model.ScanJob{
		RepoID:    req.RepoID,
		ScanMode:  req.ScanMode,
		Trigger:   model.TriggerManual,
		BranchRef: req.BranchRef,
	}
	if err := h.store.EnqueueScanJob(r.Context(), j); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, j)
}

func (h *ScansHandler) List(w http.ResponseWriter, r *http.Request) {
	q := store.ScanJobQuery{
		RepoID: r.URL.Query().Get("repo_id"),
		Status: r.URL.Query().Get("status"),
	}
	q.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	q.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	out, err := h.store.ListScanJobs(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []model.ScanJob{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": out})
}

func (h *ScansHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	j, err := h.store.GetScanJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if j == nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, j)
}

func (h *ScansHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	if err := h.store.CancelScanJob(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancel_attempted"})
}
