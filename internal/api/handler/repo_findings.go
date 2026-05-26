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
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type FindingsStore interface {
	ListRepositoryFindings(ctx context.Context, q store.RepoFindingQuery) ([]store.RepoFindingRow, error)
	GetScanJob(ctx context.Context, id string) (*model.ScanJob, error)
}

type FindingsHandler struct{ store FindingsStore }

func NewFindingsHandler(s FindingsStore) *FindingsHandler { return &FindingsHandler{store: s} }

func (h *FindingsHandler) List(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Query().Get("repo_id")
	// Accept scan_id as an alternative — the UI clicks a scan row, not a
	// repo; resolve it to repo_id server-side.
	if repoID == "" {
		if scanID := r.URL.Query().Get("scan_id"); scanID != "" {
			job, err := h.store.GetScanJob(r.Context(), scanID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if job == nil {
				writeError(w, http.StatusNotFound, "scan not found")
				return
			}
			repoID = job.RepoID
		}
	}
	if repoID == "" {
		writeError(w, http.StatusBadRequest, "repo_id or scan_id required")
		return
	}
	q := store.RepoFindingQuery{
		RepoID:     repoID,
		DetectedBy: r.URL.Query().Get("detected_by"),
	}
	if s := r.URL.Query().Get("severity"); s != "" {
		q.Severities = splitCSV(s)
	}
	if s := r.URL.Query().Get("bucket"); s != "" {
		q.Buckets = splitCSV(s)
	}
	q.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	q.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))

	rows, err := h.store.ListRepositoryFindings(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []store.RepoFindingRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": rows, "count": len(rows)})
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
