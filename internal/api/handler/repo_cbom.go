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

	"github.com/google/uuid"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// RepoCBOMStore is the narrow surface this handler depends on. The
// generator only needs ListRepositoryFindings.
type RepoCBOMStore interface {
	ListRepositoryFindings(ctx context.Context, q store.RepoFindingQuery) ([]store.RepoFindingRow, error)
}

// RepoCBOMHandler serves GET /api/v1/repo/exports/cbom?repo_id=<uuid>.
// Streams a CycloneDX 1.6 JSON document containing one algorithm component
// per unique B3 algorithm in the repository.
type RepoCBOMHandler struct {
	store RepoCBOMStore
	gen   *cbom.Generator
}

// NewRepoCBOMHandler constructs the handler. When signingCfg.Enabled is true,
// each repo CBOM download is signed with the configured key.
func NewRepoCBOMHandler(s RepoCBOMStore, signingCfg ...config.CBOMSigningConfig) *RepoCBOMHandler {
	var cfg config.CBOMSigningConfig
	if len(signingCfg) > 0 {
		cfg = signingCfg[0]
	}
	gen, err := cbom.NewGeneratorWithSigning(cfg)
	if err != nil {
		panic("repo cbom handler: " + err.Error())
	}
	return &RepoCBOMHandler{store: s, gen: gen}
}

func (h *RepoCBOMHandler) Download(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Query().Get("repo_id")
	if repoID == "" {
		writeError(w, http.StatusBadRequest, "repo_id required")
		return
	}
	if _, err := uuid.Parse(repoID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid repo_id (not a UUID): "+repoID)
		return
	}

	bom, err := h.gen.GenerateForRepo(r.Context(), h.store, repoID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json; version=1.6")
	w.Header().Set("Content-Disposition", `attachment; filename="`+repoID+`.cdx.json"`)
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(bom)
}
