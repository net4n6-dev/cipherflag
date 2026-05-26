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
	"errors"
	"io"
	"net/http"
	"strconv"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
	cbomimport "github.com/net4n6-dev/cipherflag/internal/import/cbom"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

const cbomContentType = "application/vnd.cyclonedx+json; version=1.6"

// cbomGenerator is the minimal interface the handler needs.
// *cbom.Generator satisfies it. Tests inject a fake.
type cbomGenerator interface {
	Generate(ctx context.Context, st store.CryptoStore, scope *cbom.Scope) (*cdx.BOM, error)
}

// cbomImporterIface is the minimal interface the handler needs for imports.
// *cbomimport.Importer satisfies it. Tests inject a fake.
type cbomImporterIface interface {
	Import(ctx context.Context, r io.Reader, opts cbomimport.ImportOptions) (*cbomimport.ImportResult, error)
}

// CBOMHandler serves GET /api/v1/export/cbom and POST /api/v1/import/cbom.
type CBOMHandler struct {
	store    store.CryptoStore
	gen      cbomGenerator
	importer cbomImporterIface
	cfg      *config.CBOMConfig
}

// NewCBOMHandler constructs the handler. Importer may be nil if the
// import endpoint is not wired (the Download handler works standalone).
// When cfg.Signing.Enabled is true, each on-demand CBOM download is signed.
func NewCBOMHandler(st store.CryptoStore, cfg *config.CBOMConfig, importer cbomImporterIface) *CBOMHandler {
	gen, err := cbom.NewGeneratorWithSigning(cfg.Signing)
	if err != nil {
		// Signing misconfiguration is a startup error — fail fast so the
		// operator sees a clear message rather than silently unsigned BOMs.
		panic("cbom handler: " + err.Error())
	}
	return &CBOMHandler{
		store:    st,
		gen:      gen,
		importer: importer,
		cfg:      cfg,
	}
}

// Download handles GET /api/v1/export/cbom.
// Accepts either a named `scope` param (resolved from config) or ad-hoc filter
// params (host_id, hostname_pattern, asset_type, min_risk_score).
// Mixing both is a 400.
func (h *CBOMHandler) Download(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	scopeName := q.Get("scope")
	hostID := q.Get("host_id")
	hostnamePattern := q.Get("hostname_pattern")
	assetType := q.Get("asset_type")
	minRiskScoreStr := q.Get("min_risk_score")

	hasAdHoc := hostID != "" || hostnamePattern != "" || assetType != "" || minRiskScoreStr != ""

	if scopeName != "" && hasAdHoc {
		writeError(w, http.StatusBadRequest, "scope and ad-hoc filter params are mutually exclusive")
		return
	}

	var scope *cbom.Scope

	if scopeName != "" {
		found := false
		for _, sc := range h.cfg.Scopes {
			if sc.Name == scopeName {
				s := cbom.ScopesFromConfig([]config.ScopeConfig{sc})[0]
				scope = &s
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusBadRequest, "unknown scope: "+scopeName)
			return
		}
	} else {
		adHoc := cbom.Scope{Name: "ad-hoc"}

		if hostID != "" {
			if _, err := uuid.Parse(hostID); err != nil {
				writeError(w, http.StatusBadRequest, "invalid 'host_id' (not a UUID): "+hostID)
				return
			}
			adHoc.HostIDs = []string{hostID}
		}
		if hostnamePattern != "" {
			adHoc.HostPatterns = []string{hostnamePattern}
		}
		if assetType != "" {
			switch assetType {
			case "certificate", "ssh_key", "crypto_library", "crypto_protocol", "crypto_config":
			default:
				writeError(w, http.StatusBadRequest, "invalid 'asset_type': "+assetType)
				return
			}
			adHoc.AssetTypes = []string{assetType}
		}
		if minRiskScoreStr != "" {
			n, err := strconv.Atoi(minRiskScoreStr)
			if err != nil || n < 0 || n > 100 {
				writeError(w, http.StatusBadRequest, "invalid 'min_risk_score' (must be 0..100): "+minRiskScoreStr)
				return
			}
			adHoc.MinRiskScore = n
		}
		scope = &adHoc
	}

	bom, err := h.gen.Generate(r.Context(), h.store, scope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CBOM generation failed")
		return
	}

	w.Header().Set("Content-Type", cbomContentType)
	w.WriteHeader(http.StatusOK)
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(false)
	if err := enc.Encode(bom); err != nil {
		// Headers already sent — cannot change status. Log and drop.
		_ = err
	}
}

// cbomImportMaxSize is the body size cap for POST /api/v1/import/cbom.
const cbomImportMaxSize = 50 << 20 // 50 MB

// Import handles POST /api/v1/import/cbom.
// Accepts a CycloneDX BOM in the request body.
// Optional ?host_id=<uuid> enables full asset-type import against that host.
// Without host_id, only certificates are imported; SSH/libs/configs are counted as skipped.
func (h *CBOMHandler) Import(w http.ResponseWriter, r *http.Request) {
	if h.importer == nil {
		writeError(w, http.StatusInternalServerError, "cbom import: not configured")
		return
	}

	hostID := r.URL.Query().Get("host_id")
	if hostID != "" {
		if _, err := uuid.Parse(hostID); err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'host_id' (not a UUID): "+hostID)
			return
		}
		host, err := h.store.GetHost(r.Context(), hostID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "lookup host: "+err.Error())
			return
		}
		if host == nil {
			writeError(w, http.StatusNotFound, "host not found: "+hostID)
			return
		}
	}

	// Cap body size.
	r.Body = http.MaxBytesReader(w, r.Body, cbomImportMaxSize)
	defer r.Body.Close()

	result, err := h.importer.Import(r.Context(), r.Body, cbomimport.ImportOptions{HostID: hostID})
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "body exceeds 50 MB limit")
			return
		}
		writeError(w, http.StatusBadRequest, "cbom import: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}
