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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
	cbomimport "github.com/net4n6-dev/cipherflag/internal/import/cbom"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type fakeCBOMGen struct {
	bom *cdx.BOM
	err error
}

func (f *fakeCBOMGen) Generate(_ context.Context, _ store.CryptoStore, _ *cbom.Scope) (*cdx.BOM, error) {
	return f.bom, f.err
}

func newTestCBOMHandler(gen cbomGenerator, cfg *config.CBOMConfig) *CBOMHandler {
	return &CBOMHandler{gen: gen, cfg: cfg}
}

func minimalTestBOM() *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	return bom
}

func TestCBOMHandler_Download_NamedScope_200(t *testing.T) {
	gen := &fakeCBOMGen{bom: minimalTestBOM()}
	cfg := &config.CBOMConfig{
		Scopes: []config.ScopeConfig{{Name: "prod"}},
	}
	h := newTestCBOMHandler(gen, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom?scope=prod", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/vnd.cyclonedx+json") {
		t.Errorf("Content-Type = %q, want application/vnd.cyclonedx+json prefix", ct)
	}
}

func TestCBOMHandler_Download_UnknownScope_400(t *testing.T) {
	gen := &fakeCBOMGen{bom: minimalTestBOM()}
	cfg := &config.CBOMConfig{
		Scopes: []config.ScopeConfig{{Name: "prod"}},
	}
	h := newTestCBOMHandler(gen, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom?scope=nonexistent", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestCBOMHandler_Download_InvalidHostID_400(t *testing.T) {
	gen := &fakeCBOMGen{bom: minimalTestBOM()}
	cfg := &config.CBOMConfig{}
	h := newTestCBOMHandler(gen, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom?host_id=not-a-uuid", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestCBOMHandler_Download_InvalidAssetType_400(t *testing.T) {
	gen := &fakeCBOMGen{bom: minimalTestBOM()}
	cfg := &config.CBOMConfig{}
	h := newTestCBOMHandler(gen, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom?asset_type=widget", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestCBOMHandler_Download_BothScopeAndAdHoc_400(t *testing.T) {
	gen := &fakeCBOMGen{bom: minimalTestBOM()}
	cfg := &config.CBOMConfig{
		Scopes: []config.ScopeConfig{{Name: "prod"}},
	}
	h := newTestCBOMHandler(gen, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom?scope=prod&asset_type=certificate", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when scope and ad-hoc params mixed", rr.Code)
	}
}

func TestCBOMHandler_Download_AdHocFilter_200(t *testing.T) {
	gen := &fakeCBOMGen{bom: minimalTestBOM()}
	cfg := &config.CBOMConfig{}
	h := newTestCBOMHandler(gen, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom?asset_type=certificate", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
}

// --- Import tests ---

// fakeCBOMStore is a minimal store.CryptoStore fake used by Import tests.
// Only GetHost is implemented; other methods fall through to the embedded
// interface and panic if called.
type fakeCBOMStore struct {
	store.CryptoStore
	host *model.Host
}

func (f *fakeCBOMStore) GetHost(_ context.Context, id string) (*model.Host, error) {
	if f.host != nil && f.host.ID == id {
		return f.host, nil
	}
	return nil, nil
}

// fakeCBOMImporter captures Import calls and returns a pre-set result.
type fakeCBOMImporter struct {
	received ImportCall
	result   *cbomimport.ImportResult
	err      error
}

type ImportCall struct {
	Body string
	Opts cbomimport.ImportOptions
}

func (f *fakeCBOMImporter) Import(_ context.Context, r io.Reader, opts cbomimport.ImportOptions) (*cbomimport.ImportResult, error) {
	body, _ := io.ReadAll(r)
	f.received = ImportCall{Body: string(body), Opts: opts}
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func TestImport_Hostless(t *testing.T) {
	fi := &fakeCBOMImporter{result: &cbomimport.ImportResult{
		Source:   "cbom_import",
		Imported: cbomimport.ImportedCounts{CertificatesNew: 5},
	}}
	h := &CBOMHandler{store: &fakeCBOMStore{}, importer: fi, cfg: &config.CBOMConfig{}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/cbom", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if fi.received.Opts.HostID != "" {
		t.Errorf("Opts.HostID = %q, want empty", fi.received.Opts.HostID)
	}
	var resp cbomimport.ImportResult
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Imported.CertificatesNew != 5 {
		t.Errorf("CertificatesNew = %d, want 5", resp.Imported.CertificatesNew)
	}
}

func TestImport_HostIDValidUUID(t *testing.T) {
	hostUUID := "550e8400-e29b-41d4-a716-446655440000"
	fi := &fakeCBOMImporter{result: &cbomimport.ImportResult{Source: "cbom_import", HostID: hostUUID}}
	st := &fakeCBOMStore{host: &model.Host{ID: hostUUID}}
	h := &CBOMHandler{store: st, importer: fi, cfg: &config.CBOMConfig{}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/cbom?host_id="+hostUUID, strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if fi.received.Opts.HostID != hostUUID {
		t.Errorf("Opts.HostID = %q, want %q", fi.received.Opts.HostID, hostUUID)
	}
}

func TestImport_HostIDInvalid(t *testing.T) {
	h := &CBOMHandler{store: &fakeCBOMStore{}, importer: &fakeCBOMImporter{}, cfg: &config.CBOMConfig{}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/cbom?host_id=not-a-uuid", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", w.Code)
	}
}

func TestImport_HostIDNotFound(t *testing.T) {
	hostUUID := "550e8400-e29b-41d4-a716-446655440000"
	h := &CBOMHandler{store: &fakeCBOMStore{host: nil}, importer: &fakeCBOMImporter{}, cfg: &config.CBOMConfig{}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/cbom?host_id="+hostUUID, strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", w.Code)
	}
}

func TestImport_MalformedBody(t *testing.T) {
	fi := &fakeCBOMImporter{err: fmt.Errorf("cbom import: decode: unexpected EOF")}
	h := &CBOMHandler{store: &fakeCBOMStore{}, importer: fi, cfg: &config.CBOMConfig{}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/cbom", strings.NewReader("{{{"))
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", w.Code)
	}
}

func TestImport_ImporterNil(t *testing.T) {
	h := &CBOMHandler{store: &fakeCBOMStore{}, importer: nil, cfg: &config.CBOMConfig{}}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/cbom", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500", w.Code)
	}
}
