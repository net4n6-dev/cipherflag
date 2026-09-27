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
	"regexp"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/go-chi/chi/v5"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/cbomtest"
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

func (f *fakeCBOMGen) GenerateWholeEstate(_ context.Context, _ store.CryptoStore) (*cdx.BOM, error) {
	return f.bom, f.err
}

func (f *fakeCBOMGen) GenerateForApplication(_ context.Context, _ store.CryptoStore, _ string) (*cdx.BOM, error) {
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

func TestCBOMHandler_DownloadEstate_200(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: minimalTestBOM()}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadEstate(rr, httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom/estate", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/vnd.cyclonedx+json") {
		t.Errorf("Content-Type = %q", ct)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !regexp.MustCompile(`^attachment; filename="cipherflag-cbom-estate-\d{4}-\d{2}-\d{2}\.cdx\.json"$`).MatchString(cd) {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if !strings.Contains(rr.Body.String(), `"bomFormat":"CycloneDX"`) {
		t.Errorf("body is not a CycloneDX document: %s", rr.Body.String())
	}
}

func TestCBOMHandler_DownloadEstate_GenerationErrorIs500WithoutDetail(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{err: fmt.Errorf("pq: password authentication failed")}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadEstate(rr, httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom/estate", nil))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "password") {
		t.Errorf("internal error detail leaked to the client: %s", rr.Body.String())
	}
}

func TestCBOMHandler_DownloadEstate_SignedBOMKeepsSignature(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: cbomtest.SignedBOM(t)}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadEstate(rr, httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom/estate", nil))

	cbomtest.AssertValidSignature(t, rr.Body.Bytes())
}

// appRequest builds a request whose chi route context carries the given raw
// (already decoded) tag, as the router would supply it.
func appRequest(tag string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications/x/cbom", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tag", tag)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestCBOMHandler_DownloadApplication_200(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: minimalTestBOM()}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("payments-api"))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rr.Code, rr.Body.String())
	}
	cd := rr.Header().Get("Content-Disposition")
	if !regexp.MustCompile(`^attachment; filename="cipherflag-cbom-app-payments-api-\d{4}-\d{2}-\d{2}\.cdx\.json"$`).MatchString(cd) {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

func TestCBOMHandler_DownloadApplication_UnknownTagIs404(t *testing.T) {
	err := fmt.Errorf("%w: %q", cbom.ErrNoApplicationAssets, "typo")
	h := newTestCBOMHandler(&fakeCBOMGen{err: err}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("typo"))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rr.Code, rr.Body.String())
	}
}

func TestCBOMHandler_DownloadApplication_BlankTagIs400(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: minimalTestBOM()}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("   "))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestCBOMHandler_DownloadApplication_GenerationErrorIs500(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{err: fmt.Errorf("db down")}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("payments-api"))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

// The tag is caller-controlled and lands in a header: quotes, CR/LF and path
// separators must not survive into the filename.
func TestCBOMHandler_DownloadApplication_TagCannotInjectHeaderSyntax(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: minimalTestBOM()}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("a\"b\r\nX-Evil: y/../z"))

	cd := rr.Header().Get("Content-Disposition")
	if !regexp.MustCompile(`^attachment; filename="cipherflag-cbom-app-[A-Za-z0-9._-]+-\d{4}-\d{2}-\d{2}\.cdx\.json"$`).MatchString(cd) {
		t.Errorf("unsafe characters reached Content-Disposition: %q", cd)
	}
}

func TestCBOMHandler_DownloadApplication_SignedBOMKeepsSignature(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: cbomtest.SignedBOM(t)}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.DownloadApplication(rr, appRequest("payments-api"))

	cbomtest.AssertValidSignature(t, rr.Body.Bytes())
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
