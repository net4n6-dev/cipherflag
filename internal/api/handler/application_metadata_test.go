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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type fakeAppMetaStore struct {
	getResult     *store.ApplicationMetadata
	listResult    []store.ApplicationMetadata
	hndlResult    []store.HNDLAtRiskAsset
	getErr        error
	upsertErr     error
	deleteErr     error
	hndlErr       error
	hndlHorizon   int
	upsertCalls   []store.DeclareApplicationMetadataRequest
	deleteCalls   []string
	resolveBatch  map[store.AssetRef]*store.OwnershipResolution
	resolveErr    error
}

func (f *fakeAppMetaStore) GetApplicationMetadata(_ context.Context, _ string) (*store.ApplicationMetadata, error) {
	return f.getResult, f.getErr
}
func (f *fakeAppMetaStore) ListApplicationMetadata(_ context.Context) ([]store.ApplicationMetadata, error) {
	return f.listResult, nil
}
func (f *fakeAppMetaStore) UpsertApplicationMetadata(_ context.Context, req *store.DeclareApplicationMetadataRequest) error {
	if req != nil {
		f.upsertCalls = append(f.upsertCalls, *req)
	}
	return f.upsertErr
}
func (f *fakeAppMetaStore) DeleteApplicationMetadata(_ context.Context, tag string) error {
	f.deleteCalls = append(f.deleteCalls, tag)
	return f.deleteErr
}
func (f *fakeAppMetaStore) ListHNDLAtRiskAssets(_ context.Context, horizon int) ([]store.HNDLAtRiskAsset, error) {
	f.hndlHorizon = horizon
	return f.hndlResult, f.hndlErr
}
func (f *fakeAppMetaStore) ResolveOwnerBatch(_ context.Context, refs []store.AssetRef) (map[store.AssetRef]*store.OwnershipResolution, error) {
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	if f.resolveBatch != nil {
		return f.resolveBatch, nil
	}
	// Default: every ref resolves to Unknown. Keeps the nil-map
	// risk out of the handler when tests don't configure ownership.
	out := make(map[store.AssetRef]*store.OwnershipResolution, len(refs))
	for _, r := range refs {
		out[r] = &store.OwnershipResolution{AssetType: r.AssetType, AssetID: r.AssetID, Unknown: true}
	}
	return out, nil
}

func appMetaAdminCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(),
		middleware.UserContextKeyExported(),
		&model.UserContext{ID: "admin-uuid", Email: "admin@t", Role: "admin"})
	return r.WithContext(ctx)
}

func appMetaViewerCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(),
		middleware.UserContextKeyExported(),
		&model.UserContext{ID: "viewer-uuid", Email: "v@t", Role: "viewer"})
	return r.WithContext(ctx)
}

// ── GET /applications/{tag}/metadata ──────────────────────────────────

func TestAppMeta_Get_HappyPath(t *testing.T) {
	ttl := 20
	f := &fakeAppMetaStore{getResult: &store.ApplicationMetadata{
		Tag:          "pii-customer-20y",
		DataTTLYears: &ttl,
		OwnerTeam:    "platform",
	}}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Get("/applications/{tag}/metadata", h.Get)
	req := httptest.NewRequest("GET", "/applications/pii-customer-20y/metadata", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestAppMeta_Get_NotDeclared_Returns404(t *testing.T) {
	f := &fakeAppMetaStore{getResult: nil}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Get("/applications/{tag}/metadata", h.Get)
	req := httptest.NewRequest("GET", "/applications/undeclared-app/metadata", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// ── PUT /applications/{tag}/metadata ──────────────────────────────────

func TestAppMeta_Put_HappyPath(t *testing.T) {
	f := &fakeAppMetaStore{}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Put("/applications/{tag}/metadata", h.Put)

	body := `{"data_ttl_years": 20, "owner_team": "platform", "note": "customer PII"}`
	req := httptest.NewRequest("PUT", "/applications/pii-customer/metadata", bytes.NewBufferString(body))
	req = appMetaAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(f.upsertCalls) != 1 {
		t.Fatalf("upsert calls = %d, want 1", len(f.upsertCalls))
	}
	got := f.upsertCalls[0]
	if got.Tag != "pii-customer" {
		t.Errorf("tag = %q", got.Tag)
	}
	if got.DataTTLYears == nil || *got.DataTTLYears != 20 {
		t.Errorf("ttl = %v, want 20", got.DataTTLYears)
	}
	if got.AddedBy != "admin-uuid" {
		t.Errorf("added_by = %q, want admin-uuid (from JWT context)", got.AddedBy)
	}
}

func TestAppMeta_Put_MissingTTL_Rejects400(t *testing.T) {
	f := &fakeAppMetaStore{}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Put("/applications/{tag}/metadata", h.Put)

	// Both ttl + absolute-date omitted → 400, store not called.
	body := `{"owner_team": "x"}`
	req := httptest.NewRequest("PUT", "/applications/empty-decl/metadata", bytes.NewBufferString(body))
	req = appMetaAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if len(f.upsertCalls) != 0 {
		t.Error("store must not be called when ttl + date missing")
	}
}

func TestAppMeta_Put_InvalidJSON_Rejects400(t *testing.T) {
	f := &fakeAppMetaStore{}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Put("/applications/{tag}/metadata", h.Put)

	req := httptest.NewRequest("PUT", "/applications/any/metadata", bytes.NewBufferString("not json"))
	req = appMetaAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestAppMeta_Put_OutOfRangeTTL_Rejects400(t *testing.T) {
	f := &fakeAppMetaStore{}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Put("/applications/{tag}/metadata", h.Put)

	body := `{"data_ttl_years": 200}`
	req := httptest.NewRequest("PUT", "/applications/x/metadata", bytes.NewBufferString(body))
	req = appMetaAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (out of range)", rr.Code)
	}
}

func TestAppMeta_Put_OversizedNote_Rejects400(t *testing.T) {
	f := &fakeAppMetaStore{}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Put("/applications/{tag}/metadata", h.Put)

	huge := strings.Repeat("x", 3000)
	body := `{"data_ttl_years": 5, "note": "` + huge + `"}`
	req := httptest.NewRequest("PUT", "/applications/x/metadata", bytes.NewBufferString(body))
	req = appMetaAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (note too large)", rr.Code)
	}
}

func TestAppMeta_Put_StoreError_Returns500(t *testing.T) {
	f := &fakeAppMetaStore{upsertErr: errors.New("pg connection died")}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Put("/applications/{tag}/metadata", h.Put)

	body := `{"data_ttl_years": 5}`
	req := httptest.NewRequest("PUT", "/applications/x/metadata", bytes.NewBufferString(body))
	req = appMetaAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// ── DELETE /applications/{tag}/metadata ───────────────────────────────

func TestAppMeta_Delete_HappyPath(t *testing.T) {
	f := &fakeAppMetaStore{}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Delete("/applications/{tag}/metadata", h.Delete)

	req := httptest.NewRequest("DELETE", "/applications/gdpr-eu/metadata", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if len(f.deleteCalls) != 1 || f.deleteCalls[0] != "gdpr-eu" {
		t.Errorf("delete calls = %v, want [gdpr-eu]", f.deleteCalls)
	}
}

// ── GET /analysis/hndl ────────────────────────────────────────────────

func TestAppMeta_ListHNDL_DefaultHorizonIsCRQC(t *testing.T) {
	f := &fakeAppMetaStore{hndlResult: []store.HNDLAtRiskAsset{
		{AssetID: "a1", Unscoped: false, MaxTTLYears: 20},
		{AssetID: "a2", Unscoped: true},
		{AssetID: "a3", Unscoped: false, MaxTTLYears: 25},
	}}
	h := NewApplicationMetadataHandler(f)

	req := httptest.NewRequest("GET", "/analysis/hndl", nil)
	rr := httptest.NewRecorder()
	h.ListHNDL(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if f.hndlHorizon != DefaultCRQCHorizonYear {
		t.Errorf("store horizon = %d, want %d (default)", f.hndlHorizon, DefaultCRQCHorizonYear)
	}

	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["total"] != float64(3) {
		t.Errorf("total = %v, want 3", body["total"])
	}
	if body["at_risk"] != float64(2) {
		t.Errorf("at_risk = %v, want 2", body["at_risk"])
	}
	if body["unscoped"] != float64(1) {
		t.Errorf("unscoped = %v, want 1", body["unscoped"])
	}
	if body["crqc_horizon_year"] != float64(DefaultCRQCHorizonYear) {
		t.Errorf("crqc_horizon_year = %v, want %d", body["crqc_horizon_year"], DefaultCRQCHorizonYear)
	}
}

func TestAppMeta_ListHNDL_HorizonParamOverride(t *testing.T) {
	f := &fakeAppMetaStore{hndlResult: nil}
	h := NewApplicationMetadataHandler(f)

	req := httptest.NewRequest("GET", "/analysis/hndl?horizon=2040", nil)
	rr := httptest.NewRecorder()
	h.ListHNDL(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if f.hndlHorizon != 2040 {
		t.Errorf("store horizon = %d, want 2040", f.hndlHorizon)
	}

	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["crqc_horizon_year"] != float64(2040) {
		t.Errorf("response horizon echo = %v, want 2040", body["crqc_horizon_year"])
	}
}

func TestAppMeta_ListHNDL_HorizonInvalid_Rejects400(t *testing.T) {
	f := &fakeAppMetaStore{}
	h := NewApplicationMetadataHandler(f)

	cases := []string{"abc", "1999", "2200", ""}
	// Empty string would default to DefaultCRQCHorizonYear, so drop it.
	cases = cases[:len(cases)-1]
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/analysis/hndl?horizon="+c, nil)
			rr := httptest.NewRecorder()
			h.ListHNDL(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("horizon=%q: status = %d, want 400", c, rr.Code)
			}
		})
	}
}

func TestAppMeta_ListHNDL_NilResult_SerialisesEmptyArray(t *testing.T) {
	f := &fakeAppMetaStore{hndlResult: nil}
	h := NewApplicationMetadataHandler(f)

	req := httptest.NewRequest("GET", "/analysis/hndl", nil)
	rr := httptest.NewRecorder()
	h.ListHNDL(rr, req)

	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	arr, ok := body["assets"].([]any)
	if !ok {
		t.Fatalf("assets not an array: %T (body=%s)", body["assets"], rr.Body.String())
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array, got %d", len(arr))
	}
}

// ── Admin-only regression gate ────────────────────────────────────────

// TestAppMeta_PutAndDelete_ViewerBlockedAt403 documents that the
// admin-only enforcement lives on the route wiring in server.go, not
// in the handler. Assembles the same middleware chain server.go uses
// and confirms a viewer is rejected with 403 before reaching the store.
func TestAppMeta_PutAndDelete_ViewerBlockedAt403(t *testing.T) {
	f := &fakeAppMetaStore{}
	h := NewApplicationMetadataHandler(f)

	router := chi.NewRouter()
	router.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Put("/applications/{tag}/metadata", h.Put)
		r.Delete("/applications/{tag}/metadata", h.Delete)
	})

	putReq := appMetaViewerCtx(httptest.NewRequest("PUT", "/applications/x/metadata",
		bytes.NewBufferString(`{"data_ttl_years":5}`)))
	putRR := httptest.NewRecorder()
	router.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusForbidden {
		t.Errorf("PUT as viewer: status = %d, want 403", putRR.Code)
	}

	delReq := appMetaViewerCtx(httptest.NewRequest("DELETE", "/applications/x/metadata", nil))
	delRR := httptest.NewRecorder()
	router.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusForbidden {
		t.Errorf("DELETE as viewer: status = %d, want 403", delRR.Code)
	}

	if len(f.upsertCalls) != 0 || len(f.deleteCalls) != 0 {
		t.Errorf("store reached despite 403; upsert=%d delete=%d",
			len(f.upsertCalls), len(f.deleteCalls))
	}
}

// ── v1.8.0: HNDL response enriched with owner fields (§2.7) ─────────

// TestAppMeta_ListHNDL_RowsIncludeOwnerFields asserts that each
// row in the response carries owner_team + owner_confidence when
// the resolver returns a Primary claim.
func TestAppMeta_ListHNDL_RowsIncludeOwnerFields(t *testing.T) {
	f := &fakeAppMetaStore{
		hndlResult: []store.HNDLAtRiskAsset{
			{AssetType: "certificate", AssetID: "fp-a", Label: "a.example.com", Algorithm: "RSA-2048"},
			{AssetType: "certificate", AssetID: "fp-b", Label: "b.example.com", Algorithm: "RSA-2048", Unscoped: true},
		},
		resolveBatch: map[store.AssetRef]*store.OwnershipResolution{
			{AssetType: "certificate", AssetID: "fp-a"}: {
				Primary: &store.OwnershipClaim{Team: "payments", Confidence: "attested"},
			},
			// fp-b deliberately maps to an unknown resolution.
			{AssetType: "certificate", AssetID: "fp-b"}: {Unknown: true},
		},
	}
	h := NewApplicationMetadataHandler(f)

	req := httptest.NewRequest("GET", "/analysis/hndl", nil)
	rr := httptest.NewRecorder()
	h.ListHNDL(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	rows, _ := body["assets"].([]any)
	if len(rows) != 2 {
		t.Fatalf("row count = %d, want 2", len(rows))
	}
	r0, _ := rows[0].(map[string]any)
	if r0["owner_team"] != "payments" || r0["owner_confidence"] != "attested" {
		t.Errorf("row 0 owner fields = %v / %v, want payments / attested",
			r0["owner_team"], r0["owner_confidence"])
	}
	r1, _ := rows[1].(map[string]any)
	if r1["owner_team"] != nil && r1["owner_team"] != "" {
		t.Errorf("row 1 owner_team = %v, want empty (unknown resolution)", r1["owner_team"])
	}
}

// TestAppMeta_ListHNDL_UnownedCount asserts the envelope exposes a
// unowned counter matching the §2.7 predicate: empty owner_team OR
// confidence=observed.
func TestAppMeta_ListHNDL_UnownedCount(t *testing.T) {
	f := &fakeAppMetaStore{
		hndlResult: []store.HNDLAtRiskAsset{
			{AssetType: "certificate", AssetID: "fp-attested"},
			{AssetType: "certificate", AssetID: "fp-observed"},
			{AssetType: "certificate", AssetID: "fp-none"},
		},
		resolveBatch: map[store.AssetRef]*store.OwnershipResolution{
			{AssetType: "certificate", AssetID: "fp-attested"}: {
				Primary: &store.OwnershipClaim{Team: "ok-team", Confidence: "attested"},
			},
			{AssetType: "certificate", AssetID: "fp-observed"}: {
				Primary: &store.OwnershipClaim{Team: "low-trust", Confidence: "observed"},
			},
			{AssetType: "certificate", AssetID: "fp-none"}: {Unknown: true},
		},
	}
	h := NewApplicationMetadataHandler(f)

	req := httptest.NewRequest("GET", "/analysis/hndl", nil)
	rr := httptest.NewRecorder()
	h.ListHNDL(rr, req)

	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if got, want := int(body["unowned"].(float64)), 2; got != want {
		t.Errorf("unowned = %d, want %d (observed-only + unknown both count)", got, want)
	}
}

// TestAppMeta_ListHNDL_ResolverError_Returns500 asserts the batch
// resolver's error is a hard failure — we don't want a silent
// degradation to a partially-empty ownership column.
func TestAppMeta_ListHNDL_ResolverError_Returns500(t *testing.T) {
	f := &fakeAppMetaStore{
		hndlResult: []store.HNDLAtRiskAsset{{AssetType: "certificate", AssetID: "x"}},
		resolveErr: errors.New("resolver exploded"),
	}
	h := NewApplicationMetadataHandler(f)

	req := httptest.NewRequest("GET", "/analysis/hndl", nil)
	rr := httptest.NewRecorder()
	h.ListHNDL(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}
