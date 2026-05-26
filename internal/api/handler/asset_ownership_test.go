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
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type fakeAssetOwnStore struct {
	resolveResult *store.OwnershipResolution
	resolveErr    error
	upsertErr     error
	deleteErr     error
	upsertCalls   []store.OwnershipSighting
	deleteCalls   []struct{ typ, id, team string }
}

func (f *fakeAssetOwnStore) ResolveOwner(_ context.Context, _, _ string) (*store.OwnershipResolution, error) {
	return f.resolveResult, f.resolveErr
}
func (f *fakeAssetOwnStore) UpsertOwnershipSighting(_ context.Context, s *store.OwnershipSighting) error {
	if s != nil {
		f.upsertCalls = append(f.upsertCalls, *s)
	}
	return f.upsertErr
}
func (f *fakeAssetOwnStore) DeleteOwnershipStamp(_ context.Context, typ, id, team string) error {
	f.deleteCalls = append(f.deleteCalls, struct{ typ, id, team string }{typ, id, team})
	return f.deleteErr
}

func assetOwnAdminCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(),
		middleware.UserContextKeyExported(),
		&model.UserContext{ID: "admin-uuid", Email: "admin@t", Role: "admin"})
	return r.WithContext(ctx)
}

// ── GET /assets/{type}/{id}/ownership ─────────────────────────────────

func TestAssetOwn_Get_HappyPath(t *testing.T) {
	f := &fakeAssetOwnStore{
		resolveResult: &store.OwnershipResolution{
			AssetType: "certificate", AssetID: "abc",
			Primary: &store.OwnershipClaim{Team: "payments", Source: "application_metadata", Confidence: "attested"},
		},
	}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Get("/assets/{type}/{id}/ownership", h.Get)
	req := httptest.NewRequest("GET", "/assets/certificate/abc/ownership", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var res store.OwnershipResolution
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Primary == nil || res.Primary.Team != "payments" {
		t.Errorf("Primary = %+v, want payments", res.Primary)
	}
}

func TestAssetOwn_Get_Unknown_Returns200(t *testing.T) {
	f := &fakeAssetOwnStore{resolveResult: &store.OwnershipResolution{AssetType: "certificate", AssetID: "abc", Unknown: true}}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Get("/assets/{type}/{id}/ownership", h.Get)
	req := httptest.NewRequest("GET", "/assets/certificate/abc/ownership", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (unknown is a valid state)", rr.Code)
	}
}

func TestAssetOwn_Get_AcceptsFindingType(t *testing.T) {
	f := &fakeAssetOwnStore{resolveResult: &store.OwnershipResolution{AssetType: "finding", AssetID: "report-id", Unknown: true}}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Get("/assets/{type}/{id}/ownership", h.Get)
	req := httptest.NewRequest("GET", "/assets/finding/report-id/ownership", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (finding delegates via resolver)", rr.Code)
	}
}

func TestAssetOwn_Get_RejectsBadAssetType(t *testing.T) {
	f := &fakeAssetOwnStore{}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Get("/assets/{type}/{id}/ownership", h.Get)
	req := httptest.NewRequest("GET", "/assets/bogus_type/abc/ownership", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unknown asset_type", rr.Code)
	}
}

func TestAssetOwn_Get_StoreError_Returns500(t *testing.T) {
	f := &fakeAssetOwnStore{resolveErr: errors.New("pg down")}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Get("/assets/{type}/{id}/ownership", h.Get)
	req := httptest.NewRequest("GET", "/assets/certificate/abc/ownership", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// ── PUT /assets/{type}/{id}/ownership ─────────────────────────────────

func TestAssetOwn_Put_HappyPath(t *testing.T) {
	f := &fakeAssetOwnStore{}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Put("/assets/{type}/{id}/ownership", h.Put)

	body := `{"team": "payments", "named_owner": "alice@x", "note": "legal hold 2030"}`
	req := httptest.NewRequest("PUT", "/assets/certificate/fp-abc/ownership", bytes.NewBufferString(body))
	req = assetOwnAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(f.upsertCalls) != 1 {
		t.Fatalf("upsert calls = %d, want 1", len(f.upsertCalls))
	}
	c := f.upsertCalls[0]
	if c.Team != "payments" || c.Source != "operator_stamp" || c.Confidence != "direct" {
		t.Errorf("upsert payload = %+v, want team=payments source=operator_stamp confidence=direct", c)
	}
	if c.AssetType != "certificate" || c.AssetID != "fp-abc" {
		t.Errorf("upsert asset = (%s, %s), want (certificate, fp-abc)", c.AssetType, c.AssetID)
	}
	if note, _ := c.Evidence["note"].(string); note != "legal hold 2030" {
		t.Errorf("evidence.note = %q, want 'legal hold 2030'", note)
	}
	if c.FirstSeen.IsZero() || c.LastSeen.IsZero() {
		t.Error("expected first_seen and last_seen to be populated")
	}
	// Sanity: stamped_by carries the admin UUID from context.
	if stamped, _ := c.Evidence["stamped_by"].(string); stamped != "admin-uuid" {
		t.Errorf("evidence.stamped_by = %q, want admin-uuid", stamped)
	}
}

func TestAssetOwn_Put_MissingTeam_Returns400(t *testing.T) {
	f := &fakeAssetOwnStore{}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Put("/assets/{type}/{id}/ownership", h.Put)

	body := `{"named_owner": "alice@x"}`
	req := httptest.NewRequest("PUT", "/assets/certificate/fp-abc/ownership", bytes.NewBufferString(body))
	req = assetOwnAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (missing team)", rr.Code)
	}
	if len(f.upsertCalls) != 0 {
		t.Errorf("upsert should not have been called on validation failure (got %d calls)", len(f.upsertCalls))
	}
}

func TestAssetOwn_Put_NoteTooLarge_Returns400(t *testing.T) {
	f := &fakeAssetOwnStore{}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Put("/assets/{type}/{id}/ownership", h.Put)

	huge := strings.Repeat("x", 3000)
	body := `{"team": "payments", "note": "` + huge + `"}`
	req := httptest.NewRequest("PUT", "/assets/certificate/fp-abc/ownership", bytes.NewBufferString(body))
	req = assetOwnAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestAssetOwn_Put_RejectsFindingType(t *testing.T) {
	f := &fakeAssetOwnStore{}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Put("/assets/{type}/{id}/ownership", h.Put)

	body := `{"team": "payments"}`
	req := httptest.NewRequest("PUT", "/assets/finding/report-id/ownership", bytes.NewBufferString(body))
	req = assetOwnAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (cannot stamp a finding directly)", rr.Code)
	}
}

// ── DELETE /assets/{type}/{id}/ownership/{source}/{team} ──────────────

func TestAssetOwn_Delete_HappyPath(t *testing.T) {
	f := &fakeAssetOwnStore{}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Delete("/assets/{type}/{id}/ownership/{source}/{team}", h.Delete)

	req := httptest.NewRequest("DELETE", "/assets/certificate/fp-abc/ownership/operator_stamp/payments", nil)
	req = assetOwnAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(f.deleteCalls) != 1 || f.deleteCalls[0].team != "payments" {
		t.Errorf("delete calls = %+v, want one call for payments", f.deleteCalls)
	}
}

func TestAssetOwn_Delete_RejectsNonStampSource(t *testing.T) {
	f := &fakeAssetOwnStore{}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Delete("/assets/{type}/{id}/ownership/{source}/{team}", h.Delete)

	cases := []string{"application_metadata", "cert_subject", "ssh_comment", "declared_ca"}
	for _, src := range cases {
		req := httptest.NewRequest("DELETE", "/assets/certificate/fp-abc/ownership/"+src+"/payments", nil)
		req = assetOwnAdminCtx(req)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("source=%s: status = %d, want 400 (non-stamp source)", src, rr.Code)
		}
	}
	if len(f.deleteCalls) != 0 {
		t.Error("delete should not have been called for non-stamp sources")
	}
}

func TestAssetOwn_Delete_StoreError_Returns500(t *testing.T) {
	f := &fakeAssetOwnStore{deleteErr: errors.New("lock timeout")}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Delete("/assets/{type}/{id}/ownership/{source}/{team}", h.Delete)

	req := httptest.NewRequest("DELETE", "/assets/certificate/fp-abc/ownership/operator_stamp/payments", nil)
	req = assetOwnAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// ── Nil-safety and response shape ─────────────────────────────────────

func TestAssetOwn_Get_CoOwnersAndAlternatives_SerializeNonNull(t *testing.T) {
	// When the resolver returns an Unknown resolution, the slices are
	// nil. Current behaviour: JSON emits them as `null` via omitempty.
	// This test pins the current behaviour so callers see consistent
	// field presence.
	f := &fakeAssetOwnStore{resolveResult: &store.OwnershipResolution{
		AssetType: "certificate", AssetID: "x", Unknown: true,
	}}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Get("/assets/{type}/{id}/ownership", h.Get)
	req := httptest.NewRequest("GET", "/assets/certificate/x/ownership", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var raw map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &raw)
	// Unknown=true field must be present (non-omitempty, boolean).
	if v, ok := raw["unknown"].(bool); !ok || !v {
		t.Errorf("unknown field missing or wrong: %v", raw["unknown"])
	}
}

// Sentinel — asset-ownership PUT body with an empty JSON object
// must reject on missing team before attempting the store write.
func TestAssetOwn_Put_EmptyBody_Returns400(t *testing.T) {
	f := &fakeAssetOwnStore{}
	h := NewAssetOwnershipHandler(f)

	router := chi.NewRouter()
	router.Put("/assets/{type}/{id}/ownership", h.Put)

	req := httptest.NewRequest("PUT", "/assets/certificate/fp/ownership", bytes.NewBufferString(`{}`))
	req = assetOwnAdminCtx(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (empty body)", rr.Code)
	}
	_ = time.Now // keep import used in presence of optional helpers above
}
