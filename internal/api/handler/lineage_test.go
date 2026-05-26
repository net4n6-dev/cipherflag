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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeLineageStore struct {
	fromLinks []model.LineageLink
	toLinks   []model.LineageLink
	fromErr   error
	toErr     error
}

func (f *fakeLineageStore) ListLineageFrom(ctx context.Context, fromAssetType, fromAssetID string) ([]model.LineageLink, error) {
	return f.fromLinks, f.fromErr
}
func (f *fakeLineageStore) ListLineageTo(ctx context.Context, toAssetType, toAssetID string) ([]model.LineageLink, error) {
	return f.toLinks, f.toErr
}

func newLineageRouter(t *testing.T, s lineageStore) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	h := NewLineageHandler(s)
	r.Get("/lineage/{asset_type}/{asset_id}", h.Get)
	return r
}

func TestLineageHandler_BothDirections(t *testing.T) {
	store := &fakeLineageStore{
		fromLinks: []model.LineageLink{
			{FromAssetType: "certificate", FromAssetID: "cert-1", ToAssetType: "host", ToAssetID: "host-a", LinkType: "deployed_on"},
		},
		toLinks: []model.LineageLink{
			{FromAssetType: "repository", FromAssetID: "repo-42", ToAssetType: "certificate", ToAssetID: "cert-1", LinkType: "cert_fingerprint_match"},
		},
	}
	r := newLineageRouter(t, store)
	req := httptest.NewRequest("GET", "/lineage/certificate/cert-1", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		AssetType  string              `json:"asset_type"`
		AssetID    string              `json:"asset_id"`
		Upstream   []model.LineageLink `json:"upstream"`
		Downstream []model.LineageLink `json:"downstream"`
		Total      int                 `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.AssetType != "certificate" || body.AssetID != "cert-1" {
		t.Errorf("wrong identity: %q/%q", body.AssetType, body.AssetID)
	}
	if len(body.Upstream) != 1 || body.Upstream[0].FromAssetType != "repository" {
		t.Errorf("upstream mismatch: %+v", body.Upstream)
	}
	if len(body.Downstream) != 1 || body.Downstream[0].ToAssetType != "host" {
		t.Errorf("downstream mismatch: %+v", body.Downstream)
	}
	if body.Total != 2 {
		t.Errorf("total = %d, want 2", body.Total)
	}
}

func TestLineageHandler_EmptyReturnsArrays(t *testing.T) {
	store := &fakeLineageStore{fromLinks: nil, toLinks: nil}
	r := newLineageRouter(t, store)
	req := httptest.NewRequest("GET", "/lineage/ssh_key/lonely-key", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	// Body must contain `"upstream":[]` and `"downstream":[]` (not null) so
	// the frontend can render empty-states without null-checking.
	b := rr.Body.String()
	if !contains(b, `"upstream":[]`) || !contains(b, `"downstream":[]`) {
		t.Errorf("empty arrays not serialised as []; got body: %s", b)
	}
}

func TestLineageHandler_StoreErrorPropagates(t *testing.T) {
	store := &fakeLineageStore{fromErr: errors.New("db down")}
	r := newLineageRouter(t, store)
	req := httptest.NewRequest("GET", "/lineage/certificate/cert-x", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rr.Code)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
