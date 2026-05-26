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

type fakeAssetHealthStore struct {
	report *model.AssetHealthReport
	err    error
	lastAT string
	lastAI string
}

func (f *fakeAssetHealthStore) GetAssetHealthReport(ctx context.Context, assetType, assetID string) (*model.AssetHealthReport, error) {
	f.lastAT = assetType
	f.lastAI = assetID
	return f.report, f.err
}

func newAssetFindingRouter(t *testing.T, s findingsStore) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	h := NewAssetFindingHandler(s)
	r.Get("/findings/{asset_type}/{asset_id}/{rule_id}", h.Get)
	return r
}

func TestAssetFindingHandler_Success(t *testing.T) {
	store := &fakeAssetHealthStore{
		report: &model.AssetHealthReport{
			AssetType: "crypto_library",
			AssetID:   "lib-123",
			Grade:     "C",
			Score:     62,
			Findings: []model.HealthFinding{
				{RuleID: "LIB-003", Title: "EOL", Severity: model.SeverityHigh, Deduction: 35},
				{RuleID: "LIB-004", Title: "No PQC", Severity: model.SeverityMedium, Deduction: 10},
			},
		},
	}
	r := newAssetFindingRouter(t, store)
	req := httptest.NewRequest("GET", "/findings/crypto_library/lib-123/LIB-003", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Finding    model.HealthFinding `json:"finding"`
		AssetType  string              `json:"asset_type"`
		AssetID    string              `json:"asset_id"`
		RuleID     string              `json:"rule_id"`
		AssetGrade string              `json:"asset_grade"`
		AssetScore int                 `json:"asset_score"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Finding.RuleID != "LIB-003" {
		t.Errorf("want LIB-003, got %q", body.Finding.RuleID)
	}
	if body.AssetGrade != "C" || body.AssetScore != 62 {
		t.Errorf("want C/62, got %s/%d", body.AssetGrade, body.AssetScore)
	}
	if store.lastAT != "crypto_library" || store.lastAI != "lib-123" {
		t.Errorf("store called with wrong args: %q/%q", store.lastAT, store.lastAI)
	}
}

func TestAssetFindingHandler_NotFound_NoReport(t *testing.T) {
	store := &fakeAssetHealthStore{report: nil} // GetAssetHealthReport returns (nil, nil) when absent
	r := newAssetFindingRouter(t, store)
	req := httptest.NewRequest("GET", "/findings/ssh_key/missing/LIB-003", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rr.Code)
	}
}

func TestAssetFindingHandler_NotFound_RuleNotOnReport(t *testing.T) {
	store := &fakeAssetHealthStore{
		report: &model.AssetHealthReport{
			Findings: []model.HealthFinding{{RuleID: "LIB-004"}},
		},
	}
	r := newAssetFindingRouter(t, store)
	req := httptest.NewRequest("GET", "/findings/crypto_library/lib-x/LIB-999", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rr.Code)
	}
}

func TestAssetFindingHandler_StoreError(t *testing.T) {
	store := &fakeAssetHealthStore{err: errors.New("db timeout")}
	r := newAssetFindingRouter(t, store)
	req := httptest.NewRequest("GET", "/findings/crypto_library/lib-x/LIB-003", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rr.Code)
	}
}
