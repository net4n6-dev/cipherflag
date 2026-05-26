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
	"net/http/httptest"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/analysis/pqc"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type fakeHygieneStore struct {
	lastFilter  store.WeakAlgoFilter
	occurrences []store.WeakAlgoOccurrence
	err         error
	// calls records how many times ListWeakAlgorithmOccurrences fired —
	// handy for asserting that bad inputs short-circuit before the store.
	calls int
}

func (f *fakeHygieneStore) ListWeakAlgorithmOccurrences(_ context.Context, filter store.WeakAlgoFilter) ([]store.WeakAlgoOccurrence, error) {
	f.calls++
	f.lastFilter = filter
	return f.occurrences, f.err
}

func TestHygieneHandler_ListWeakAlgorithms_DefaultsBothClassifications(t *testing.T) {
	f := &fakeHygieneStore{occurrences: []store.WeakAlgoOccurrence{
		{AssetType: "certificate", AssetID: "fp1", AlgorithmCanonical: "rsa", Classification: pqc.QuantumVulnerable},
	}}
	h := NewHygieneHandler(f)
	req := httptest.NewRequest("GET", "/analysis/weak-algorithms", nil)
	rr := httptest.NewRecorder()
	h.ListWeakAlgorithms(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Occurrences []store.WeakAlgoOccurrence `json:"occurrences"`
		Count       int                        `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Count != 1 || len(body.Occurrences) != 1 {
		t.Errorf("expected 1 occurrence, got %d / len=%d", body.Count, len(body.Occurrences))
	}
	// With no status param, both IncludeVulnerable and IncludeWeakened
	// remain false on the filter — the store method defaults both on.
	// That contract is pinned in the store unit tests; here we just
	// assert that the handler passes the filter through unmodified.
	if f.lastFilter.IncludeVulnerable || f.lastFilter.IncludeWeakened {
		t.Errorf("handler should not set classification flags when status param is omitted")
	}
}

func TestHygieneHandler_StatusFilter(t *testing.T) {
	f := &fakeHygieneStore{}
	h := NewHygieneHandler(f)
	req := httptest.NewRequest("GET", "/analysis/weak-algorithms?status=vulnerable", nil)
	rr := httptest.NewRecorder()
	h.ListWeakAlgorithms(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !f.lastFilter.IncludeVulnerable {
		t.Errorf("IncludeVulnerable = false, want true")
	}
	if f.lastFilter.IncludeWeakened {
		t.Errorf("IncludeWeakened = true, want false (not requested)")
	}
}

func TestHygieneHandler_TypeFilter(t *testing.T) {
	f := &fakeHygieneStore{}
	h := NewHygieneHandler(f)
	req := httptest.NewRequest("GET", "/analysis/weak-algorithms?type=certificate,ssh_key", nil)
	rr := httptest.NewRecorder()
	h.ListWeakAlgorithms(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if len(f.lastFilter.AssetTypes) != 2 {
		t.Fatalf("AssetTypes len = %d, want 2", len(f.lastFilter.AssetTypes))
	}
	want := map[string]bool{"certificate": true, "ssh_key": true}
	for _, a := range f.lastFilter.AssetTypes {
		if !want[a] {
			t.Errorf("unexpected AssetType %q", a)
		}
	}
}

func TestHygieneHandler_InvalidStatus_Rejects400(t *testing.T) {
	f := &fakeHygieneStore{}
	h := NewHygieneHandler(f)
	req := httptest.NewRequest("GET", "/analysis/weak-algorithms?status=bogus", nil)
	rr := httptest.NewRecorder()
	h.ListWeakAlgorithms(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if f.calls != 0 {
		t.Errorf("store must not be hit on invalid input; got %d calls", f.calls)
	}
}

func TestHygieneHandler_InvalidType_Rejects400(t *testing.T) {
	f := &fakeHygieneStore{}
	h := NewHygieneHandler(f)
	req := httptest.NewRequest("GET", "/analysis/weak-algorithms?type=certificate,host", nil)
	rr := httptest.NewRecorder()
	h.ListWeakAlgorithms(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (host is not a supported type)", rr.Code)
	}
	if f.calls != 0 {
		t.Errorf("store must not be hit on invalid input; got %d calls", f.calls)
	}
}

func TestHygieneHandler_LimitPassthrough(t *testing.T) {
	f := &fakeHygieneStore{}
	h := NewHygieneHandler(f)
	req := httptest.NewRequest("GET", "/analysis/weak-algorithms?limit=50", nil)
	rr := httptest.NewRecorder()
	h.ListWeakAlgorithms(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if f.lastFilter.Limit != 50 {
		t.Errorf("Limit = %d, want 50", f.lastFilter.Limit)
	}
}

func TestHygieneHandler_NilResultSerialisesAsEmptyArray(t *testing.T) {
	// Store returns nil (no rows). Response MUST be `"occurrences": []`,
	// not `null` — frontend type assumes array.
	f := &fakeHygieneStore{occurrences: nil}
	h := NewHygieneHandler(f)
	req := httptest.NewRequest("GET", "/analysis/weak-algorithms", nil)
	rr := httptest.NewRecorder()
	h.ListWeakAlgorithms(rr, req)

	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	arr, ok := body["occurrences"].([]any)
	if !ok {
		t.Fatalf("occurrences not an array: %T (body=%s)", body["occurrences"], rr.Body.String())
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array, got %d elements", len(arr))
	}
	if body["count"].(float64) != 0 {
		t.Errorf("count = %v, want 0", body["count"])
	}
}
