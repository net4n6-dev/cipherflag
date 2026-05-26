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

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type fakeFindingsStore struct {
	resp []store.RepoFindingRow
	err  error
	last store.RepoFindingQuery
}

func (f *fakeFindingsStore) ListRepositoryFindings(ctx context.Context, q store.RepoFindingQuery) ([]store.RepoFindingRow, error) {
	f.last = q
	return f.resp, f.err
}
func (f *fakeFindingsStore) GetScanJob(ctx context.Context, id string) (*model.ScanJob, error) {
	return nil, nil
}

func TestFindingsHandler_RequireRepoID(t *testing.T) {
	f := &fakeFindingsStore{}
	h := NewFindingsHandler(f)
	req := httptest.NewRequest("GET", "/api/v1/repo/findings", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 missing repo_id, got %d", rr.Code)
	}
}

func TestFindingsHandler_Paginated(t *testing.T) {
	f := &fakeFindingsStore{resp: []store.RepoFindingRow{
		{RuleID: "A", Severity: "Critical"}, {RuleID: "B", Severity: "Medium"},
	}}
	h := NewFindingsHandler(f)
	req := httptest.NewRequest("GET", "/api/v1/repo/findings?repo_id=r-1&severity=Critical,Medium&bucket=B1,B4&detected_by=det&limit=50", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var body struct {
		Findings []store.RepoFindingRow `json:"findings"`
		Count    int                    `json:"count"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Count != 2 {
		t.Errorf("count: %d", body.Count)
	}
	if len(f.last.Severities) != 2 || f.last.Severities[0] != "Critical" {
		t.Errorf("severity parse: %+v", f.last.Severities)
	}
	if len(f.last.Buckets) != 2 {
		t.Errorf("bucket parse: %+v", f.last.Buckets)
	}
	if f.last.DetectedBy != "det" {
		t.Errorf("detected_by: %q", f.last.DetectedBy)
	}
	if f.last.Limit != 50 {
		t.Errorf("limit: %d", f.last.Limit)
	}
}
