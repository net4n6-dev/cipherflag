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
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/net4n6-dev/cipherflag/internal/store"
)

type fakeRepoCBOMStore struct {
	rows []store.RepoFindingRow
	err  error
}

func (f *fakeRepoCBOMStore) ListRepositoryFindings(ctx context.Context, q store.RepoFindingQuery) ([]store.RepoFindingRow, error) {
	return f.rows, f.err
}

func TestRepoCBOMHandler_RequiresRepoID(t *testing.T) {
	h := NewRepoCBOMHandler(&fakeRepoCBOMStore{})
	req := httptest.NewRequest("GET", "/api/v1/repo/exports/cbom", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRepoCBOMHandler_RejectsInvalidUUID(t *testing.T) {
	h := NewRepoCBOMHandler(&fakeRepoCBOMStore{})
	req := httptest.NewRequest("GET", "/api/v1/repo/exports/cbom?repo_id=not-a-uuid", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 on bad UUID, got %d", rr.Code)
	}
}

func TestRepoCBOMHandler_Success_EmptyRepo(t *testing.T) {
	h := NewRepoCBOMHandler(&fakeRepoCBOMStore{rows: nil})
	req := httptest.NewRequest("GET", "/api/v1/repo/exports/cbom?repo_id=11111111-1111-1111-1111-111111111111", nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "cyclonedx") {
		t.Errorf("want CycloneDX content-type, got %q", ct)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(rr.Body.Bytes(), &bom); err != nil {
		t.Fatalf("response not valid CycloneDX JSON: %v", err)
	}
	if bom.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("spec version: %v", bom.SpecVersion)
	}
}

func TestRepoCBOMHandler_ContentDispositionFilename(t *testing.T) {
	h := NewRepoCBOMHandler(&fakeRepoCBOMStore{rows: nil})
	repoID := "22222222-2222-2222-2222-222222222222"
	req := httptest.NewRequest("GET", "/api/v1/repo/exports/cbom?repo_id="+repoID, nil)
	rr := httptest.NewRecorder()
	h.Download(rr, req)
	cd := rr.Header().Get("Content-Disposition")
	if !strings.Contains(cd, repoID) || !strings.Contains(cd, ".cdx.json") {
		t.Errorf("Content-Disposition should suggest <repo_id>.cdx.json filename; got %q", cd)
	}
}
