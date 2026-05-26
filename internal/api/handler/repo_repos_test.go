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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

type fakeReposStore struct {
	provider    *model.Provider
	repos       map[string]*model.Repository
	lastUpsert  *model.Repository
	lastDeleted string
	upsertErr   error
	getErr      error
	listResult  []model.Repository
	findByURL   map[string]*model.Repository // key = providerID|url
}

func newFakeReposStore() *fakeReposStore {
	return &fakeReposStore{
		repos:     map[string]*model.Repository{},
		findByURL: map[string]*model.Repository{},
	}
}

func (f *fakeReposStore) GetProvider(ctx context.Context, id string) (*model.Provider, error) {
	if f.provider != nil && f.provider.ID == id {
		return f.provider, nil
	}
	return nil, nil
}
func (f *fakeReposStore) UpsertRepository(ctx context.Context, r *model.Repository) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	if r.ID == "" {
		r.ID = "repo-1"
	}
	f.repos[r.ID] = r
	f.findByURL[r.ProviderID+"|"+r.URL] = r
	f.lastUpsert = r
	return nil
}
func (f *fakeReposStore) GetRepository(ctx context.Context, id string) (*model.Repository, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.repos[id], nil
}
func (f *fakeReposStore) FindRepositoryByURL(ctx context.Context, pid, url string) (*model.Repository, error) {
	return f.findByURL[pid+"|"+url], nil
}
func (f *fakeReposStore) ListRepositories(ctx context.Context, providerID string, limit, offset int) ([]model.Repository, error) {
	return f.listResult, nil
}
func (f *fakeReposStore) DeleteRepository(ctx context.Context, id string) error {
	f.lastDeleted = id
	return nil
}

func TestReposHandler_Create_Success(t *testing.T) {
	f := newFakeReposStore()
	f.provider = &model.Provider{ID: "p-1", Kind: "github", BaseURL: "https://github.com"}
	h := NewRepositoriesHandler(f)

	body := []byte(`{"provider_id":"p-1","url":"https://github.com/acme/widget","default_branch":"main","default_scan_mode":"deterministic_only"}`)
	req := httptest.NewRequest("POST", "/api/v1/repo/repos", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.Create(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out model.Repository
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.URL != "https://github.com/acme/widget" {
		t.Errorf("bad URL: %q", out.URL)
	}
}

func TestReposHandler_Create_RejectsUnknownProvider(t *testing.T) {
	f := newFakeReposStore()
	h := NewRepositoriesHandler(f)

	body := []byte(`{"provider_id":"missing","url":"x","default_branch":"main","default_scan_mode":"deterministic_only"}`)
	req := httptest.NewRequest("POST", "/api/v1/repo/repos", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.Create(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 on missing provider, got %d", rr.Code)
	}
}

func TestReposHandler_Create_RejectsInvalidScanMode(t *testing.T) {
	f := newFakeReposStore()
	f.provider = &model.Provider{ID: "p-1"}
	h := NewRepositoriesHandler(f)

	body := []byte(`{"provider_id":"p-1","url":"x","default_branch":"main","default_scan_mode":"turbo"}`)
	req := httptest.NewRequest("POST", "/api/v1/repo/repos", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.Create(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestReposHandler_Create_DuplicateReturns409(t *testing.T) {
	f := newFakeReposStore()
	f.provider = &model.Provider{ID: "p-1"}
	f.findByURL["p-1|https://github.com/a/b"] = &model.Repository{ID: "existing"}
	h := NewRepositoriesHandler(f)

	body := []byte(`{"provider_id":"p-1","url":"https://github.com/a/b","default_branch":"main","default_scan_mode":"deterministic_only"}`)
	req := httptest.NewRequest("POST", "/api/v1/repo/repos", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.Create(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("want 409, got %d", rr.Code)
	}
}

func TestReposHandler_Patch_UpdatesSchedule(t *testing.T) {
	f := newFakeReposStore()
	f.repos["r-1"] = &model.Repository{ID: "r-1", ProviderID: "p-1", URL: "u", DefaultBranch: "main", DefaultScanMode: "deterministic_only"}
	h := NewRepositoriesHandler(f)

	body := []byte(`{"schedule_cron":"0 3 * * *","default_scan_mode":"enrichment"}`)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "r-1")
	req := httptest.NewRequest("PATCH", "/api/v1/repo/repos/r-1", bytes.NewReader(body)).
		WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	h.Patch(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if f.lastUpsert.ScheduleCron != "0 3 * * *" {
		t.Errorf("cron not updated: %q", f.lastUpsert.ScheduleCron)
	}
	if f.lastUpsert.DefaultScanMode != "enrichment" {
		t.Errorf("scan_mode not updated: %q", f.lastUpsert.DefaultScanMode)
	}
}

func TestReposHandler_Patch_RejectsInvalidCron(t *testing.T) {
	f := newFakeReposStore()
	f.repos["r-1"] = &model.Repository{ID: "r-1", DefaultScanMode: "deterministic_only"}
	h := NewRepositoriesHandler(f)

	body := []byte(`{"schedule_cron":"not a cron"}`)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "r-1")
	req := httptest.NewRequest("PATCH", "/api/v1/repo/repos/r-1", bytes.NewReader(body)).
		WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	h.Patch(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestReposHandler_Delete(t *testing.T) {
	f := newFakeReposStore()
	h := NewRepositoriesHandler(f)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "r-1")
	req := httptest.NewRequest("DELETE", "/api/v1/repo/repos/r-1", nil).
		WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	h.Delete(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rr.Code)
	}
	if f.lastDeleted != "r-1" {
		t.Errorf("want delete id r-1, got %q", f.lastDeleted)
	}
}

func TestReposHandler_List(t *testing.T) {
	f := newFakeReposStore()
	f.listResult = []model.Repository{{ID: "r-1"}, {ID: "r-2"}}
	h := NewRepositoriesHandler(f)

	req := httptest.NewRequest("GET", "/api/v1/repo/repos", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"r-1"`) {
		t.Errorf("body missing r-1: %s", rr.Body.String())
	}
}
