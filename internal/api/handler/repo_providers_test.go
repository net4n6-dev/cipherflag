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

// fakeProviderStore implements only the methods ProvidersHandler uses
// (the handler accepts a narrow interface, not the full CryptoStore).
type fakeProviderStore struct {
	upsertErr   error
	listErr     error
	getErr      error
	deleteErr   error
	upserted    []*model.Provider
	providers   map[string]*model.Provider
	findByKU    map[string]*model.Provider // key = kind+"|"+url
	listResult  []model.Provider
	lastDeleted string
}

func newFakeProviderStore() *fakeProviderStore {
	return &fakeProviderStore{providers: map[string]*model.Provider{}, findByKU: map[string]*model.Provider{}}
}

func (f *fakeProviderStore) UpsertProvider(ctx context.Context, p *model.Provider) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	if p.ID == "" {
		p.ID = "prov-1"
	}
	f.providers[p.ID] = p
	f.findByKU[p.Kind+"|"+p.BaseURL] = p
	f.upserted = append(f.upserted, p)
	return nil
}
func (f *fakeProviderStore) GetProvider(ctx context.Context, id string) (*model.Provider, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.providers[id], nil
}
func (f *fakeProviderStore) FindProviderByKindURL(ctx context.Context, kind, baseURL string) (*model.Provider, error) {
	return f.findByKU[kind+"|"+baseURL], nil
}
func (f *fakeProviderStore) ListProviders(ctx context.Context) ([]model.Provider, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResult, nil
}
func (f *fakeProviderStore) DeleteProvider(ctx context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.lastDeleted = id
	return nil
}

func TestProvidersHandler_Create_ValidatesKind(t *testing.T) {
	f := newFakeProviderStore()
	h := NewProvidersHandler(f)

	body := []byte(`{"kind":"not-a-kind","base_url":"https://x","auth_secret_ref":"env:X"}`)
	req := httptest.NewRequest("POST", "/api/v1/repo/providers", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.Create(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid provider kind") {
		t.Errorf("expected error message about invalid kind, got %s", rr.Body.String())
	}
	if len(f.upserted) != 0 {
		t.Error("store.Upsert should not have been called on validation failure")
	}
}

func TestProvidersHandler_Create_ValidatesRequiredFields(t *testing.T) {
	f := newFakeProviderStore()
	h := NewProvidersHandler(f)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty kind", `{"kind":"","base_url":"https://x","auth_secret_ref":"env:X"}`},
		{"empty base_url", `{"kind":"github","base_url":"","auth_secret_ref":"env:X"}`},
		{"empty auth_secret_ref", `{"kind":"github","base_url":"https://x","auth_secret_ref":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/repo/providers", strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			h.Create(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("want 400, got %d", rr.Code)
			}
		})
	}
}

func TestProvidersHandler_Create_Success(t *testing.T) {
	f := newFakeProviderStore()
	h := NewProvidersHandler(f)

	body := []byte(`{"kind":"github","base_url":"https://github.com","auth_secret_ref":"env:PAT","display_name":"Org"}`)
	req := httptest.NewRequest("POST", "/api/v1/repo/providers", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.Create(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out model.Provider
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Kind != "github" || out.DisplayName != "Org" {
		t.Errorf("bad response: %+v", out)
	}
	if len(f.upserted) != 1 {
		t.Errorf("want 1 upserted, got %d", len(f.upserted))
	}
}

func TestProvidersHandler_Create_DuplicateReturns409(t *testing.T) {
	f := newFakeProviderStore()
	f.findByKU["github|https://github.com"] = &model.Provider{ID: "existing", Kind: "github", BaseURL: "https://github.com"}
	h := NewProvidersHandler(f)

	body := []byte(`{"kind":"github","base_url":"https://github.com","auth_secret_ref":"env:PAT"}`)
	req := httptest.NewRequest("POST", "/api/v1/repo/providers", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.Create(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("want 409, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestProvidersHandler_List(t *testing.T) {
	f := newFakeProviderStore()
	f.listResult = []model.Provider{
		{ID: "a", Kind: "github", BaseURL: "https://github.com"},
		{ID: "b", Kind: "gitlab", BaseURL: "https://gitlab.example"},
	}
	h := NewProvidersHandler(f)

	req := httptest.NewRequest("GET", "/api/v1/repo/providers", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp struct {
		Providers []model.Provider `json:"providers"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Providers) != 2 {
		t.Errorf("want 2, got %d", len(resp.Providers))
	}
}

func TestProvidersHandler_GetOne(t *testing.T) {
	f := newFakeProviderStore()
	f.providers["p-1"] = &model.Provider{ID: "p-1", Kind: "github", BaseURL: "https://github.com"}
	h := NewProvidersHandler(f)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "p-1")
	req := httptest.NewRequest("GET", "/api/v1/repo/providers/p-1", nil).
		WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	h.Get(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func TestProvidersHandler_GetMissingReturns404(t *testing.T) {
	f := newFakeProviderStore()
	h := NewProvidersHandler(f)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "nope")
	req := httptest.NewRequest("GET", "/api/v1/repo/providers/nope", nil).
		WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	h.Get(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rr.Code)
	}
}

func TestProvidersHandler_Delete(t *testing.T) {
	f := newFakeProviderStore()
	h := NewProvidersHandler(f)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "p-1")
	req := httptest.NewRequest("DELETE", "/api/v1/repo/providers/p-1", nil).
		WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	h.Delete(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if f.lastDeleted != "p-1" {
		t.Errorf("want DeleteProvider called with 'p-1', got %q", f.lastDeleted)
	}
}
