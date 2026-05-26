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

// fakeShadowCAStore captures every call so the tests can assert
// pass-through of params, authz-relevant fields, and error shape.
type fakeShadowCAStore struct {
	shadowResult   []store.ShadowCA
	declaredResult []store.DeclaredCA
	declareErr     error
	revokeErr      error

	declareCalls []store.DeclareCARequest
	revokeCalls  []string
}

func (f *fakeShadowCAStore) ListShadowCAs(_ context.Context) ([]store.ShadowCA, error) {
	return f.shadowResult, nil
}
func (f *fakeShadowCAStore) ListDeclaredCAs(_ context.Context) ([]store.DeclaredCA, error) {
	return f.declaredResult, nil
}
func (f *fakeShadowCAStore) DeclareCA(_ context.Context, req *store.DeclareCARequest) error {
	if req != nil {
		f.declareCalls = append(f.declareCalls, *req)
	}
	return f.declareErr
}
func (f *fakeShadowCAStore) RevokeDeclaredCA(_ context.Context, fp string) error {
	f.revokeCalls = append(f.revokeCalls, fp)
	return f.revokeErr
}

func shadowCATestAdminCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(),
		middleware.UserContextKeyExported(),
		&model.UserContext{ID: "admin-uuid", Email: "admin@test", Role: "admin"})
	return r.WithContext(ctx)
}

func TestShadowCA_ListShadow_WrapsResultAndReturns200(t *testing.T) {
	f := &fakeShadowCAStore{shadowResult: []store.ShadowCA{
		{FingerprintSHA256: "fp1", SubjectCN: "CA 1", DirectChildrenCount: 5},
		{FingerprintSHA256: "fp2", SubjectCN: "CA 2", DirectChildrenCount: 3},
	}}
	h := NewShadowCAHandler(f)

	req := httptest.NewRequest("GET", "/api/v1/inventory/shadow-cas", nil)
	rr := httptest.NewRecorder()
	h.ListShadow(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["total"] != float64(2) {
		t.Errorf("total = %v, want 2", body["total"])
	}
	if arr, _ := body["shadow_cas"].([]any); len(arr) != 2 {
		t.Errorf("shadow_cas length = %d, want 2", len(arr))
	}
}

func TestShadowCA_ListShadow_NilResult_SerialisesAsEmptyArray(t *testing.T) {
	// Even when the store returns nil, the wire contract is [] not null.
	// Frontend guards against this but the handler should do the right
	// thing too.
	f := &fakeShadowCAStore{shadowResult: nil}
	h := NewShadowCAHandler(f)

	req := httptest.NewRequest("GET", "/api/v1/inventory/shadow-cas", nil)
	rr := httptest.NewRecorder()
	h.ListShadow(rr, req)

	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	arr, ok := body["shadow_cas"].([]any)
	if !ok {
		t.Fatalf("shadow_cas not an array: %T", body["shadow_cas"])
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array, got %d", len(arr))
	}
}

func TestShadowCA_ListDeclared_WrapsAndReturns200(t *testing.T) {
	f := &fakeShadowCAStore{declaredResult: []store.DeclaredCA{
		{FingerprintSHA256: "fp1", SubjectCN: "CA 1", OwnerTeam: "platform"},
	}}
	h := NewShadowCAHandler(f)

	req := httptest.NewRequest("GET", "/api/v1/inventory/declared-cas", nil)
	rr := httptest.NewRecorder()
	h.ListDeclared(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["total"] != float64(1) {
		t.Errorf("total = %v, want 1", body["total"])
	}
}

func TestShadowCA_Declare_HappyPath(t *testing.T) {
	f := &fakeShadowCAStore{}
	h := NewShadowCAHandler(f)

	body := `{"fingerprint_sha256":"sha256:abc","owner_team":"platform","note":"internal root"}`
	req := httptest.NewRequest("POST", "/api/v1/inventory/declared-cas", bytes.NewBufferString(body))
	req = shadowCATestAdminCtx(req)
	rr := httptest.NewRecorder()
	h.Declare(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(f.declareCalls) != 1 {
		t.Fatalf("declare calls = %d, want 1", len(f.declareCalls))
	}
	got := f.declareCalls[0]
	if got.FingerprintSHA256 != "sha256:abc" {
		t.Errorf("fingerprint = %q", got.FingerprintSHA256)
	}
	if got.AddedBy != "admin-uuid" {
		t.Errorf("added_by = %q, want admin-uuid (from JWT context)", got.AddedBy)
	}
	if got.OwnerTeam != "platform" || got.Note != "internal root" {
		t.Errorf("metadata lost: %+v", got)
	}
}

func TestShadowCA_Declare_MissingFingerprint_Rejects400(t *testing.T) {
	f := &fakeShadowCAStore{}
	h := NewShadowCAHandler(f)

	body := `{"owner_team":"x"}`
	req := httptest.NewRequest("POST", "/api/v1/inventory/declared-cas", bytes.NewBufferString(body))
	req = shadowCATestAdminCtx(req)
	rr := httptest.NewRecorder()
	h.Declare(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if len(f.declareCalls) != 0 {
		t.Errorf("store must not be called when fingerprint missing")
	}
}

func TestShadowCA_Declare_InvalidJSON_Rejects400(t *testing.T) {
	f := &fakeShadowCAStore{}
	h := NewShadowCAHandler(f)

	req := httptest.NewRequest("POST", "/api/v1/inventory/declared-cas", bytes.NewBufferString("not json"))
	req = shadowCATestAdminCtx(req)
	rr := httptest.NewRecorder()
	h.Declare(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestShadowCA_Declare_OversizedNote_Rejects400(t *testing.T) {
	f := &fakeShadowCAStore{}
	h := NewShadowCAHandler(f)

	huge := strings.Repeat("x", 3000)
	body := `{"fingerprint_sha256":"sha256:abc","note":"` + huge + `"}`
	req := httptest.NewRequest("POST", "/api/v1/inventory/declared-cas", bytes.NewBufferString(body))
	req = shadowCATestAdminCtx(req)
	rr := httptest.NewRecorder()
	h.Declare(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (note too large)", rr.Code)
	}
	if len(f.declareCalls) != 0 {
		t.Errorf("store must not be called for oversized note")
	}
}

func TestShadowCA_Declare_StoreRejectsLeaf_Returns400(t *testing.T) {
	// Store signals "not a CA" — handler must surface as 400, not 500.
	f := &fakeShadowCAStore{declareErr: errors.New("DeclareCA: fingerprint sha256:x is a leaf, not a CA")}
	h := NewShadowCAHandler(f)

	body := `{"fingerprint_sha256":"sha256:x"}`
	req := httptest.NewRequest("POST", "/api/v1/inventory/declared-cas", bytes.NewBufferString(body))
	req = shadowCATestAdminCtx(req)
	rr := httptest.NewRecorder()
	h.Declare(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestShadowCA_Declare_StoreRejectsUnknown_Returns400(t *testing.T) {
	f := &fakeShadowCAStore{declareErr: errors.New("DeclareCA: fingerprint sha256:y not in certificates")}
	h := NewShadowCAHandler(f)

	body := `{"fingerprint_sha256":"sha256:y"}`
	req := httptest.NewRequest("POST", "/api/v1/inventory/declared-cas", bytes.NewBufferString(body))
	req = shadowCATestAdminCtx(req)
	rr := httptest.NewRecorder()
	h.Declare(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestShadowCA_Declare_StoreUnexpectedError_Returns500(t *testing.T) {
	f := &fakeShadowCAStore{declareErr: errors.New("pg connection died")}
	h := NewShadowCAHandler(f)

	body := `{"fingerprint_sha256":"sha256:abc"}`
	req := httptest.NewRequest("POST", "/api/v1/inventory/declared-cas", bytes.NewBufferString(body))
	req = shadowCATestAdminCtx(req)
	rr := httptest.NewRecorder()
	h.Declare(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for unexpected error", rr.Code)
	}
}

func TestShadowCA_Revoke_HappyPath(t *testing.T) {
	f := &fakeShadowCAStore{}
	h := NewShadowCAHandler(f)

	router := chi.NewRouter()
	router.Delete("/inventory/declared-cas/{fingerprint}", h.Revoke)

	req := httptest.NewRequest("DELETE", "/inventory/declared-cas/sha256:abc", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(f.revokeCalls) != 1 || f.revokeCalls[0] != "sha256:abc" {
		t.Errorf("revoke calls = %v, want [sha256:abc]", f.revokeCalls)
	}
}

func TestShadowCA_Revoke_StoreError_Returns500(t *testing.T) {
	f := &fakeShadowCAStore{revokeErr: errors.New("pg connection died")}
	h := NewShadowCAHandler(f)

	router := chi.NewRouter()
	router.Delete("/inventory/declared-cas/{fingerprint}", h.Revoke)

	req := httptest.NewRequest("DELETE", "/inventory/declared-cas/sha256:abc", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// TestShadowCA_Revoke_AdminOnly_AtRoutingLayer documents that the
// admin-only enforcement lives on the route wiring in server.go
// (middleware.RequireAdmin), not in the handler. This test assembles
// the same middleware chain server.go uses and confirms a non-admin
// caller is rejected with 403 without ever reaching the store.
func TestShadowCA_DeclareAndRevoke_ViewerBlockedAt403(t *testing.T) {
	f := &fakeShadowCAStore{}
	h := NewShadowCAHandler(f)

	router := chi.NewRouter()
	router.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Post("/inventory/declared-cas", h.Declare)
		r.Delete("/inventory/declared-cas/{fingerprint}", h.Revoke)
	})

	// Inject a VIEWER user (not admin) into the request context.
	viewerCtx := func(r *http.Request) *http.Request {
		ctx := context.WithValue(r.Context(),
			middleware.UserContextKeyExported(),
			&model.UserContext{ID: "viewer-uuid", Email: "v@t", Role: "viewer"})
		return r.WithContext(ctx)
	}

	postReq := viewerCtx(httptest.NewRequest("POST", "/inventory/declared-cas",
		bytes.NewBufferString(`{"fingerprint_sha256":"sha256:abc"}`)))
	postRR := httptest.NewRecorder()
	router.ServeHTTP(postRR, postReq)
	if postRR.Code != http.StatusForbidden {
		t.Errorf("POST as viewer: status = %d, want 403", postRR.Code)
	}

	delReq := viewerCtx(httptest.NewRequest("DELETE", "/inventory/declared-cas/sha256:abc", nil))
	delRR := httptest.NewRecorder()
	router.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusForbidden {
		t.Errorf("DELETE as viewer: status = %d, want 403", delRR.Code)
	}

	if len(f.declareCalls) != 0 || len(f.revokeCalls) != 0 {
		t.Errorf("store reached despite 403; declare=%d revoke=%d",
			len(f.declareCalls), len(f.revokeCalls))
	}
}
