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

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/analysis/scoring"
	"github.com/net4n6-dev/cipherflag/internal/auth"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
	"github.com/net4n6-dev/cipherflag/internal/export/venafi"
	"github.com/net4n6-dev/cipherflag/internal/ingest/observcache"
	"github.com/net4n6-dev/cipherflag/internal/sse"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// exportGateStore adds empty inventories to the auth fake so the export routes
// can run end to end without a database.
type exportGateStore struct{ authGateStore }

func (*exportGateStore) ListAllAssetHealthReports(context.Context) ([]store.ScopeAssetRow, error) {
	return nil, nil
}
func (*exportGateStore) SearchCertificates(context.Context, store.CertSearchQuery) (*store.CertSearchResult, error) {
	return &store.CertSearchResult{}, nil
}
func (*exportGateStore) ListApplicationScopeAssets(context.Context, string) ([]store.ScopeAssetRow, error) {
	return nil, nil
}

// The CBOM export routes are readable by any authenticated caller (viewer and
// agent tokens included) but never anonymously.
func TestRouter_CBOMExportRoutes_AuthenticatedButNotAdminOnly(t *testing.T) {
	secret := []byte("test-secret")
	sum := sha256.Sum256([]byte("agent-secret"))
	st := &exportGateStore{authGateStore{agentHash: hex.EncodeToString(sum[:])}}
	router := NewRouter(st, &config.Config{}, "", "", secret, "",
		observcache.NewNoop(), scoring.NewNoopScorer(), sse.NewHub(),
		venafi.NewLiveConfig(config.VenafiExportConfig{}), cbom.NewGenerator())

	viewer := func(r *http.Request) {
		tok, err := auth.SignJWT(secret, "u1", "u1@example.com", "viewer")
		if err != nil {
			t.Fatalf("SignJWT: %v", err)
		}
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
	}
	agent := func(r *http.Request) { r.Header.Set("Authorization", "Bearer agent-secret") }
	anon := func(*http.Request) {}

	cases := []struct {
		name string
		path string
		auth func(*http.Request)
		want int
	}{
		{"estate anonymous", "/api/v1/export/cbom/estate", anon, http.StatusUnauthorized},
		{"estate viewer", "/api/v1/export/cbom/estate", viewer, http.StatusOK},
		{"estate agent token", "/api/v1/export/cbom/estate", agent, http.StatusOK},
		{"application anonymous", "/api/v1/applications/payments-api/cbom", anon, http.StatusUnauthorized},
		{"application viewer, unknown tag", "/api/v1/applications/payments-api/cbom", viewer, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			tc.auth(req)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusOK && !strings.Contains(rec.Body.String(), `"bomFormat":"CycloneDX"`) {
				t.Errorf("200 response is not a CycloneDX document: %s", rec.Body.String())
			}
		})
	}
}

// The certificate inventory export follows the same rule as the CBOM export:
// any authenticated caller may read it, an anonymous one may not.
func TestRouter_CertificateExportRoute_AuthenticatedButNotAdminOnly(t *testing.T) {
	secret := []byte("test-secret")
	sum := sha256.Sum256([]byte("agent-secret"))
	st := &exportGateStore{authGateStore{agentHash: hex.EncodeToString(sum[:])}}
	router := NewRouter(st, &config.Config{}, "", "", secret, "",
		observcache.NewNoop(), scoring.NewNoopScorer(), sse.NewHub(),
		venafi.NewLiveConfig(config.VenafiExportConfig{}), cbom.NewGenerator())

	viewer := func(r *http.Request) {
		tok, err := auth.SignJWT(secret, "u1", "u1@example.com", "viewer")
		if err != nil {
			t.Fatalf("SignJWT: %v", err)
		}
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
	}
	agent := func(r *http.Request) { r.Header.Set("Authorization", "Bearer agent-secret") }
	anon := func(*http.Request) {}

	cases := []struct {
		name string
		auth func(*http.Request)
		want int
	}{
		{"anonymous", anon, http.StatusUnauthorized},
		{"viewer", viewer, http.StatusOK},
		{"agent token", agent, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/export/certificates", nil)
			tc.auth(req)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusOK && !strings.HasPrefix(rec.Body.String(), "fingerprint_sha256,") {
				t.Errorf("200 response is not the CSV export: %s", rec.Body.String())
			}
		})
	}
}
