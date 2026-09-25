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
	"github.com/net4n6-dev/cipherflag/internal/export/venafi"
	"github.com/net4n6-dev/cipherflag/internal/ingest/observcache"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/sse"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// authGateStore answers only what the auth middleware asks: users exist, and
// one known agent token. Anything else falls through to the nil embedded
// CryptoStore and would panic, which is intended: these tests must be rejected
// or rejected-by-handler before reaching the store.
type authGateStore struct {
	store.CryptoStore
	agentHash string
}

func (s *authGateStore) HasUsers(context.Context) (bool, error) { return true, nil }
func (s *authGateStore) GetAgentToken(_ context.Context, hash string) (*model.AgentToken, error) {
	if hash == s.agentHash {
		return &model.AgentToken{ID: "agent-1"}, nil
	}
	return nil, nil
}
func (s *authGateStore) UpdateAgentTokenLastUsed(context.Context, string) error { return nil }

// POST /import/cbom writes foreign-BOM contents (up to 50 MB) into the shared
// inventory. Like the other inventory mutations it must be admin-only: the
// read-only "viewer" role and agent tokens must be refused. The body is
// deliberately malformed so an admin who passes the gate is rejected by the
// handler with 400 before any store access.
func TestRouter_ImportCBOM_AdminOnly(t *testing.T) {
	secret := []byte("test-secret")
	sum := sha256.Sum256([]byte("agent-secret"))
	st := &authGateStore{agentHash: hex.EncodeToString(sum[:])}
	router := NewRouter(st, &config.Config{}, "", "", secret,
		observcache.NewNoop(), scoring.NewNoopScorer(), sse.NewHub(),
		venafi.NewLiveConfig(config.VenafiExportConfig{}))

	cookie := func(role string) *http.Cookie {
		tok, err := auth.SignJWT(secret, "u1", "u1@example.com", role)
		if err != nil {
			t.Fatalf("SignJWT: %v", err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}
	}

	cases := []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"unauthenticated", func(*http.Request) {}, http.StatusUnauthorized},
		{"viewer", func(r *http.Request) { r.AddCookie(cookie("viewer")) }, http.StatusForbidden},
		{"agent token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer agent-secret") }, http.StatusForbidden},
		{"admin reaches handler", func(r *http.Request) { r.AddCookie(cookie("admin")) }, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/import/cbom", strings.NewReader("{{{"))
			tc.mutate(req)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
