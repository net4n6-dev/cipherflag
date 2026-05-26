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

package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/auth"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type mockStore struct {
	store.CryptoStore
	hasUsers bool
	token    *model.AgentToken
}

func (m *mockStore) HasUsers(ctx context.Context) (bool, error) {
	return m.hasUsers, nil
}

func (m *mockStore) GetAgentToken(ctx context.Context, tokenHash string) (*model.AgentToken, error) {
	if m.token != nil && m.token.TokenHash == tokenHash {
		return m.token, nil
	}
	return nil, nil
}

func (m *mockStore) UpdateAgentTokenLastUsed(ctx context.Context, id string) error {
	return nil
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func TestAuth_AgentTokenValid(t *testing.T) {
	rawToken := "test-agent-token-raw-value-12345"
	tokenHash := hashToken(rawToken)

	st := &mockStore{
		hasUsers: true,
		token: &model.AgentToken{
			ID: "tok-1", Name: "test-agent", TokenHash: tokenHash,
			TokenPrefix: rawToken[:8], CreatedBy: "admin-1",
			CreatedAt: time.Now(),
		},
	}

	var gotUser *model.UserContext
	handler := Auth(st, []byte("secret"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = GetUser(r.Context())
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("POST", "/api/v1/ingest", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if gotUser == nil {
		t.Fatal("expected user context to be set for agent token")
	}
	if gotUser.Role != "agent" {
		t.Errorf("role = %q, want agent", gotUser.Role)
	}
	if gotUser.ID != "tok-1" {
		t.Errorf("id = %q, want tok-1", gotUser.ID)
	}
}

func TestAuth_AgentTokenRevoked(t *testing.T) {
	rawToken := "revoked-agent-token-value-12345"
	tokenHash := hashToken(rawToken)
	revokedAt := time.Now()

	st := &mockStore{
		hasUsers: true,
		token: &model.AgentToken{
			ID: "tok-2", Name: "revoked", TokenHash: tokenHash,
			TokenPrefix: rawToken[:8], CreatedBy: "admin-1",
			CreatedAt: time.Now(), RevokedAt: &revokedAt,
		},
	}

	handler := Auth(st, []byte("secret"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("POST", "/api/v1/ingest", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d, want 401 for revoked token", w.Code)
	}
}

func TestAuth_AgentTokenInvalid(t *testing.T) {
	st := &mockStore{hasUsers: true}

	handler := Auth(st, []byte("secret"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("POST", "/api/v1/ingest", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d, want 401 for invalid token", w.Code)
	}
}

func TestAuth_AgentTokenWorksWithNoUsers(t *testing.T) {
	rawToken := "no-users-token-raw-value-12345"
	tokenHash := hashToken(rawToken)

	st := &mockStore{
		hasUsers: false,
		token: &model.AgentToken{
			ID: "tok-3", Name: "agent-no-users", TokenHash: tokenHash,
			TokenPrefix: rawToken[:8], CreatedBy: "seed-admin",
			CreatedAt: time.Now(),
		},
	}

	var gotUser *model.UserContext
	handler := Auth(st, []byte("secret"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = GetUser(r.Context())
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("POST", "/api/v1/ingest", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if gotUser == nil || gotUser.Role != "agent" {
		t.Error("expected agent auth to work even with no users")
	}
}

func TestAuth_JWTCookieStillWorks(t *testing.T) {
	secret := auth.GenerateSecret("test-middleware-secret")
	st := &mockStore{hasUsers: true}

	token, _ := auth.SignJWT(secret, "user-123", "admin@test.com", "admin")

	var gotUser *model.UserContext
	handler := Auth(st, secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = GetUser(r.Context())
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200 for JWT cookie", w.Code)
	}
	if gotUser == nil || gotUser.Role != "admin" {
		t.Error("expected JWT auth to still work")
	}
}

func TestRequireHumanUser_BlocksAgents(t *testing.T) {
	var called bool
	handler := RequireHumanUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	ctx := context.WithValue(req.Context(), userContextKey, &model.UserContext{
		ID: "tok-1", Role: "agent",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("status = %d, want 403 for agent role", w.Code)
	}
	if called {
		t.Error("handler should not be called for agent role")
	}
}

func TestRequireHumanUser_AllowsAdmin(t *testing.T) {
	var called bool
	handler := RequireHumanUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
	ctx := context.WithValue(req.Context(), userContextKey, &model.UserContext{
		ID: "user-1", Role: "admin",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200 for admin role", w.Code)
	}
	if !called {
		t.Error("handler should be called for admin role")
	}
}
