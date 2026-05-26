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
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type mockAgentTokenStore struct {
	store.CryptoStore
	tokens []model.AgentToken
}

func (m *mockAgentTokenStore) CreateAgentToken(ctx context.Context, token *model.AgentToken) error {
	token.ID = "new-token-id"
	token.CreatedAt = time.Now()
	m.tokens = append(m.tokens, *token)
	return nil
}

func (m *mockAgentTokenStore) ListAgentTokens(ctx context.Context) ([]model.AgentToken, error) {
	return m.tokens, nil
}

func (m *mockAgentTokenStore) RevokeAgentToken(ctx context.Context, id string) error {
	for i := range m.tokens {
		if m.tokens[i].ID == id {
			now := time.Now()
			m.tokens[i].RevokedAt = &now
			return nil
		}
	}
	return nil
}

func withUser(r *http.Request, id, role string) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.UserContextKeyExported(), &model.UserContext{
		ID: id, Email: "admin@test.com", Role: role,
	})
	return r.WithContext(ctx)
}

func TestAgentTokenHandler_Create(t *testing.T) {
	st := &mockAgentTokenStore{}
	h := NewAgentTokenHandler(st)

	body := `{"name":"prod-osquery"}`
	req := httptest.NewRequest("POST", "/api/v1/auth/agent-tokens", bytes.NewBufferString(body))
	req = withUser(req, "admin-1", "admin")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] == nil || resp["token"] == "" {
		t.Error("expected raw token in response")
	}
	if resp["id"] == nil {
		t.Error("expected id in response")
	}
}

func TestAgentTokenHandler_Create_MissingName(t *testing.T) {
	st := &mockAgentTokenStore{}
	h := NewAgentTokenHandler(st)

	body := `{}`
	req := httptest.NewRequest("POST", "/api/v1/auth/agent-tokens", bytes.NewBufferString(body))
	req = withUser(req, "admin-1", "admin")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAgentTokenHandler_List(t *testing.T) {
	st := &mockAgentTokenStore{
		tokens: []model.AgentToken{
			{ID: "tok-1", Name: "token-a", TokenPrefix: "abcd1234", CreatedBy: "admin-1"},
			{ID: "tok-2", Name: "token-b", TokenPrefix: "efgh5678", CreatedBy: "admin-1"},
		},
	}
	h := NewAgentTokenHandler(st)

	req := httptest.NewRequest("GET", "/api/v1/auth/agent-tokens", nil)
	req = withUser(req, "admin-1", "admin")
	w := httptest.NewRecorder()

	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	tokens := resp["tokens"].([]any)
	if len(tokens) != 2 {
		t.Errorf("tokens count = %d, want 2", len(tokens))
	}
}

func TestAgentTokenHandler_Delete(t *testing.T) {
	st := &mockAgentTokenStore{
		tokens: []model.AgentToken{
			{ID: "tok-1", Name: "delete-me", TokenPrefix: "abcd1234", CreatedBy: "admin-1"},
		},
	}
	h := NewAgentTokenHandler(st)

	r := chi.NewRouter()
	r.Delete("/api/v1/auth/agent-tokens/{id}", h.Delete)

	req := httptest.NewRequest("DELETE", "/api/v1/auth/agent-tokens/tok-1", nil)
	req = withUser(req, "admin-1", "admin")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
