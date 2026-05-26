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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type AgentTokenHandler struct {
	store store.CryptoStore
}

func NewAgentTokenHandler(s store.CryptoStore) *AgentTokenHandler {
	return &AgentTokenHandler{store: s}
}

type createAgentTokenRequest struct {
	Name string `json:"name"`
}

func (h *AgentTokenHandler) Create(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUser(r.Context())
	if u == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createAgentTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Generate 256-bit random token.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	rawToken := hex.EncodeToString(buf)
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])
	tokenPrefix := rawToken[:8]

	token := &model.AgentToken{
		Name:        req.Name,
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
		CreatedBy:   u.ID,
	}

	if err := h.store.CreateAgentToken(r.Context(), token); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"token":        rawToken,
		"id":           token.ID,
		"name":         token.Name,
		"token_prefix": token.TokenPrefix,
	})
}

func (h *AgentTokenHandler) List(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.store.ListAgentTokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// TokenHash is already stripped via json:"-" tag on model.AgentToken
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

func (h *AgentTokenHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := h.store.RevokeAgentToken(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
