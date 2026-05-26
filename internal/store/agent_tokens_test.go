//go:build integration

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

package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func generateTestToken() (raw string, hash string, prefix string) {
	buf := make([]byte, 32)
	rand.Read(buf)
	raw = hex.EncodeToString(buf)
	h := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(h[:])
	prefix = raw[:8]
	return
}

func TestCreateAndGetAgentToken(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	userID := seedUser(t, st)

	rawToken, tokenHash, tokenPrefix := generateTestToken()
	_ = rawToken

	token := &model.AgentToken{
		Name:        "prod-osquery",
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
		CreatedBy:   userID,
	}

	if err := st.CreateAgentToken(ctx, token); err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	if token.ID == "" {
		t.Fatal("expected token ID to be populated after create")
	}

	got, err := st.GetAgentToken(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetAgentToken: %v", err)
	}
	if got == nil {
		t.Fatal("expected agent token, got nil")
	}
	if got.Name != "prod-osquery" {
		t.Errorf("name = %q, want prod-osquery", got.Name)
	}
	if got.TokenPrefix != tokenPrefix {
		t.Errorf("token_prefix = %q, want %q", got.TokenPrefix, tokenPrefix)
	}
	if got.CreatedBy != userID {
		t.Errorf("created_by = %q, want %q", got.CreatedBy, userID)
	}
	if got.RevokedAt != nil {
		t.Error("expected revoked_at to be nil for new token")
	}
}

func TestGetAgentToken_NotFound(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	got, err := st.GetAgentToken(ctx, "nonexistent-hash")
	if err != nil {
		t.Fatalf("GetAgentToken: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing token, got %+v", got)
	}
}

func TestListAgentTokens(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	userID := seedUser(t, st)

	for _, name := range []string{"token-a", "token-b"} {
		_, hash, prefix := generateTestToken()
		tok := &model.AgentToken{
			Name: name, TokenHash: hash, TokenPrefix: prefix, CreatedBy: userID,
		}
		if err := st.CreateAgentToken(ctx, tok); err != nil {
			t.Fatalf("CreateAgentToken %s: %v", name, err)
		}
	}

	tokens, err := st.ListAgentTokens(ctx)
	if err != nil {
		t.Fatalf("ListAgentTokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("tokens count = %d, want 2", len(tokens))
	}
}

func TestRevokeAgentToken(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	userID := seedUser(t, st)

	_, hash, prefix := generateTestToken()
	tok := &model.AgentToken{
		Name: "revoke-me", TokenHash: hash, TokenPrefix: prefix, CreatedBy: userID,
	}
	if err := st.CreateAgentToken(ctx, tok); err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}

	if err := st.RevokeAgentToken(ctx, tok.ID); err != nil {
		t.Fatalf("RevokeAgentToken: %v", err)
	}

	got, err := st.GetAgentToken(ctx, hash)
	if err != nil {
		t.Fatalf("GetAgentToken after revoke: %v", err)
	}
	if got == nil {
		t.Fatal("expected token to still exist after revoke")
	}
	if got.RevokedAt == nil {
		t.Error("expected revoked_at to be set after revoke")
	}
}

func TestUpdateAgentTokenLastUsed(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	userID := seedUser(t, st)

	_, hash, prefix := generateTestToken()
	tok := &model.AgentToken{
		Name: "use-me", TokenHash: hash, TokenPrefix: prefix, CreatedBy: userID,
	}
	if err := st.CreateAgentToken(ctx, tok); err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}

	if err := st.UpdateAgentTokenLastUsed(ctx, tok.ID); err != nil {
		t.Fatalf("UpdateAgentTokenLastUsed: %v", err)
	}

	got, err := st.GetAgentToken(ctx, hash)
	if err != nil {
		t.Fatalf("GetAgentToken after last_used update: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Error("expected last_used_at to be set")
	}
	if time.Since(*got.LastUsedAt) > 5*time.Second {
		t.Errorf("last_used_at too old: %v", got.LastUsedAt)
	}
}
