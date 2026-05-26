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
	"strings"
	"sync"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/auth"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

type contextKey string

const userContextKey contextKey = "user"

func GetUser(ctx context.Context) *model.UserContext {
	u, _ := ctx.Value(userContextKey).(*model.UserContext)
	return u
}

// UserContextKeyExported returns the context key for testing.
func UserContextKeyExported() contextKey {
	return userContextKey
}

func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := GetUser(r.Context())
		if u == nil || u.Role != "admin" {
			http.Error(w, `{"error":"admin access required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireHumanUser rejects agent tokens. Use on routes that agents must not access.
func RequireHumanUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := GetUser(r.Context())
		if u != nil && u.Role == "agent" {
			http.Error(w, `{"error":"human user required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// agentTokenStore is the subset of CryptoStore needed for agent token auth.
type agentTokenStore interface {
	HasUsers(ctx context.Context) (bool, error)
	GetAgentToken(ctx context.Context, tokenHash string) (*model.AgentToken, error)
	UpdateAgentTokenLastUsed(ctx context.Context, id string) error
}

func Auth(st agentTokenStore, jwtSecret []byte) func(http.Handler) http.Handler {
	var (
		hasUsersCached bool
		cacheTime      time.Time
		cacheMu        sync.Mutex
	)

	checkHasUsers := func(ctx context.Context) bool {
		cacheMu.Lock()
		defer cacheMu.Unlock()
		if time.Since(cacheTime) < 60*time.Second {
			return hasUsersCached
		}
		has, err := st.HasUsers(ctx)
		if err != nil {
			return hasUsersCached
		}
		hasUsersCached = has
		cacheTime = time.Now()
		return has
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for agent token (Authorization: Bearer header) first.
			if bearer := r.Header.Get("Authorization"); strings.HasPrefix(bearer, "Bearer ") {
				rawToken := strings.TrimPrefix(bearer, "Bearer ")
				h := sha256.Sum256([]byte(rawToken))
				tokenHash := hex.EncodeToString(h[:])

				agentToken, err := st.GetAgentToken(r.Context(), tokenHash)
				if err == nil && agentToken != nil && agentToken.RevokedAt == nil {
					ctx := context.WithValue(r.Context(), userContextKey, &model.UserContext{
						ID: agentToken.ID, Role: "agent",
					})
					// Fire-and-forget last_used update.
					go st.UpdateAgentTokenLastUsed(context.Background(), agentToken.ID)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// Bearer token present but invalid/revoked -> 401.
				http.Error(w, `{"error":"invalid or revoked agent token"}`, http.StatusUnauthorized)
				return
			}

			// Existing flow: no-auth mode if no users exist.
			if !checkHasUsers(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}

			token := auth.GetTokenFromCookie(r)
			if token == "" {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}

			claims, err := auth.VerifyJWT(jwtSecret, token)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, &model.UserContext{
				ID: claims.Sub, Email: claims.Email, Role: claims.Role,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
