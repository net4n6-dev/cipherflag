package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/cyberflag-ai/cipherflag/internal/auth"
	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type contextKey string

const userContextKey contextKey = "user"

func GetUser(ctx context.Context) *model.UserContext {
	u, _ := ctx.Value(userContextKey).(*model.UserContext)
	return u
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

func Auth(st store.CertStore, jwtSecret []byte) func(http.Handler) http.Handler {
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
