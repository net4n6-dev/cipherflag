# Authentication System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add user authentication with JWT in HTTP-only cookies, bcrypt passwords, admin/viewer roles, auth middleware, and first-visit admin registration — backward compatible with existing deployments.

**Architecture:** New `internal/auth/` package for JWT and password operations. New `internal/store/users.go` for user queries. Auth middleware wraps all API routes but skips when no users exist. Frontend login/setup-admin pages with auth state in layout. Cookie-based JWT — no localStorage tokens.

**Tech Stack:** Go (bcrypt via golang.org/x/crypto, HS256 JWT via crypto/hmac), SvelteKit 5, PostgreSQL

**Spec:** `docs/superpowers/specs/2026-03-28-authentication-design.md`

---

## File Map

### Backend

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/store/migrations/005_auth.sql` | Create | Users table |
| `internal/model/user.go` | Create | User type, UserContext, request types |
| `internal/auth/password.go` | Create | Bcrypt hash/verify |
| `internal/auth/jwt.go` | Create | JWT sign/verify, cookie helpers |
| `internal/store/store.go` | Modify | Add user methods to CertStore |
| `internal/store/users.go` | Create | User query implementations |
| `internal/api/handler/auth.go` | Create | Auth endpoint handlers |
| `internal/api/middleware/auth.go` | Create | Auth middleware |
| `internal/api/server.go` | Modify | Wire auth middleware + routes |
| `go.mod` | Modify | Add golang.org/x/crypto |

### Frontend

| File | Action | Responsibility |
|------|--------|----------------|
| `frontend/src/lib/auth.ts` | Create | Auth state + API helpers |
| `frontend/src/routes/login/+page.svelte` | Create | Login form |
| `frontend/src/routes/setup-admin/+page.svelte` | Create | First admin registration |
| `frontend/src/routes/+layout.svelte` | Modify | Auth check, user menu, logout |

---

## Task 1: Migration + User Model + Password Utils

**Files:**
- Create: `internal/store/migrations/005_auth.sql`
- Create: `internal/model/user.go`
- Create: `internal/auth/password.go`
- Modify: `go.mod`

- [ ] **Step 1: Add golang.org/x/crypto dependency**

```bash
cd /Users/Erik/projects/cipherflag && go get golang.org/x/crypto/bcrypt
```

- [ ] **Step 2: Create migration**

Create `internal/store/migrations/005_auth.sql`:

```sql
-- 005_auth.sql
-- User accounts for authentication.

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);
```

- [ ] **Step 3: Create user model**

Create `internal/model/user.go`:

```go
package model

import "time"

// User represents an authenticated user.
type User struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	PasswordHash string    `json:"-"` // never serialized
	DisplayName string     `json:"display_name"`
	Role        string     `json:"role"` // "admin" or "viewer"
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// UserContext is the authenticated user info extracted from JWT and injected into request context.
type UserContext struct {
	ID    string
	Email string
	Role  string
}

// LoginRequest is the body for POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// CreateUserRequest is the body for POST /auth/users and /auth/setup-admin.
type CreateUserRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role,omitempty"` // defaults to "viewer"
}

// UpdateUserRequest is the body for PUT /auth/users/{id}.
type UpdateUserRequest struct {
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role,omitempty"`
}

// ChangePasswordRequest is the body for PUT /auth/me/password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}
```

- [ ] **Step 4: Create password utilities**

Create `internal/auth/password.go`:

```go
package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost     = 12
	minPasswordLen = 8
)

// HashPassword hashes a plaintext password with bcrypt.
func HashPassword(password string) (string, error) {
	if len(password) < minPasswordLen {
		return "", fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword compares a plaintext password against a bcrypt hash.
func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
```

- [ ] **Step 5: Verify compilation**

```bash
go build ./...
```

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/store/migrations/005_auth.sql internal/model/user.go internal/auth/password.go
git commit -m "feat(auth): add user model, migration, and bcrypt password utilities"
```

---

## Task 2: JWT Utilities

**Files:**
- Create: `internal/auth/jwt.go`

- [ ] **Step 1: Create JWT sign/verify and cookie helpers**

```go
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	CookieName = "cipherflag_token"
	tokenExpiry = 24 * time.Hour
)

// JWTHeader is the fixed header for HS256.
var jwtHeaderB64 = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// Claims holds the JWT payload.
type Claims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// SignJWT creates a signed JWT string.
func SignJWT(secret []byte, userID, email, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		Sub:   userID,
		Email: email,
		Role:  role,
		Iat:   now.Unix(),
		Exp:   now.Add(tokenExpiry).Unix(),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	sigInput := jwtHeaderB64 + "." + payloadB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return sigInput + "." + sig, nil
}

// VerifyJWT parses and validates a JWT string. Returns claims if valid.
func VerifyJWT(secret []byte, token string) (*Claims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Verify signature
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode claims
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// SetTokenCookie sets the JWT as an HTTP-only cookie.
func SetTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(tokenExpiry.Seconds()),
	})
}

// ClearTokenCookie removes the JWT cookie.
func ClearTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// GetTokenFromCookie extracts the JWT string from the request cookie.
func GetTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// GenerateSecret creates a deterministic JWT secret from a seed string.
// In production, use a dedicated secret; this derives one from config for simplicity.
func GenerateSecret(seed string) []byte {
	h := sha256.Sum256([]byte("cipherflag-jwt-" + seed))
	return h[:]
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/auth/...
```

- [ ] **Step 3: Commit**

```bash
git add internal/auth/jwt.go
git commit -m "feat(auth): add JWT sign/verify and cookie utilities"
```

---

## Task 3: Store — User Methods

**Files:**
- Modify: `internal/store/store.go`
- Create: `internal/store/users.go`

- [ ] **Step 1: Add user methods to CertStore interface**

Add a `// Users` section:

```go
	// Users
	HasUsers(ctx context.Context) (bool, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	ListUsers(ctx context.Context) ([]model.User, error)
	CreateUser(ctx context.Context, user *model.User) error
	UpdateUser(ctx context.Context, id string, displayName string, role string) error
	UpdateUserPassword(ctx context.Context, id string, passwordHash string) error
	UpdateUserLastLogin(ctx context.Context, id string) error
	DeleteUser(ctx context.Context, id string) error
```

- [ ] **Step 2: Implement in users.go**

Create `internal/store/users.go`:

```go
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/cyberflag-ai/cipherflag/internal/model"
)

func (s *PostgresStore) HasUsers(ctx context.Context) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users)").Scan(&exists)
	return exists, err
}

func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var u model.User
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, display_name, role, created_at, updated_at, last_login_at
		FROM users WHERE email = $1
	`, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Role, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	var u model.User
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, display_name, role, created_at, updated_at, last_login_at
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Role, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *PostgresStore) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, password_hash, display_name, role, created_at, updated_at, last_login_at
		FROM users ORDER BY created_at
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Role, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if users == nil {
		users = []model.User{}
	}
	return users, nil
}

func (s *PostgresStore) CreateUser(ctx context.Context, user *model.User) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, display_name, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at
	`, user.Email, user.PasswordHash, user.DisplayName, user.Role).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
}

func (s *PostgresStore) UpdateUser(ctx context.Context, id string, displayName string, role string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET display_name = $2, role = $3, updated_at = NOW() WHERE id = $1
	`, id, displayName, role)
	return err
}

func (s *PostgresStore) UpdateUserPassword(ctx context.Context, id string, passwordHash string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1
	`, id, passwordHash)
	return err
}

func (s *PostgresStore) UpdateUserLastLogin(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET last_login_at = NOW() WHERE id = $1
	`, id)
	return err
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}
```

- [ ] **Step 3: Verify compilation**

```bash
go build ./...
```

Expected: Compile error — PostgresStore missing methods. That's correct since the interface now requires them and `users.go` provides them. If it compiles, good. If not, ensure the `pgx` import is correct.

- [ ] **Step 4: Commit**

```bash
git add internal/store/store.go internal/store/users.go
git commit -m "feat(auth): add user store methods (CRUD, auth queries)"
```

---

## Task 4: Auth Middleware

**Files:**
- Create: `internal/api/middleware/auth.go`

- [ ] **Step 1: Create auth middleware**

```go
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

// GetUser extracts the authenticated user from the request context.
func GetUser(ctx context.Context) *model.UserContext {
	u, _ := ctx.Value(userContextKey).(*model.UserContext)
	return u
}

// RequireAdmin returns 403 if the user is not an admin.
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

// Auth returns middleware that validates JWT cookies.
// If no users exist in the database, auth is bypassed (backward compatible).
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
			return hasUsersCached // keep old value on error
		}
		hasUsersCached = has
		cacheTime = time.Now()
		return has
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth if no users exist (backward compatible)
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
				ID:    claims.Sub,
				Email: claims.Email,
				Role:  claims.Role,
			})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/api/middleware/...
```

- [ ] **Step 3: Commit**

```bash
git add internal/api/middleware/auth.go
git commit -m "feat(auth): add JWT auth middleware with backward compatibility"
```

---

## Task 5: Auth Handlers

**Files:**
- Create: `internal/api/handler/auth.go`

- [ ] **Step 1: Create auth handlers**

```go
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cyberflag-ai/cipherflag/internal/auth"
	"github.com/cyberflag-ai/cipherflag/internal/api/middleware"
	"github.com/cyberflag-ai/cipherflag/internal/model"
	"github.com/cyberflag-ai/cipherflag/internal/store"
)

type AuthHandler struct {
	store     store.CertStore
	jwtSecret []byte
}

func NewAuthHandler(s store.CertStore, jwtSecret []byte) *AuthHandler {
	return &AuthHandler{store: s, jwtSecret: jwtSecret}
}

// Status returns whether any users exist (frontend routing decision).
func (h *AuthHandler) Status(w http.ResponseWriter, r *http.Request) {
	has, err := h.store.HasUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"has_users": has})
}

// Login authenticates a user and sets JWT cookie.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user == nil || !auth.CheckPassword(req.Password, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token, err := auth.SignJWT(h.jwtSecret, user.ID, user.Email, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "creating token")
		return
	}

	h.store.UpdateUserLastLogin(r.Context(), user.ID)
	auth.SetTokenCookie(w, token)
	user.PasswordHash = ""
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

// Logout clears the JWT cookie.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	auth.ClearTokenCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// Me returns the current user profile.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	uc := middleware.GetUser(r.Context())
	if uc == nil {
		// No auth mode (no users exist)
		writeJSON(w, http.StatusOK, map[string]any{
			"id": "", "email": "", "display_name": "Anonymous", "role": "admin",
		})
		return
	}

	user, err := h.store.GetUserByID(r.Context(), uc.ID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}
	user.PasswordHash = ""
	writeJSON(w, http.StatusOK, user)
}

// ChangePassword updates the current user's password.
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	uc := middleware.GetUser(r.Context())
	if uc == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req model.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.store.GetUserByID(r.Context(), uc.ID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}

	if !auth.CheckPassword(req.CurrentPassword, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.store.UpdateUserPassword(r.Context(), uc.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password updated"})
}

// SetupAdmin creates the first admin user. Only works when no users exist.
func (h *AuthHandler) SetupAdmin(w http.ResponseWriter, r *http.Request) {
	has, err := h.store.HasUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if has {
		writeError(w, http.StatusForbidden, "admin already exists")
		return
	}

	var req model.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user := &model.User{
		Email:        req.Email,
		PasswordHash: hash,
		DisplayName:  req.DisplayName,
		Role:         "admin",
	}

	if err := h.store.CreateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	token, err := auth.SignJWT(h.jwtSecret, user.ID, user.Email, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "creating token")
		return
	}

	auth.SetTokenCookie(w, token)
	user.PasswordHash = ""
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
}

// ListUsers returns all users (admin only).
func (h *AuthHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Strip password hashes
	for i := range users {
		users[i].PasswordHash = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// CreateUser creates a new user (admin only).
func (h *AuthHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req model.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Role == "" {
		req.Role = "viewer"
	}
	if req.Role != "admin" && req.Role != "viewer" {
		writeError(w, http.StatusBadRequest, "role must be 'admin' or 'viewer'")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user := &model.User{
		Email:        req.Email,
		PasswordHash: hash,
		DisplayName:  req.DisplayName,
		Role:         req.Role,
	}

	if err := h.store.CreateUser(r.Context(), user); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	user.PasswordHash = ""
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
}

// UpdateUser updates a user's display name and role (admin only).
func (h *AuthHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req model.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.store.GetUserByID(r.Context(), id)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	name := req.DisplayName
	if name == "" {
		name = user.DisplayName
	}
	role := req.Role
	if role == "" {
		role = user.Role
	}
	if role != "admin" && role != "viewer" {
		writeError(w, http.StatusBadRequest, "role must be 'admin' or 'viewer'")
		return
	}

	if err := h.store.UpdateUser(r.Context(), id, name, role); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// DeleteUser deletes a user (admin only, cannot delete self).
func (h *AuthHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	uc := middleware.GetUser(r.Context())
	if uc != nil && uc.ID == id {
		writeError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}

	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./...
```

- [ ] **Step 3: Commit**

```bash
git add internal/api/handler/auth.go
git commit -m "feat(auth): add auth handlers (login, logout, me, users CRUD, setup-admin)"
```

---

## Task 6: Wire Auth into Server

**Files:**
- Modify: `internal/api/server.go`

- [ ] **Step 1: Add auth middleware and routes**

Update `NewRouter` to accept JWT secret and wire auth:

Add `jwtSecret []byte` parameter to `NewRouter`:

```go
func NewRouter(st store.CertStore, frontendURL string, pcapInputDir string, pcapMaxSizeMB int, venafiEnabled bool, venafiPushInterval time.Duration, jwtSecret []byte) http.Handler {
```

Create auth handler:
```go
	authH := handler.NewAuthHandler(st, jwtSecret)
```

Inside `r.Route("/api/v1", ...)`, add auth routes BEFORE the existing routes, with the auth middleware applied to the existing routes:

```go
	r.Route("/api/v1", func(r chi.Router) {
		// Public auth routes (no middleware)
		r.Post("/auth/login", authH.Login)
		r.Get("/auth/status", authH.Status)
		r.Post("/auth/setup-admin", authH.SetupAdmin)

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(st, jwtSecret))

			// Auth - any role
			r.Post("/auth/logout", authH.Logout)
			r.Get("/auth/me", authH.Me)
			r.Put("/auth/me/password", authH.ChangePassword)

			// Auth - admin only
			r.Route("/auth/users", func(r chi.Router) {
				r.Use(middleware.RequireAdmin)
				r.Get("/", authH.ListUsers)
				r.Post("/", authH.CreateUser)
				r.Put("/{id}", authH.UpdateUser)
				r.Delete("/{id}", authH.DeleteUser)
			})

			// ... all existing routes go here inside this group ...
```

Move ALL existing routes (certificates, graph, stats, etc.) inside the authenticated group.

Update `cmd/cipherflag/main.go` to pass `jwtSecret` to `NewRouter`:

```go
	jwtSecret := auth.GenerateSecret(cfg.Storage.PostgresURL)
	router := api.NewRouter(st, cfg.Server.FrontendURL, cfg.PCAP.InputDir, cfg.PCAP.MaxFileSizeMB, cfg.Export.Venafi.Enabled, venafiInterval, jwtSecret)
```

Add import for `auth` package in main.go:
```go
	"github.com/cyberflag-ai/cipherflag/internal/auth"
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./...
```

- [ ] **Step 3: Commit**

```bash
git add internal/api/server.go cmd/cipherflag/main.go
git commit -m "feat(auth): wire auth middleware and routes into server"
```

---

## Task 7: Frontend — Auth State + Login Page

**Files:**
- Create: `frontend/src/lib/auth.ts`
- Create: `frontend/src/routes/login/+page.svelte`
- Create: `frontend/src/routes/setup-admin/+page.svelte`

- [ ] **Step 1: Create auth state helper**

Create `frontend/src/lib/auth.ts`:

```typescript
const BASE = '/api/v1';

export interface AuthUser {
	id: string;
	email: string;
	display_name: string;
	role: 'admin' | 'viewer';
	last_login_at?: string;
}

export async function checkAuthStatus(): Promise<{ has_users: boolean }> {
	const res = await fetch(`${BASE}/auth/status`);
	return res.json();
}

export async function getCurrentUser(): Promise<AuthUser | null> {
	const res = await fetch(`${BASE}/auth/me`);
	if (!res.ok) return null;
	return res.json();
}

export async function login(email: string, password: string): Promise<AuthUser> {
	const res = await fetch(`${BASE}/auth/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password }),
	});
	if (!res.ok) {
		const err = await res.json();
		throw new Error(err.error || 'Login failed');
	}
	const data = await res.json();
	return data.user;
}

export async function logout(): Promise<void> {
	await fetch(`${BASE}/auth/logout`, { method: 'POST' });
}

export async function setupAdmin(email: string, password: string, displayName: string): Promise<AuthUser> {
	const res = await fetch(`${BASE}/auth/setup-admin`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password, display_name: displayName }),
	});
	if (!res.ok) {
		const err = await res.json();
		throw new Error(err.error || 'Setup failed');
	}
	const data = await res.json();
	return data.user;
}
```

- [ ] **Step 2: Create login page**

Create `frontend/src/routes/login/+page.svelte` — a centered login form with email + password fields, error message display, and submit handler that calls `login()` then redirects to `/`.

- [ ] **Step 3: Create setup-admin page**

Create `frontend/src/routes/setup-admin/+page.svelte` — a registration form with email, password, confirm password, display name fields. Calls `setupAdmin()` then redirects to `/`.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/lib/auth.ts frontend/src/routes/login/ frontend/src/routes/setup-admin/
git commit -m "feat(auth): add auth state, login page, and setup-admin page"
```

---

## Task 8: Frontend — Layout Auth Check + User Menu

**Files:**
- Modify: `frontend/src/routes/+layout.svelte`

- [ ] **Step 1: Add auth check to layout**

On mount, call `getCurrentUser()`:
- If returns user → store in state, show nav with user menu
- If returns null → call `checkAuthStatus()`
  - `has_users: false` → redirect to `/setup-admin`
  - `has_users: true` → redirect to `/login`
- Skip auth check if current path is `/login` or `/setup-admin`

Add to the nav bar (right side):
- User display name / email
- Role badge (Admin/Viewer)
- Logout button

- [ ] **Step 2: Verify frontend compiles**

```bash
npx svelte-check
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/routes/+layout.svelte
git commit -m "feat(auth): add auth check to layout with user menu and logout"
```

---

## Task 9: Integration Verification

- [ ] **Step 1: Build and migrate**

```bash
go build -o bin/cipherflag ./cmd/cipherflag && bin/cipherflag migrate
```

- [ ] **Step 2: Verify auth status endpoint**

```bash
curl -s http://localhost:8443/api/v1/auth/status
```

Expected: `{"has_users":false}` (no users yet, all endpoints open)

- [ ] **Step 3: Verify existing endpoints still work without auth**

```bash
curl -s http://localhost:8443/api/v1/stats/summary | head -1
```

Expected: JSON response (backward compatible — no users = no auth)

- [ ] **Step 4: Create first admin via API**

```bash
curl -s -X POST http://localhost:8443/api/v1/auth/setup-admin \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cipherflag.local","password":"changeme123","display_name":"Admin"}' | python3 -m json.tool
```

Expected: 201 with user object + Set-Cookie header

- [ ] **Step 5: Verify auth is now enforced**

```bash
curl -s http://localhost:8443/api/v1/stats/summary
```

Expected: `{"error":"authentication required"}` (401)

- [ ] **Step 6: Verify login works**

```bash
curl -s -c /tmp/cf-cookies -X POST http://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cipherflag.local","password":"changeme123"}'
```

Then use cookie:
```bash
curl -s -b /tmp/cf-cookies http://localhost:8443/api/v1/stats/summary | head -1
```

Expected: JSON response (authenticated)
