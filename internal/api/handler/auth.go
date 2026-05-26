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
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/auth"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type AuthHandler struct {
	store     store.CertStore
	jwtSecret []byte
}

func NewAuthHandler(s store.CertStore, jwtSecret []byte) *AuthHandler {
	return &AuthHandler{store: s, jwtSecret: jwtSecret}
}

// Status returns whether any users exist (public, no auth).
func (h *AuthHandler) Status(w http.ResponseWriter, r *http.Request) {
	has, err := h.store.HasUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"has_users": has})
}

// Login validates email+password, signs JWT, sets cookie, updates last_login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	if !auth.CheckPassword(req.Password, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token, err := auth.SignJWT(h.jwtSecret, user.ID, user.Email, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	auth.SetTokenCookie(w, token)
	_ = h.store.UpdateUserLastLogin(r.Context(), user.ID)

	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":           user.ID,
			"email":        user.Email,
			"display_name": user.DisplayName,
			"role":         user.Role,
		},
	})
}

// Logout clears the auth cookie.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	auth.ClearTokenCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Me returns the current user profile. Semantically a *status* endpoint
// rather than a protected resource — always returns 200 with a user
// object or `user: null`. Moved out of the Auth() middleware group in
// server.go so a fresh visit without a cookie doesn't produce a console-
// visible 401 on initial page load.
//
// Response shapes:
//
//	{ "user": { ... }, "authenticated": true }   — valid session
//	{ "user": <anonymous admin>, "authenticated": false } — no-users no-auth mode
//	{ "user": null, "authenticated": false }     — no cookie / expired / invalid
//
// Callers distinguish `user: null` from `user: {anonymous}` via the
// user.id field ("anonymous" for no-auth mode). The frontend
// getCurrentUser() already handles both.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	token := auth.GetTokenFromCookie(r)

	// No cookie — either no-auth mode (no users exist) or unauthenticated.
	if token == "" {
		hasUsers, err := h.store.HasUsers(r.Context())
		if err == nil && !hasUsers {
			writeJSON(w, http.StatusOK, map[string]any{
				"user": map[string]any{
					"id":           "anonymous",
					"email":        "admin@localhost",
					"display_name": "Administrator",
					"role":         "admin",
				},
				"authenticated": false,
			})
			return
		}
		// Users exist but no cookie — unauthenticated, but return 200
		// so the status check doesn't pollute the browser console with
		// a 401 on every initial page load.
		writeJSON(w, http.StatusOK, map[string]any{
			"user":          nil,
			"authenticated": false,
		})
		return
	}

	// Cookie present — verify it.
	claims, err := auth.VerifyJWT(h.jwtSecret, token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"user":            nil,
			"authenticated":   false,
			"session_expired": true,
		})
		return
	}

	user, err := h.store.GetUserByID(r.Context(), claims.Sub)
	if err != nil || user == nil {
		// Token valid but user gone (deleted after token issued).
		writeJSON(w, http.StatusOK, map[string]any{
			"user":          nil,
			"authenticated": false,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":            user.ID,
			"email":         user.Email,
			"display_name":  user.DisplayName,
			"role":          user.Role,
			"created_at":    user.CreatedAt,
			"last_login_at": user.LastLoginAt,
		},
		"authenticated": true,
	})
}

// ChangePassword validates current password, hashes new, updates.
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUser(r.Context())
	if u == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req model.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.store.GetUserByID(r.Context(), u.ID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "user not found")
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

	if err := h.store.UpdateUserPassword(r.Context(), u.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// SetupAdmin creates the first admin user. Returns 403 if users already exist.
func (h *AuthHandler) SetupAdmin(w http.ResponseWriter, r *http.Request) {
	has, err := h.store.HasUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if has {
		writeError(w, http.StatusForbidden, "users already exist")
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

	// Auto-login on success
	token, err := auth.SignJWT(h.jwtSecret, user.ID, user.Email, user.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user created but failed to sign token")
		return
	}

	auth.SetTokenCookie(w, token)

	writeJSON(w, http.StatusCreated, map[string]any{
		"user": map[string]any{
			"id":           user.ID,
			"email":        user.Email,
			"display_name": user.DisplayName,
			"role":         user.Role,
		},
	})
}

// ListUsers returns all users with password_hash stripped.
func (h *AuthHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// password_hash is already stripped via json:"-" tag on model.User
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// CreateUser validates role, hashes password, creates user.
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
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
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

	writeJSON(w, http.StatusCreated, map[string]any{
		"user": map[string]any{
			"id":           user.ID,
			"email":        user.Email,
			"display_name": user.DisplayName,
			"role":         user.Role,
		},
	})
}

// UpdateUser updates display_name and/or role.
func (h *AuthHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req model.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Role != "" && req.Role != "admin" && req.Role != "viewer" {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}

	if err := h.store.UpdateUser(r.Context(), id, req.DisplayName, req.Role); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// DeleteUser deletes a user, preventing self-deletion.
func (h *AuthHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	u := middleware.GetUser(r.Context())
	if u != nil && u.ID == id {
		writeError(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}

	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
