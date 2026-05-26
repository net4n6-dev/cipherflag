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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/auth"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// fakeAuthMeStore is a narrow test double for AuthHandler.Me. Embeds
// store.CertStore so we can override just the two methods Me() uses
// (HasUsers + GetUserByID) without implementing the full interface.
type fakeAuthMeStore struct {
	store.CertStore
	hasUsers    bool
	hasUsersErr error
	users       map[string]*model.User
}

func (f *fakeAuthMeStore) HasUsers(_ context.Context) (bool, error) {
	return f.hasUsers, f.hasUsersErr
}
func (f *fakeAuthMeStore) GetUserByID(_ context.Context, id string) (*model.User, error) {
	return f.users[id], nil
}

const testJWTSecret = "0123456789abcdef0123456789abcdef"

func TestAuthMe_NoCookie_NoUsers_ReturnsAnonymousAdmin(t *testing.T) {
	// Fresh deployment: no users yet, no cookie. Backend runs in
	// "no-auth mode" and surfaces the anonymous-admin fallback.
	h := NewAuthHandler(&fakeAuthMeStore{hasUsers: false}, []byte(testJWTSecret))
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	rr := httptest.NewRecorder()
	h.Me(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (never 401 from this endpoint)", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	user, _ := body["user"].(map[string]any)
	if user == nil || user["id"] != "anonymous" {
		t.Errorf("expected anonymous admin user, got %v", body)
	}
	if auth, _ := body["authenticated"].(bool); auth {
		t.Errorf("anonymous admin must not be flagged as authenticated")
	}
}

func TestAuthMe_NoCookie_UsersExist_ReturnsNullUser(t *testing.T) {
	// Users exist but client has no cookie — the v1.4.1 behaviour
	// change. Previously this returned 401 (via the Auth middleware);
	// now it returns 200 with user:null so the browser console stays
	// clean on initial unauthenticated page load.
	h := NewAuthHandler(&fakeAuthMeStore{hasUsers: true}, []byte(testJWTSecret))
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	rr := httptest.NewRecorder()
	h.Me(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (pre-v1.4.1 returned 401 here — regression guard)", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["user"] != nil {
		t.Errorf("expected user=null for unauthenticated visit, got %v", body["user"])
	}
	if auth, _ := body["authenticated"].(bool); auth {
		t.Errorf("authenticated must be false for no-cookie request")
	}
}

func TestAuthMe_InvalidCookie_ReturnsSessionExpired(t *testing.T) {
	h := NewAuthHandler(&fakeAuthMeStore{hasUsers: true}, []byte(testJWTSecret))
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "cipherflag_token", Value: "not-a-valid-jwt"})
	rr := httptest.NewRecorder()
	h.Me(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["user"] != nil {
		t.Errorf("expected user=null for invalid cookie, got %v", body["user"])
	}
	if expired, _ := body["session_expired"].(bool); !expired {
		t.Errorf("expected session_expired=true for invalid cookie; body=%v", body)
	}
}

func TestAuthMe_ValidCookie_ReturnsAuthenticatedUser(t *testing.T) {
	u := &model.User{
		ID:          "user-1",
		Email:       "admin@example.com",
		DisplayName: "Admin",
		Role:        "admin",
		CreatedAt:   time.Now(),
	}
	token, err := auth.SignJWT([]byte(testJWTSecret), u.ID, u.Email, u.Role)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	h := NewAuthHandler(&fakeAuthMeStore{
		hasUsers: true,
		users:    map[string]*model.User{u.ID: u},
	}, []byte(testJWTSecret))
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "cipherflag_token", Value: token})
	rr := httptest.NewRecorder()
	h.Me(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if auth, _ := body["authenticated"].(bool); !auth {
		t.Errorf("authenticated must be true for valid cookie; body=%v", body)
	}
	user, _ := body["user"].(map[string]any)
	if user == nil || user["id"] != u.ID {
		t.Errorf("expected user %q in response; got %v", u.ID, body)
	}
}
