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
	"strings"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type fakeSetupStore struct {
	store.CertStore
	hasUsers bool
	created  []*model.User
}

func (f *fakeSetupStore) HasUsers(context.Context) (bool, error) { return f.hasUsers, nil }
func (f *fakeSetupStore) CreateUser(_ context.Context, u *model.User) error {
	u.ID = "u-1"
	f.created = append(f.created, u)
	return nil
}

const setupBody = `{"email":"admin@example.com","password":"correct-horse-battery","display_name":"Admin"}`

func setupReq(token *string) *http.Request {
	req := httptest.NewRequest("POST", "/api/v1/auth/setup-admin", strings.NewReader(setupBody))
	if token != nil {
		req.Header.Set("X-Setup-Token", *token)
	}
	return req
}

func str(s string) *string { return &s }

const realSetupToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Review focus 4: every wrong or malformed token is refused and creates no user.
func TestSetupAdmin_RejectsBadTokens(t *testing.T) {
	cases := map[string]*string{
		"missing header":      nil,
		"empty header":        str(""),
		"wrong value":         str(strings.Repeat("f", 64)),
		"prefix of real":      str(realSetupToken[:32]),
		"longer than real":    str(realSetupToken + "0"),
		"leading space":       str(" " + realSetupToken),
		"trailing whitespace": str(realSetupToken + "\n"),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			st := &fakeSetupStore{}
			h := NewAuthHandler(st, []byte(testJWTSecret), realSetupToken)
			rr := httptest.NewRecorder()
			h.SetupAdmin(rr, setupReq(tok))
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rr.Code, rr.Body.String())
			}
			if len(st.created) != 0 {
				t.Error("a user was created without a valid token")
			}
		})
	}
}

// Review focus 4: a handler built with an empty token must not match an empty header.
func TestSetupAdmin_EmptyConfiguredTokenNeverMatches(t *testing.T) {
	st := &fakeSetupStore{}
	h := NewAuthHandler(st, []byte(testJWTSecret), "")
	for _, tok := range []*string{nil, str("")} {
		rr := httptest.NewRecorder()
		h.SetupAdmin(rr, setupReq(tok))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	}
	if len(st.created) != 0 {
		t.Error("a user was created with no token configured")
	}
}

func TestSetupAdmin_CorrectTokenCreatesAdminAndSetsCookie(t *testing.T) {
	st := &fakeSetupStore{}
	h := NewAuthHandler(st, []byte(testJWTSecret), realSetupToken)
	rr := httptest.NewRecorder()
	h.SetupAdmin(rr, setupReq(str(realSetupToken)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rr.Code, rr.Body.String())
	}
	if len(st.created) != 1 || st.created[0].Role != "admin" {
		t.Fatalf("created = %+v, want one admin", st.created)
	}
	if len(rr.Result().Cookies()) == 0 {
		t.Error("no session cookie set")
	}
}

// Users-exist is checked before the token (403 either way, distinct message).
func TestSetupAdmin_UsersExistWinsOverToken(t *testing.T) {
	for _, tok := range []*string{nil, str(realSetupToken)} {
		st := &fakeSetupStore{hasUsers: true}
		h := NewAuthHandler(st, []byte(testJWTSecret), realSetupToken)
		rr := httptest.NewRecorder()
		h.SetupAdmin(rr, setupReq(tok))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
		var body map[string]string
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		if !strings.Contains(body["error"], "users already exist") {
			t.Errorf("error = %q, want users-already-exist", body["error"])
		}
		if len(st.created) != 0 {
			t.Error("a user was created although users exist")
		}
	}
}

func TestMe_NoCookie_NoUsers_ReturnsNullUser(t *testing.T) {
	h := NewAuthHandler(&fakeSetupStore{hasUsers: false}, []byte(testJWTSecret), realSetupToken)
	rr := httptest.NewRecorder()
	h.Me(rr, httptest.NewRequest("GET", "/api/v1/auth/me", nil))
	var body map[string]any
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, ok := body["user"]; !ok {
		t.Error("body must contain the user key")
	}
	if body["user"] != nil {
		t.Errorf("user = %v, want null: no anonymous admin", body["user"])
	}
	if a, _ := body["authenticated"].(bool); a {
		t.Error("authenticated must be false")
	}
}
