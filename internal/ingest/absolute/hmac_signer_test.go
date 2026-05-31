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

package absolute

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHMACSigner_SetsRequiredHeaders(t *testing.T) {
	signer := NewHMACSigner("token-id-1", "secret-abc")
	signer.now = func() time.Time { return time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC) }

	req, _ := http.NewRequest(http.MethodGet, "https://api.absolute.com/v2/reporting/devices?limit=10", nil)

	if err := signer.Sign(req, nil); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if got := req.Header.Get("X-Abs-Date"); got != "2026-04-12T10:00:00Z" {
		t.Errorf("X-Abs-Date = %q, want 2026-04-12T10:00:00Z", got)
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "ABS1-HMAC-SHA-256 ") {
		t.Errorf("Authorization missing scheme prefix: %q", auth)
	}
	if !strings.Contains(auth, "Credential=token-id-1") {
		t.Errorf("Authorization missing Credential: %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=host;x-abs-date") {
		t.Errorf("Authorization missing SignedHeaders: %q", auth)
	}
	if !strings.Contains(auth, "Signature=") {
		t.Errorf("Authorization missing Signature: %q", auth)
	}
}

func TestHMACSigner_SetsContentTypeForBody(t *testing.T) {
	signer := NewHMACSigner("t", "s")
	body := []byte(`{"hello":"world"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://api.absolute.com/v2/thing", bytes.NewReader(body))
	if err := signer.Sign(req, body); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

func TestHMACSigner_SameInputsProduceSameSignature(t *testing.T) {
	mk := func() *HMACSigner {
		s := NewHMACSigner("t", "secret")
		s.now = func() time.Time { return time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC) }
		return s
	}

	body := []byte(`{"x":1}`)
	req1, _ := http.NewRequest(http.MethodPost, "https://api.absolute.com/v2/thing?a=1&b=2", bytes.NewReader(body))
	req2, _ := http.NewRequest(http.MethodPost, "https://api.absolute.com/v2/thing?a=1&b=2", bytes.NewReader(body))
	_ = mk().Sign(req1, body)
	_ = mk().Sign(req2, body)

	if req1.Header.Get("Authorization") != req2.Header.Get("Authorization") {
		t.Errorf("same inputs produced different signatures:\n  %s\n  %s",
			req1.Header.Get("Authorization"), req2.Header.Get("Authorization"))
	}
}

func TestHMACSigner_BodyChangeMutatesSignature(t *testing.T) {
	mk := func() *HMACSigner {
		s := NewHMACSigner("t", "secret")
		s.now = func() time.Time { return time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC) }
		return s
	}
	req1, _ := http.NewRequest(http.MethodPost, "https://api.absolute.com/v2/thing", bytes.NewReader([]byte(`{"x":1}`)))
	req2, _ := http.NewRequest(http.MethodPost, "https://api.absolute.com/v2/thing", bytes.NewReader([]byte(`{"x":2}`)))
	_ = mk().Sign(req1, []byte(`{"x":1}`))
	_ = mk().Sign(req2, []byte(`{"x":2}`))

	if req1.Header.Get("Authorization") == req2.Header.Get("Authorization") {
		t.Error("different bodies produced the same signature")
	}
}

func TestHMACSigner_QueryChangeMutatesSignature(t *testing.T) {
	mk := func() *HMACSigner {
		s := NewHMACSigner("t", "secret")
		s.now = func() time.Time { return time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC) }
		return s
	}
	req1, _ := http.NewRequest(http.MethodGet, "https://api.absolute.com/v2/thing?a=1", nil)
	req2, _ := http.NewRequest(http.MethodGet, "https://api.absolute.com/v2/thing?a=2", nil)
	_ = mk().Sign(req1, nil)
	_ = mk().Sign(req2, nil)

	if req1.Header.Get("Authorization") == req2.Header.Get("Authorization") {
		t.Error("different queries produced the same signature")
	}
}

func TestHMACSigner_MethodChangeMutatesSignature(t *testing.T) {
	mk := func() *HMACSigner {
		s := NewHMACSigner("t", "secret")
		s.now = func() time.Time { return time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC) }
		return s
	}
	req1, _ := http.NewRequest(http.MethodGet, "https://api.absolute.com/v2/thing", nil)
	req2, _ := http.NewRequest(http.MethodPost, "https://api.absolute.com/v2/thing", nil)
	_ = mk().Sign(req1, nil)
	_ = mk().Sign(req2, nil)

	if req1.Header.Get("Authorization") == req2.Header.Get("Authorization") {
		t.Error("different methods produced the same signature")
	}
}
