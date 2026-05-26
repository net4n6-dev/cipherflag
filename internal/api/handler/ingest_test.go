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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

type mockIngester struct {
	lastResult *ingest.DiscoveryResult
}

func (m *mockIngester) Ingest(ctx context.Context, result *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	m.lastResult = result
	return &ingest.IngestionSummary{HostID: "host-1", CertificatesNew: 1}, nil
}

func (m *mockIngester) AttributeAssets(_ context.Context, claims []ingest.OwnershipClaim) (emitted, skipped int, err error) {
	return len(claims), 0, nil
}

func TestIngestHandler_Success(t *testing.T) {
	mock := &mockIngester{}
	h := NewIngestHandler(mock)

	body := `{"source":"osquery","hostname":"web-01","ip_addresses":["10.0.1.5"],"certificates":[{"fingerprint_sha256":"abc123","subject_cn":"test.com"}]}`
	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewBufferString(body))
	ctx := context.WithValue(req.Context(), middleware.UserContextKeyExported(), &model.UserContext{
		ID: "tok-1", Role: "agent",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Ingest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if mock.lastResult == nil {
		t.Fatal("expected ingester to be called")
	}
	if mock.lastResult.Source != "osquery" {
		t.Errorf("source = %q, want osquery", mock.lastResult.Source)
	}
}

func TestIngestHandler_MissingSource(t *testing.T) {
	mock := &mockIngester{}
	h := NewIngestHandler(mock)

	body := `{"hostname":"web-01"}`
	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewBufferString(body))
	ctx := context.WithValue(req.Context(), middleware.UserContextKeyExported(), &model.UserContext{
		ID: "tok-1", Role: "agent",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Ingest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing source", w.Code)
	}
}

func TestIngestHandler_InvalidJSON(t *testing.T) {
	mock := &mockIngester{}
	h := NewIngestHandler(mock)

	body := `not json at all`
	req := httptest.NewRequest("POST", "/api/v1/ingest", bytes.NewBufferString(body))
	ctx := context.WithValue(req.Context(), middleware.UserContextKeyExported(), &model.UserContext{
		ID: "tok-1", Role: "agent",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Ingest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid JSON", w.Code)
	}
}
