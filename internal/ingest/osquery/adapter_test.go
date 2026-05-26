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

package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
)

// ---------------------------------------------------------------------------
// Mock ingester
// ---------------------------------------------------------------------------

type mockIngester struct {
	results []*ingest.DiscoveryResult
	err     error
}

func (m *mockIngester) Ingest(_ context.Context, result *ingest.DiscoveryResult) (*ingest.IngestionSummary, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.results = append(m.results, result)
	return &ingest.IngestionSummary{HostID: "host-1"}, nil
}

func (m *mockIngester) AttributeAssets(_ context.Context, claims []ingest.OwnershipClaim) (emitted, skipped int, err error) {
	return len(claims), 0, nil
}

// ---------------------------------------------------------------------------
// Helper: POST fixture file to the handler
// ---------------------------------------------------------------------------

func postFixture(t *testing.T, ing ingest.Ingester, fixture string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := os.ReadFile("testdata/" + fixture)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook/osquery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	NewAdapter(ing).HandleWebhook(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestHandleWebhook_Certificates(t *testing.T) {
	mock := &mockIngester{}
	rr := postFixture(t, mock, "fleet_certificates.json")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(mock.results) != 1 {
		t.Fatalf("expected 1 ingest call, got %d", len(mock.results))
	}

	res := mock.results[0]
	if res.Source != "osquery" {
		t.Errorf("expected source=osquery, got %q", res.Source)
	}
	if res.SourceHostID != "E4F7D2A1-B3C8-4E5F-9A6D-1234567890AB" {
		t.Errorf("unexpected SourceHostID: %q", res.SourceHostID)
	}
	if res.Hostname != "web-01.prod.internal" {
		t.Errorf("unexpected Hostname: %q", res.Hostname)
	}
	if res.OSFamily != "linux" {
		t.Errorf("expected OSFamily=linux, got %q", res.OSFamily)
	}
	if len(res.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(res.Certificates))
	}

	// First cert: *.example.com
	c0 := res.Certificates[0]
	if c0.FingerprintSHA256 != "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" {
		t.Errorf("unexpected fingerprint for cert[0]: %q", c0.FingerprintSHA256)
	}
	if c0.SubjectCN != "*.example.com" {
		t.Errorf("unexpected SubjectCN for cert[0]: %q", c0.SubjectCN)
	}
	if c0.StoreType != "os_store" {
		t.Errorf("expected StoreType=os_store, got %q", c0.StoreType)
	}
	if c0.KeyAlgorithm != "RSA" {
		t.Errorf("unexpected KeyAlgorithm: %q", c0.KeyAlgorithm)
	}

	// Second cert: internal-ca.corp
	c1 := res.Certificates[1]
	if c1.FingerprintSHA256 != "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3" {
		t.Errorf("unexpected fingerprint for cert[1]: %q", c1.FingerprintSHA256)
	}
}

func TestHandleWebhook_SSHKeys(t *testing.T) {
	mock := &mockIngester{}
	rr := postFixture(t, mock, "fleet_ssh_user_keys.json")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(mock.results) != 1 {
		t.Fatalf("expected 1 ingest call, got %d", len(mock.results))
	}

	res := mock.results[0]
	if len(res.SSHKeys) != 2 {
		t.Fatalf("expected 2 SSH keys, got %d", len(res.SSHKeys))
	}

	// First key: rsa, not encrypted
	k0 := res.SSHKeys[0]
	if k0.KeyType != "rsa" {
		t.Errorf("expected KeyType=rsa, got %q", k0.KeyType)
	}
	if k0.IsProtected {
		t.Errorf("expected IsProtected=false for key[0]")
	}
	if k0.IsAuthorized {
		t.Errorf("expected IsAuthorized=false for SSH user key")
	}
	if k0.FilePath != "/home/admin/.ssh/id_rsa" {
		t.Errorf("unexpected FilePath: %q", k0.FilePath)
	}

	// Second key: ed25519, encrypted
	k1 := res.SSHKeys[1]
	if k1.KeyType != "ed25519" {
		t.Errorf("expected KeyType=ed25519, got %q", k1.KeyType)
	}
	if !k1.IsProtected {
		t.Errorf("expected IsProtected=true for key[1]")
	}
}

func TestHandleWebhook_AuthorizedKeys(t *testing.T) {
	mock := &mockIngester{}
	rr := postFixture(t, mock, "fleet_authorized_keys.json")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(mock.results) != 1 {
		t.Fatalf("expected 1 ingest call, got %d", len(mock.results))
	}

	res := mock.results[0]
	if len(res.SSHKeys) != 2 {
		t.Fatalf("expected 2 authorized keys, got %d", len(res.SSHKeys))
	}

	// Both keys must be marked IsAuthorized
	for i, k := range res.SSHKeys {
		if !k.IsAuthorized {
			t.Errorf("key[%d]: expected IsAuthorized=true", i)
		}
	}

	// uid=0 → GrantsRoot
	k0 := res.SSHKeys[0]
	if !k0.GrantsRoot {
		t.Errorf("expected GrantsRoot=true for uid=0 key")
	}
	if k0.KeyType != "rsa" {
		t.Errorf("expected KeyType=rsa, got %q", k0.KeyType)
	}

	// uid=1000 → no GrantsRoot
	k1 := res.SSHKeys[1]
	if k1.GrantsRoot {
		t.Errorf("expected GrantsRoot=false for uid=1000 key")
	}
	if k1.KeyType != "ed25519" {
		t.Errorf("expected KeyType=ed25519, got %q", k1.KeyType)
	}
}

func TestHandleWebhook_CryptoPackagesDeb(t *testing.T) {
	mock := &mockIngester{}
	rr := postFixture(t, mock, "fleet_crypto_packages_deb.json")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(mock.results) != 1 {
		t.Fatalf("expected 1 ingest call, got %d", len(mock.results))
	}

	res := mock.results[0]
	if len(res.Libraries) != 2 {
		t.Fatalf("expected 2 libraries, got %d", len(res.Libraries))
	}

	// libssl3 → openssl
	l0 := res.Libraries[0]
	if l0.LibraryName != "openssl" {
		t.Errorf("expected LibraryName=openssl, got %q", l0.LibraryName)
	}
	if l0.PackageName != "libssl3" {
		t.Errorf("expected PackageName=libssl3, got %q", l0.PackageName)
	}
	if l0.PackageManager != "dpkg" {
		t.Errorf("expected PackageManager=dpkg, got %q", l0.PackageManager)
	}
	if l0.Version != "3.0.14-1ubuntu1" {
		t.Errorf("unexpected Version: %q", l0.Version)
	}

	// libgnutls30 → gnutls
	l1 := res.Libraries[1]
	if l1.LibraryName != "gnutls" {
		t.Errorf("expected LibraryName=gnutls, got %q", l1.LibraryName)
	}
	if l1.PackageManager != "dpkg" {
		t.Errorf("expected PackageManager=dpkg, got %q", l1.PackageManager)
	}
}

func TestHandleWebhook_CryptoPackagesRpm(t *testing.T) {
	mock := &mockIngester{}
	rr := postFixture(t, mock, "fleet_crypto_packages_rpm.json")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(mock.results) != 1 {
		t.Fatalf("expected 1 ingest call, got %d", len(mock.results))
	}

	res := mock.results[0]
	// Different host from the deb fixture
	if res.SourceHostID != "F5A8B3C2-D4E6-7F89-0A1B-CDEF23456789" {
		t.Errorf("unexpected SourceHostID: %q", res.SourceHostID)
	}
	if res.OSFamily != "linux" {
		t.Errorf("expected OSFamily=linux (centos normalized), got %q", res.OSFamily)
	}
	if len(res.Libraries) != 2 {
		t.Fatalf("expected 2 libraries, got %d", len(res.Libraries))
	}

	// openssl-libs → openssl
	l0 := res.Libraries[0]
	if l0.LibraryName != "openssl" {
		t.Errorf("expected LibraryName=openssl, got %q", l0.LibraryName)
	}
	if l0.PackageManager != "rpm" {
		t.Errorf("expected PackageManager=rpm, got %q", l0.PackageManager)
	}

	// nss → nss
	l1 := res.Libraries[1]
	if l1.LibraryName != "nss" {
		t.Errorf("expected LibraryName=nss, got %q", l1.LibraryName)
	}
	if l1.PackageManager != "rpm" {
		t.Errorf("expected PackageManager=rpm, got %q", l1.PackageManager)
	}
}

func TestHandleWebhook_InvalidJSON(t *testing.T) {
	mock := &mockIngester{}
	req := httptest.NewRequest(http.MethodPost, "/webhook/osquery", bytes.NewBufferString("{not valid json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	NewAdapter(mock).HandleWebhook(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	if len(mock.results) != 0 {
		t.Errorf("expected 0 ingest calls for invalid JSON, got %d", len(mock.results))
	}
}

func TestHandleWebhook_EmptyArray(t *testing.T) {
	mock := &mockIngester{}
	req := httptest.NewRequest(http.MethodPost, "/webhook/osquery", bytes.NewBufferString("[]"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	NewAdapter(mock).HandleWebhook(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp webhookResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Processed != 0 {
		t.Errorf("expected processed=0, got %d", resp.Processed)
	}
}

func TestHandleWebhook_UnknownQueryName(t *testing.T) {
	mock := &mockIngester{}
	body := `[{"host_identifier":"h1","hostname":"h1","platform":"linux","name":"unknown_query","action":"snapshot","snapshot":[{"foo":"bar"}]}]`
	req := httptest.NewRequest(http.MethodPost, "/webhook/osquery", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	NewAdapter(mock).HandleWebhook(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for unknown query, got %d", rr.Code)
	}
	if len(mock.results) != 0 {
		t.Errorf("expected 0 ingest calls for unknown query name, got %d", len(mock.results))
	}
}

func TestHandleWebhook_EmptySnapshot(t *testing.T) {
	mock := &mockIngester{}
	body := `[{"host_identifier":"h1","hostname":"h1","platform":"ubuntu","name":"cipherflag_certificates","action":"snapshot","snapshot":[]}]`
	req := httptest.NewRequest(http.MethodPost, "/webhook/osquery", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	NewAdapter(mock).HandleWebhook(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if len(mock.results) != 0 {
		t.Errorf("expected 0 ingest calls for empty snapshot, got %d", len(mock.results))
	}
}

func TestTeamFromEntry_Populated(t *testing.T) {
	entry := fleetWebhookEntry{Team: "Payments Team", TeamID: 3}
	if got := teamFromEntry(entry); got != "Payments Team" {
		t.Errorf("teamFromEntry = %q, want %q", got, "Payments Team")
	}
}

func TestTeamFromEntry_Empty(t *testing.T) {
	entry := fleetWebhookEntry{}
	if got := teamFromEntry(entry); got != "" {
		t.Errorf("teamFromEntry = %q, want empty", got)
	}
}

func TestTeamFromEntry_DefaultBuckets(t *testing.T) {
	for _, name := range []string{"No team", "no team", "NO TEAM", "   ", ""} {
		t.Run(name, func(t *testing.T) {
			entry := fleetWebhookEntry{Team: name}
			if got := teamFromEntry(entry); got != "" {
				t.Errorf("teamFromEntry(%q) = %q, want empty", name, got)
			}
		})
	}
}
