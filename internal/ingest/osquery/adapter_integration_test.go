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

package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// ---------------------------------------------------------------------------
// Test helper
// ---------------------------------------------------------------------------

// integrationSetup connects to the test DB, runs migrations, truncates all
// tables, and returns a store + ingester ready for use.
// The test is skipped if CIPHERFLAG_TEST_DB is not set.
func integrationSetup(t *testing.T) (*store.PostgresStore, *ingest.UnifiedIngester) {
	t.Helper()

	connStr := testdb.Require(t)

	ctx := context.Background()

	st, err := store.NewPostgresStore(ctx, connStr)
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}

	tables := []string{
		"asset_ownership_sightings",
		"asset_provenance",
		"asset_health_reports",
		"agent_tokens",
		"protocol_observations",
		"crypto_configs",
		"crypto_libraries",
		"ssh_keys",
		"host_identifiers",
		"observations",
		"endpoint_profiles",
		"health_reports",
		"ingestion_state",
		"pcap_jobs",
		"certificates",
		"hosts",
		"users",
	}
	pool := st.Pool()
	for _, table := range tables {
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+table+" CASCADE"); err != nil {
			// Table may not exist yet in earlier migration states; ignore.
			_ = err
		}
	}

	ingester := ingest.NewUnifiedIngester(st)
	return st, ingester
}

// postFixtureIntegration POSTs a fixture file through the real adapter.
func postFixtureIntegration(t *testing.T, ing ingest.Ingester, fixture string) *httptest.ResponseRecorder {
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
// TestIntegration_FullIngestCycle
// ---------------------------------------------------------------------------

func TestIntegration_FullIngestCycle(t *testing.T) {
	st, ingester := integrationSetup(t)
	ctx := context.Background()

	// POST certificates fixture
	rr := postFixtureIntegration(t, ingester, "fleet_certificates.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("certificates webhook: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// POST SSH user keys fixture
	rr = postFixtureIntegration(t, ingester, "fleet_ssh_user_keys.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("ssh_user_keys webhook: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// POST crypto packages deb fixture
	rr = postFixtureIntegration(t, ingester, "fleet_crypto_packages_deb.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("crypto_packages_deb webhook: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// 1. Verify exactly 1 host with correct attributes.
	hostResult, err := st.ListHosts(ctx, store.HostSearchQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if len(hostResult.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hostResult.Hosts))
	}
	host := hostResult.Hosts[0]
	if host.CanonicalHostname != "web-01.prod.internal" {
		t.Errorf("expected hostname=web-01.prod.internal, got %q", host.CanonicalHostname)
	}
	if host.OSFamily != "linux" {
		t.Errorf("expected os_family=linux, got %q", host.OSFamily)
	}

	// 2. Host is findable by osquery source ID.
	foundHost, err := st.FindHostBySourceID(ctx, "osquery", "E4F7D2A1-B3C8-4E5F-9A6D-1234567890AB")
	if err != nil {
		t.Fatalf("find host by source id: %v", err)
	}
	if foundHost == nil {
		t.Fatal("host not found by osquery source ID")
	}
	if foundHost.ID != host.ID {
		t.Errorf("source-ID lookup returned wrong host: got %q, want %q", foundHost.ID, host.ID)
	}

	// 3. Certificates exist in the DB.
	certResult, err := st.SearchCertificates(ctx, store.CertSearchQuery{PageSize: 10})
	if err != nil {
		t.Fatalf("search certificates: %v", err)
	}
	if len(certResult.Certificates) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(certResult.Certificates))
	}

	// 4. SSH keys exist for the host.
	keyResult, err := st.ListSSHKeys(ctx, store.SSHKeySearchQuery{HostID: host.ID, Limit: 10})
	if err != nil {
		t.Fatalf("list ssh keys: %v", err)
	}
	if len(keyResult.Keys) != 2 {
		t.Errorf("expected 2 SSH keys for host, got %d", len(keyResult.Keys))
	}

	// 5. Libraries exist for the host.
	libResult, err := st.ListCryptoLibraries(ctx, store.LibrarySearchQuery{HostID: host.ID, Limit: 10})
	if err != nil {
		t.Fatalf("list crypto libraries: %v", err)
	}
	if len(libResult.Libraries) != 2 {
		t.Errorf("expected 2 libraries for host, got %d", len(libResult.Libraries))
	}

	// 6. Provenance records exist with source="osquery".
	// Check provenance for the first certificate.
	firstFP := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	provRecords, err := st.GetProvenance(ctx, "certificate", firstFP)
	if err != nil {
		t.Fatalf("get provenance for cert: %v", err)
	}
	if len(provRecords) == 0 {
		t.Fatal("expected provenance records for certificate, got none")
	}
	var foundOsquery bool
	for _, p := range provRecords {
		if p.Source == "osquery" {
			foundOsquery = true
			break
		}
	}
	if !foundOsquery {
		t.Error("expected provenance record with source=osquery for certificate")
	}
}

// ---------------------------------------------------------------------------
// TestIntegration_CrossSourceDedup
// ---------------------------------------------------------------------------

func TestIntegration_CrossSourceDedup(t *testing.T) {
	st, ingester := integrationSetup(t)
	ctx := context.Background()

	// The fingerprint from the fleet_certificates.json fixture.
	const certFP = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

	// Step 1: Ingest the cert directly via zeek_passive source.
	zeekResult := &ingest.DiscoveryResult{
		Source:       "zeek_passive",
		SourceHostID: "zeek-sensor-01",
		Hostname:     "zeek-sensor-01.internal",
		OSFamily:     "linux",
		Timestamp:    time.Now().UTC(),
		Certificates: []dedup.CertDiscovery{
			{
				FingerprintSHA256:  certFP,
				SubjectCN:          "*.example.com",
				IssuerCN:           "CN=DigiCert SHA2 Extended Validation Server CA,O=DigiCert Inc",
				NotBefore:          time.Unix(1704067200, 0).UTC(),
				NotAfter:           time.Unix(1798761600, 0).UTC(),
				KeyAlgorithm:       "RSA",
				KeySizeBits:        2048,
				SignatureAlgorithm: "sha256WithRSAEncryption",
				Source:             "zeek_passive",
			},
		},
	}
	if _, err := ingester.Ingest(ctx, zeekResult); err != nil {
		t.Fatalf("zeek ingest: %v", err)
	}

	// Step 2: POST the same cert via osquery webhook.
	rr := postFixtureIntegration(t, ingester, "fleet_certificates.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("osquery webhook: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify: still only 1 certificate row (deduped by fingerprint).
	certResult, err := st.SearchCertificates(ctx, store.CertSearchQuery{PageSize: 10})
	if err != nil {
		t.Fatalf("search certificates: %v", err)
	}
	// The osquery fixture has 2 certs, but certFP is the same as zeek — so still 2 total.
	if len(certResult.Certificates) != 2 {
		t.Errorf("expected 2 total certificates (1 deduped + 1 new), got %d", len(certResult.Certificates))
	}

	// Verify: 2 provenance records for the shared cert (one per source).
	provRecords, err := st.GetProvenance(ctx, "certificate", certFP)
	if err != nil {
		t.Fatalf("get provenance: %v", err)
	}
	if len(provRecords) != 2 {
		t.Errorf("expected 2 provenance records for deduped cert, got %d", len(provRecords))
	}
	sources := make(map[string]bool)
	for _, p := range provRecords {
		sources[p.Source] = true
	}
	if !sources["zeek_passive"] {
		t.Error("expected provenance record with source=zeek_passive")
	}
	if !sources["osquery"] {
		t.Error("expected provenance record with source=osquery")
	}
}

// ---------------------------------------------------------------------------
// TestIntegration_IdempotentReIngest
// ---------------------------------------------------------------------------

func TestIntegration_IdempotentReIngest(t *testing.T) {
	st, ingester := integrationSetup(t)
	ctx := context.Background()

	// POST the certificates fixture twice.
	for i := 0; i < 2; i++ {
		rr := postFixtureIntegration(t, ingester, "fleet_certificates.json")
		if rr.Code != http.StatusOK {
			t.Fatalf("pass %d: expected 200, got %d: %s", i+1, rr.Code, rr.Body.String())
		}
	}

	// Verify: still 1 host.
	hostResult, err := st.ListHosts(ctx, store.HostSearchQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if len(hostResult.Hosts) != 1 {
		t.Errorf("expected 1 host after re-ingest, got %d", len(hostResult.Hosts))
	}

	// Verify: 1 provenance record per cert (not duplicated).
	firstFP := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	secondFP := "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"

	for _, fp := range []string{firstFP, secondFP} {
		provRecords, err := st.GetProvenance(ctx, "certificate", fp)
		if err != nil {
			t.Fatalf("get provenance for %s: %v", fp, err)
		}
		if len(provRecords) != 1 {
			t.Errorf("cert %s: expected 1 provenance record after re-ingest, got %d", fp, len(provRecords))
		}
	}
}

// ---------------------------------------------------------------------------
// TestWebhook_EmitsOwnershipSightings
// ---------------------------------------------------------------------------

func TestWebhook_EmitsOwnershipSightings(t *testing.T) {
	st, ingester := integrationSetup(t)
	ctx := context.Background()

	adapter := NewAdapter(ingester)
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/osquery", adapter.HandleWebhook)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, err := os.ReadFile("testdata/fleet_certificates_with_team.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	resp, err := http.Post(srv.URL+"/webhook/osquery", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var wr webhookResponse
	if err := json.NewDecoder(resp.Body).Decode(&wr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if wr.OwnershipSightingsEmitted == 0 {
		t.Fatalf("response OwnershipSightingsEmitted = 0, want > 0: %+v", wr)
	}

	// Count asset_ownership_sightings rows with source=sighting_agent,
	// confidence=inferred, team=payments-team.
	var sightingCount int
	if err := st.Pool().QueryRow(ctx, `
		SELECT count(*) FROM asset_ownership_sightings
		WHERE source = 'sighting_agent'
		  AND confidence = 'inferred'
		  AND team = 'payments-team'
	`).Scan(&sightingCount); err != nil {
		t.Fatalf("count sightings: %v", err)
	}
	if sightingCount == 0 {
		t.Errorf("no sighting_agent sightings written; expected >0 for the fleet_certificates_with_team fixture")
	}
	if sightingCount != wr.OwnershipSightingsEmitted {
		t.Errorf("DB count (%d) != response counter (%d)", sightingCount, wr.OwnershipSightingsEmitted)
	}

	// Evidence check — at least one sighting must carry the canonical
	// raw_team_name (value "Payments Team") plus the FleetDM-specific
	// fleet_team_id. See OwnershipClaim.Evidence convention in
	// internal/ingest/ownership.go.
	var evidenceJSON string
	if err := st.Pool().QueryRow(ctx, `
		SELECT evidence::text FROM asset_ownership_sightings
		WHERE source = 'sighting_agent' LIMIT 1
	`).Scan(&evidenceJSON); err != nil {
		t.Fatalf("fetch evidence: %v", err)
	}
	if !strings.Contains(evidenceJSON, `"raw_team_name"`) || !strings.Contains(evidenceJSON, "Payments Team") {
		t.Errorf("evidence JSON missing raw_team_name=\"Payments Team\": %s", evidenceJSON)
	}
	if !strings.Contains(evidenceJSON, `"fleet_team_id": 3`) && !strings.Contains(evidenceJSON, `"fleet_team_id":3`) {
		t.Errorf("evidence JSON missing fleet_team_id=3: %s", evidenceJSON)
	}
}

// ---------------------------------------------------------------------------
// TestWebhook_NoTeamProducesNoSightings
// ---------------------------------------------------------------------------

func TestWebhook_NoTeamProducesNoSightings(t *testing.T) {
	st, ingester := integrationSetup(t)
	ctx := context.Background()

	adapter := NewAdapter(ingester)
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/osquery", adapter.HandleWebhook)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Original fixture has no `team` field — must produce zero sightings.
	body, err := os.ReadFile("testdata/fleet_certificates.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	resp, err := http.Post(srv.URL+"/webhook/osquery", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	var wr webhookResponse
	if err := json.NewDecoder(resp.Body).Decode(&wr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if wr.OwnershipSightingsEmitted != 0 {
		t.Errorf("response OwnershipSightingsEmitted = %d, want 0 (no team field in fixture)", wr.OwnershipSightingsEmitted)
	}

	var sightingCount int
	if err := st.Pool().QueryRow(ctx, `
		SELECT count(*) FROM asset_ownership_sightings WHERE source = 'sighting_agent'
	`).Scan(&sightingCount); err != nil {
		t.Fatalf("count sightings: %v", err)
	}
	if sightingCount != 0 {
		t.Errorf("sighting_agent sighting count = %d, want 0", sightingCount)
	}
}
