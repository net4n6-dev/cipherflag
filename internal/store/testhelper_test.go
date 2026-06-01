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

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// minCert builds a minimal valid certificate for integration tests that only
// need a row to exist (lookups, private-key-holding, trust-store fixtures).
func minCert(fp string) *model.Certificate {
	return &model.Certificate{
		FingerprintSHA256:  fp,
		Subject:            model.DistinguishedName{CommonName: fp},
		Issuer:             model.DistinguishedName{CommonName: fp},
		SerialNumber:       "serial-" + fp,
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          time.Now(),
		LastSeen:           time.Now(),
	}
}

// testStore creates a PostgresStore connected to the test database, runs
// migrations, and truncates all tables before each test. The CIPHERFLAG_TEST_DB
// environment variable must contain a valid PostgreSQL connection string.
func testStore(t *testing.T) *PostgresStore {
	t.Helper()

	connStr := testdb.Require(t)

	ctx := context.Background()
	st, err := NewPostgresStore(ctx, connStr)
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}

	// Truncate all CE-bound tables in dependency order. EE-only tables
	// (ad_cs_events, rank_review_observations, protocol_endpoints,
	// protocol_observations, teams, external_sources, pcap_jobs,
	// cert_issuance, sweep_watermarks, host_blast_radius,
	// ssh_edge_details, shared_cert_edge_details, app_tag_edge_details,
	// pki_edge_details, host_dependency_edges) are not in the CE
	// baseline and have been removed from this list.
	tables := []string{
		"asset_ownership_sightings",
		"asset_provenance",
		"asset_health_reports",
		"agent_tokens",
		"crypto_configs",
		"crypto_library_cves",
		"crypto_libraries",
		"ssh_keys",
		"host_ip_sightings",
		"operator_declared_cas",
		"application_metadata",
		"host_identifiers",
		"observations",
		"endpoint_profiles",
		"health_reports",
		"ingestion_state",
		"host_trust_store",
		"cert_private_key_holding",
		"certificates",
		"hosts",
		"users",
	}
	for _, table := range tables {
		if _, err := st.pool.Exec(ctx, "TRUNCATE TABLE "+table+" CASCADE"); err != nil {
			// Table may not exist yet in earlier migration states; ignore.
		}
	}

	return st
}

// seedTestHost inserts a host row and returns its UUID.
func seedTestHost(t *testing.T, st *PostgresStore, hostname string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	err := st.pool.QueryRow(ctx,
		`INSERT INTO hosts (canonical_hostname, first_seen, last_seen)
		 VALUES ($1, NOW(), NOW())
		 RETURNING id::text`, hostname).Scan(&id)
	if err != nil {
		t.Fatalf("insert host %q: %v", hostname, err)
	}
	return id
}

// EE-only seed helpers (seedSSHEdge, seedSharedCertEdge, seedAppTagEdge,
// seedHostBlastRadius) were removed during the CE port — the tables they
// insert into (host_dependency_edges, ssh_edge_details,
// shared_cert_edge_details, app_tag_edge_details, host_blast_radius) are
// not part of the CE baseline. They live in EE's Layer 4.4 risk engine
// (SP-1..1.6) and were never wired to any CE test.

// seedTestHostWithAppTags seeds a host and a certificate with the given tags,
// linked via asset_provenance. Returns the host UUID.
func seedTestHostWithAppTags(t *testing.T, st *PostgresStore, hostname string, tags []string) string {
	t.Helper()
	ctx := context.Background()
	hostID := seedTestHost(t, st, hostname)
	fp := fmt.Sprintf("fp-tag-%s", hostname)
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO certificates (fingerprint_sha256, not_before, not_after, application_tags)
		 VALUES ($1, NOW(), NOW() + INTERVAL '30 days', $2)`,
		fp, tags); err != nil {
		t.Fatalf("insert certificates for tag test: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO asset_provenance (asset_type, asset_id, source, host_id, first_seen, last_seen)
		 VALUES ('certificate', $1, 'test', $2, NOW(), NOW())`,
		fp, hostID); err != nil {
		t.Fatalf("insert asset_provenance for tag test: %v", err)
	}
	return hostID
}

// seedUser creates a test user and returns its ID. Many tests need a user
// for foreign key constraints (e.g., agent_tokens.created_by).
func seedUser(t *testing.T, st *PostgresStore) string {
	t.Helper()
	ctx := context.Background()

	var id string
	err := st.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, display_name, role)
		VALUES ('test@example.com', '$2a$10$dummy', 'Test User', 'admin')
		RETURNING id
	`).Scan(&id)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// pkiSeed is the deterministic PKI test scenario used by Tasks 11-15:
//
//	hostA holds CA cert "ca-fp" (self-signed root, is_ca=true, AKI=SKI={0xCA,0xFE})
//	hostB holds leaf cert "leaf-fp" (is_ca=false, AKI={0xCA,0xFE})
//	cert_issuance: leaf-fp→ca-fp via aki_ski_match (attested) — written by
//	              the inline resolver in UpsertCertificate (Task 6).
type pkiSeed struct {
	HostA  uuid.UUID // CA holder
	HostB  uuid.UUID // leaf holder
	CAFP   string
	LeafFP string
}

// seedPKIScenario inserts the pkiSeed scenario into st and returns the
// populated seed struct. The cert_issuance rows are written automatically
// by the UpsertCertificate inline resolver — do not insert them manually.
//
// Callers must not pre-create the hosts or certs; this helper owns those rows.
// The two hosts are inserted with deterministic UUIDs so assertions can
// reference HostA and HostB by value.
func seedPKIScenario(t *testing.T, ctx context.Context, st *PostgresStore) pkiSeed {
	t.Helper()
	s := pkiSeed{
		HostA:  uuid.New(),
		HostB:  uuid.New(),
		CAFP:   "ca-fp",
		LeafFP: "leaf-fp",
	}

	if _, err := st.pool.Exec(ctx,
		`INSERT INTO hosts (id, canonical_hostname) VALUES ($1, 'pki-host-a'), ($2, 'pki-host-b')`,
		s.HostA, s.HostB); err != nil {
		t.Fatalf("seedPKIScenario: insert hosts: %v", err)
	}

	// Self-signed root CA on hostA. AKI=SKI={0xCA,0xFE} — the inline
	// resolver will produce a self_signed cert_issuance row (CA→CA).
	now := time.Now()
	caModel := &model.Certificate{
		FingerprintSHA256:  s.CAFP,
		Subject:            model.DistinguishedName{CommonName: "Test Root CA", Full: "CN=Test Root CA"},
		Issuer:             model.DistinguishedName{CommonName: "Test Root CA", Full: "CN=Test Root CA"},
		SerialNumber:       "serial-ca",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        4096,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now,
		LastSeen:           now,
		IsCA:               true,
		AuthorityKeyID:     []byte{0xCA, 0xFE},
		SubjectKeyID:       []byte{0xCA, 0xFE},
	}
	if err := st.UpsertCertificate(ctx, caModel); err != nil {
		t.Fatalf("seedPKIScenario: UpsertCertificate CA: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `
		INSERT INTO asset_provenance (asset_type, asset_id, source, host_id, first_seen, last_seen)
		VALUES ('certificate', $1, 'test', $2, NOW(), NOW())
	`, s.CAFP, s.HostA); err != nil {
		t.Fatalf("seedPKIScenario: asset_provenance CA→hostA: %v", err)
	}

	// Leaf cert on hostB, signed by the CA. AKI={0xCA,0xFE} matches the CA's
	// SKI, so the inline resolver produces an aki_ski_match cert_issuance row.
	leafModel := &model.Certificate{
		FingerprintSHA256:  s.LeafFP,
		Subject:            model.DistinguishedName{CommonName: "leaf.example.com", Full: "CN=leaf.example.com"},
		Issuer:             model.DistinguishedName{CommonName: "Test Root CA", Full: "CN=Test Root CA"},
		SerialNumber:       "serial-leaf",
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(365 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          now,
		LastSeen:           now,
		IsCA:               false,
		AuthorityKeyID:     []byte{0xCA, 0xFE},
		SubjectKeyID:       []byte{0x1E, 0xAF},
	}
	if err := st.UpsertCertificate(ctx, leafModel); err != nil {
		t.Fatalf("seedPKIScenario: UpsertCertificate leaf: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `
		INSERT INTO asset_provenance (asset_type, asset_id, source, host_id, first_seen, last_seen)
		VALUES ('certificate', $1, 'test', $2, NOW(), NOW())
	`, s.LeafFP, s.HostB); err != nil {
		t.Fatalf("seedPKIScenario: asset_provenance leaf→hostB: %v", err)
	}

	return s
}
