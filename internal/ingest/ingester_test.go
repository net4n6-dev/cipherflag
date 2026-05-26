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

package ingest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// Use a mock store that satisfies store.CryptoStore minimally.
// For this test, the mock just tracks calls without real DB.
type ingestMockStore struct {
	store.CryptoStore
	provenanceCount  int
	provenanceCalls  []*model.AssetProvenance
	hostCreated      bool
	host             *model.Host
	sightingCalls    []*store.HostIPSighting
	sightingErr      error
}

func (m *ingestMockStore) FindHostBySourceID(ctx context.Context, source, sourceHostID string) (*model.Host, error) {
	return nil, nil
}
func (m *ingestMockStore) FindHostByIP(ctx context.Context, ip string) (*model.Host, error) {
	return nil, nil
}
func (m *ingestMockStore) FindHostByHostname(ctx context.Context, hostname string) (*model.Host, error) {
	return nil, nil
}
func (m *ingestMockStore) UpsertHost(ctx context.Context, host *model.Host) error {
	if host.ID == "" {
		host.ID = "mock-host-1"
		host.FirstSeen = time.Now()
		host.LastSeen = time.Now()
	}
	m.hostCreated = true
	return nil
}
func (m *ingestMockStore) UpsertHostIdentifier(ctx context.Context, ident *model.HostIdentifier) error {
	return nil
}
func (m *ingestMockStore) GetHost(ctx context.Context, id string) (*model.Host, error) {
	if m.host != nil && m.host.ID == id {
		return m.host, nil
	}
	return nil, nil
}
func (m *ingestMockStore) GetCertificate(ctx context.Context, fp string) (*model.Certificate, error) {
	return nil, nil
}
func (m *ingestMockStore) UpsertCertificate(ctx context.Context, cert *model.Certificate) error {
	return nil
}
func (m *ingestMockStore) UpsertSSHKey(ctx context.Context, key *model.SSHKey) error {
	key.ID = "mock-key-1"
	key.FirstSeen = time.Now()
	key.LastSeen = key.FirstSeen
	return nil
}
func (m *ingestMockStore) UpsertCryptoLibrary(ctx context.Context, lib *model.CryptoLibrary) error {
	lib.ID = "mock-lib-1"
	lib.FirstSeen = time.Now()
	lib.LastSeen = lib.FirstSeen
	return nil
}
func (m *ingestMockStore) UpsertCryptoConfig(ctx context.Context, cfg *model.CryptoConfig) error {
	cfg.ID = "mock-cfg-1"
	cfg.FirstSeen = time.Now()
	cfg.LastSeen = cfg.FirstSeen
	return nil
}
// CE-flavor: RecordProtocolObservation + UpsertProtocolEndpoint mocks
// removed — those methods are EE-only (Layer 4.1c).
func (m *ingestMockStore) RecordProvenance(ctx context.Context, prov *model.AssetProvenance) error {
	m.provenanceCount++
	// Copy so later mutation by the caller doesn't alter the recorded state.
	cp := *prov
	m.provenanceCalls = append(m.provenanceCalls, &cp)
	return nil
}
func (m *ingestMockStore) UpsertHostIPSighting(ctx context.Context, s *store.HostIPSighting) error {
	if m.sightingErr != nil {
		return m.sightingErr
	}
	// Copy so later mutation by the caller doesn't alter the recorded state.
	cp := *s
	m.sightingCalls = append(m.sightingCalls, &cp)
	return nil
}

func TestUnifiedIngester_MixedAssets(t *testing.T) {
	st := &ingestMockStore{}
	ingester := NewUnifiedIngester(st)
	ctx := context.Background()

	result := &DiscoveryResult{
		Source:       "osquery",
		SourceHostID: "osq-host-1",
		Hostname:     "web-01.prod",
		IPAddresses:  []string{"10.0.1.5"},
		Timestamp:    time.Now(),
		Certificates: []dedup.CertDiscovery{
			{FingerprintSHA256: "abc123", SubjectCN: "test.com", KeyAlgorithm: "RSA", KeySizeBits: 2048},
		},
		SSHKeys: []dedup.SSHKeyDiscovery{
			{KeyType: "ssh-ed25519", FingerprintSHA256: "key123", KeySizeBits: 256},
		},
		Libraries: []dedup.LibraryDiscovery{
			{LibraryName: "openssl", Version: "3.0.12"},
		},
		Protocols: []dedup.ProtocolDiscovery{
			{ServerIP: "10.0.1.5", ServerPort: 443, Protocol: "TLS", Algorithms: map[string]string{}, ObservedAt: time.Now()},
		},
		Configs: []dedup.ConfigDiscovery{
			{ConfigType: "sshd_config", FilePath: "/etc/ssh/sshd_config", Settings: map[string]string{}},
		},
	}

	summary, err := ingester.Ingest(ctx, result)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if !st.hostCreated {
		t.Error("expected host to be created")
	}
	if summary.CertificatesNew+summary.CertificatesUpdated != 1 {
		t.Errorf("expected 1 certificate, got new=%d updated=%d", summary.CertificatesNew, summary.CertificatesUpdated)
	}
	if summary.SSHKeysNew+summary.SSHKeysUpdated != 1 {
		t.Errorf("expected 1 SSH key, got new=%d updated=%d", summary.SSHKeysNew, summary.SSHKeysUpdated)
	}
	if summary.LibrariesNew+summary.LibrariesUpdated != 1 {
		t.Errorf("expected 1 library, got new=%d updated=%d", summary.LibrariesNew, summary.LibrariesUpdated)
	}
	// CE-flavor: protocol observations are silently dropped — the
	// crypto_protocol asset path is EE-only (Layer 4.1c). Expect 0.
	if summary.ProtocolObservations != 0 {
		t.Errorf("CE expects 0 protocol observations, got %d", summary.ProtocolObservations)
	}
	if summary.ConfigsNew+summary.ConfigsUpdated != 1 {
		t.Errorf("expected 1 config, got new=%d updated=%d", summary.ConfigsNew, summary.ConfigsUpdated)
	}
	// Provenance: 1 cert + 1 key + 1 lib + 1 config = 4 (protocols don't record provenance)
	if st.provenanceCount != 4 {
		t.Errorf("provenance count = %d, want 4", st.provenanceCount)
	}
}

func TestUnifiedIngester_EmptyResult(t *testing.T) {
	st := &ingestMockStore{}
	ingester := NewUnifiedIngester(st)
	ctx := context.Background()

	result := &DiscoveryResult{
		Source:    "osquery",
		Hostname:  "empty-host",
		Timestamp: time.Now(),
	}

	summary, err := ingester.Ingest(ctx, result)
	if err != nil {
		t.Fatalf("Ingest empty: %v", err)
	}
	if summary.CertificatesNew != 0 || summary.SSHKeysNew != 0 {
		t.Error("empty result should produce zero counts")
	}
}

// CE-flavor: TestClassifyProtocolObservation_* removed — they covered
// the Layer 4.1c protocol-endpoint classifier which is EE-only.

func TestIngest_SkipHostResolution_Hostless(t *testing.T) {
	// Hostless import: SkipHostResolution=true with empty SourceHostID.
	// Certs should ingest; SSH keys / libs / configs should be skipped.
	fs := &ingestMockStore{}
	ingester := NewUnifiedIngester(fs)

	result := &DiscoveryResult{
		Source:             "cbom_import",
		SkipHostResolution: true,
		Certificates: []dedup.CertDiscovery{
			{FingerprintSHA256: "aaa", SubjectCN: "cert1.test", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)},
		},
		SSHKeys: []dedup.SSHKeyDiscovery{
			{FingerprintSHA256: "bbb", KeyType: "ssh-ed25519", KeySizeBits: 256},
		},
		Libraries: []dedup.LibraryDiscovery{
			{LibraryName: "openssl", Version: "3.0.14"},
		},
	}

	summary, err := ingester.Ingest(context.Background(), result)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if summary.HostID != "" {
		t.Errorf("HostID = %q, want empty (hostless import)", summary.HostID)
	}
	if summary.CertificatesNew != 1 {
		t.Errorf("CertificatesNew = %d, want 1", summary.CertificatesNew)
	}
	if summary.SSHKeysNew != 0 || summary.LibrariesNew != 0 {
		t.Errorf("SSH/Library counts should be 0 in hostless mode (got SSH=%d, Lib=%d)",
			summary.SSHKeysNew, summary.LibrariesNew)
	}
}

func TestIngest_SkipHostResolution_HostTargeted(t *testing.T) {
	// Targeted import: SkipHostResolution=true + SourceHostID set.
	// Host looked up directly via GetHost; all asset types ingest.
	targetHostID := "aaaaaaaa-0000-0000-0000-000000000001"
	fs := &ingestMockStore{
		host: &model.Host{ID: targetHostID, CanonicalHostname: "target"},
	}
	ingester := NewUnifiedIngester(fs)

	result := &DiscoveryResult{
		Source:             "cbom_import",
		SourceHostID:       targetHostID,
		SkipHostResolution: true,
		Certificates: []dedup.CertDiscovery{
			{FingerprintSHA256: "aaa", SubjectCN: "cert1.test", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)},
		},
		SSHKeys: []dedup.SSHKeyDiscovery{
			{FingerprintSHA256: "bbb", KeyType: "ssh-ed25519", KeySizeBits: 256},
		},
	}

	summary, err := ingester.Ingest(context.Background(), result)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if summary.HostID != targetHostID {
		t.Errorf("HostID = %q, want %q", summary.HostID, targetHostID)
	}
	if summary.CertificatesNew != 1 || summary.SSHKeysNew != 1 {
		t.Errorf("expected 1 cert + 1 ssh key; got cert=%d ssh=%d",
			summary.CertificatesNew, summary.SSHKeysNew)
	}
}

func TestIngest_SkipHostResolution_HostNotFound(t *testing.T) {
	fs := &ingestMockStore{host: nil}
	ingester := NewUnifiedIngester(fs)

	result := &DiscoveryResult{
		Source:             "cbom_import",
		SourceHostID:       "nonexistent",
		SkipHostResolution: true,
	}

	_, err := ingester.Ingest(context.Background(), result)
	if err == nil {
		t.Fatal("expected error for host not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want 'not found'", err)
	}
}

// ── v1.5.0 endpoint sighting dual-write ───────────────────────────────

// TestUnifiedIngester_WritesEndpointSightingPerHostIP confirms that
// when an ingest cycle resolves a host with IPs, one direct-tier
// sighting is upserted per IP — not per asset. Cycle above has five
// asset types but we expect one sighting per host IP, independent of
// the asset count.
func TestUnifiedIngester_WritesEndpointSightingPerHostIP(t *testing.T) {
	st := &ingestMockStore{}
	ingester := NewUnifiedIngester(st)
	ctx := context.Background()

	ts := time.Now()
	result := &DiscoveryResult{
		Source:       "osquery",
		SourceHostID: "osq-host-1",
		Hostname:     "web-01.prod",
		IPAddresses:  []string{"10.0.1.5", "10.0.1.6"},
		Timestamp:    ts,
		Certificates: []dedup.CertDiscovery{
			{FingerprintSHA256: "abc123", SubjectCN: "test.com", KeyAlgorithm: "RSA", KeySizeBits: 2048},
		},
		SSHKeys: []dedup.SSHKeyDiscovery{
			{KeyType: "ssh-ed25519", FingerprintSHA256: "key123", KeySizeBits: 256},
		},
	}
	if _, err := ingester.Ingest(ctx, result); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if len(st.sightingCalls) != 2 {
		t.Fatalf("sighting calls = %d, want 2 (one per host IP, independent of asset count)", len(st.sightingCalls))
	}
	seen := map[string]bool{}
	for _, s := range st.sightingCalls {
		if s.Source != "endpoint" || s.Confidence != "direct" {
			t.Errorf("tier = %s/%s, want endpoint/direct", s.Source, s.Confidence)
		}
		if s.HostID == "" {
			t.Errorf("host_id empty on sighting %+v", s)
		}
		if !s.FirstSeen.Equal(ts) {
			t.Errorf("first_seen = %v, want %v (from DiscoveryResult.Timestamp)", s.FirstSeen, ts)
		}
		if s.LastSeen.Before(s.FirstSeen) {
			t.Errorf("last_seen %v < first_seen %v", s.LastSeen, s.FirstSeen)
		}
		if s.Attribution["source_adapter"] != "osquery" {
			t.Errorf("attribution.source_adapter = %v, want osquery", s.Attribution["source_adapter"])
		}
		seen[s.IP] = true
	}
	if !seen["10.0.1.5"] || !seen["10.0.1.6"] {
		t.Errorf("expected sightings for both IPs; got %v", seen)
	}
}

// TestUnifiedIngester_NoSightingWhenHostless confirms the cross-host
// cert dedup path (host=nil) does NOT write sightings. Without a
// resolved host there's nothing to attribute.
func TestUnifiedIngester_NoSightingWhenHostless(t *testing.T) {
	st := &ingestMockStore{}
	ingester := NewUnifiedIngester(st)
	ctx := context.Background()

	// SkipHostResolution=true + SourceHostID empty → host stays nil.
	result := &DiscoveryResult{
		Source:             "cbom_import",
		SkipHostResolution: true,
		Timestamp:          time.Now(),
		Certificates: []dedup.CertDiscovery{
			{FingerprintSHA256: "hostless-abc", SubjectCN: "x", KeyAlgorithm: "RSA", KeySizeBits: 2048},
		},
	}
	if _, err := ingester.Ingest(ctx, result); err != nil {
		t.Fatalf("Ingest hostless: %v", err)
	}
	if len(st.sightingCalls) != 0 {
		t.Errorf("sighting calls = %d, want 0 for hostless ingest", len(st.sightingCalls))
	}
	if st.provenanceCount != 1 {
		t.Errorf("provenance count = %d, want 1 (cert still recorded)", st.provenanceCount)
	}
}

// TestUnifiedIngester_NoSightingWhenHostHasNoIPs confirms that a
// resolved-but-IP-less host produces no sightings but the primary
// ingest path completes.
func TestUnifiedIngester_NoSightingWhenHostHasNoIPs(t *testing.T) {
	st := &ingestMockStore{}
	ingester := NewUnifiedIngester(st)
	ctx := context.Background()

	result := &DiscoveryResult{
		Source:       "osquery",
		SourceHostID: "osq-host-1",
		Hostname:     "noip-host",
		IPAddresses:  nil, // explicitly none
		Timestamp:    time.Now(),
		Certificates: []dedup.CertDiscovery{
			{FingerprintSHA256: "noip-cert", SubjectCN: "x", KeyAlgorithm: "RSA", KeySizeBits: 2048},
		},
	}
	if _, err := ingester.Ingest(ctx, result); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(st.sightingCalls) != 0 {
		t.Errorf("sighting calls = %d, want 0 for IP-less host", len(st.sightingCalls))
	}
	if st.provenanceCount != 1 {
		t.Errorf("provenance count = %d, want 1", st.provenanceCount)
	}
}

// TestUnifiedIngester_SightingErrorDoesNotBlockIngest is the
// log-and-continue contract (spec §6). A store that errors on
// UpsertHostIPSighting must not abort the primary provenance path.
func TestUnifiedIngester_SightingErrorDoesNotBlockIngest(t *testing.T) {
	st := &ingestMockStore{sightingErr: errSightingWriteFailed}
	ingester := NewUnifiedIngester(st)
	ctx := context.Background()

	result := &DiscoveryResult{
		Source:       "osquery",
		SourceHostID: "osq-host-1",
		Hostname:     "erroring-host",
		IPAddresses:  []string{"10.0.1.5"},
		Timestamp:    time.Now(),
		Certificates: []dedup.CertDiscovery{
			{FingerprintSHA256: "cert-err", SubjectCN: "x", KeyAlgorithm: "RSA", KeySizeBits: 2048},
		},
	}
	summary, err := ingester.Ingest(ctx, result)
	if err != nil {
		t.Fatalf("Ingest MUST succeed despite sighting error: %v", err)
	}
	if summary.CertificatesNew+summary.CertificatesUpdated != 1 {
		t.Errorf("cert not recorded: summary=%+v", summary)
	}
	if st.provenanceCount != 1 {
		t.Errorf("provenance count = %d, want 1 (primary path must complete)", st.provenanceCount)
	}
}

// errSightingWriteFailed is the sentinel used by
// TestUnifiedIngester_SightingErrorDoesNotBlockIngest.
var errSightingWriteFailed = &sightingErrStub{msg: "simulated sighting-write DB outage"}

type sightingErrStub struct{ msg string }

func (e *sightingErrStub) Error() string { return e.msg }

// TestIngest_ExternalSourceID_ReachesProvenance covers the v1.10 Phase B
// Task 2 contract: when a DiscoveryResult carries an ExternalSourceID
// (set by polling adapters like aws_acm), every provenance row written
// by this Ingest cycle must carry that same value forward so the FK
// column added in migration 032 is populated end-to-end.
func TestIngest_ExternalSourceID_ReachesProvenance(t *testing.T) {
	st := &ingestMockStore{}
	ingester := NewUnifiedIngester(st)

	const wantExtSrcID = "11111111-1111-1111-1111-111111111111"

	result := &DiscoveryResult{
		Source:             "aws_acm",
		SourceHostID:       "",
		Hostname:           "",
		ExternalSourceID:   wantExtSrcID,
		Timestamp:          time.Now().UTC(),
		SkipHostResolution: true,
		Certificates: []dedup.CertDiscovery{
			{
				FingerprintSHA256:  "aaaabbbbccccdddd" + strings.Repeat("0", 48),
				SubjectCN:          "test.example.com",
				Source:             "aws_acm",
				StoreType:          "aws_acm",
				NotBefore:          time.Now().Add(-time.Hour),
				NotAfter:           time.Now().Add(365 * 24 * time.Hour),
				KeyAlgorithm:       "RSA",
				KeySizeBits:        2048,
				SignatureAlgorithm: "SHA256-RSA",
				RawPEM:             "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			},
		},
	}

	if _, err := ingester.Ingest(context.Background(), result); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if len(st.provenanceCalls) == 0 {
		t.Fatal("no RecordProvenance call recorded")
	}
	if got := st.provenanceCalls[0].ExternalSourceID; got != wantExtSrcID {
		t.Errorf("ExternalSourceID = %q, want %q", got, wantExtSrcID)
	}
}

// generateTestPEM returns a valid self-signed PEM-encoded certificate.
// Used by the ingester boundary derivation test below; mirrors the
// helper in internal/certparse/certparse_test.go but kept local so this
// test file has no inter-package test dependency.
func generateTestPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ingest-test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestIngest_FingerprintDerivedFromRawPEM pins the v1.10 Phase B Task 7
// Critical fix: when an adapter (AWS ACM, future CT logs) supplies only
// RawPEM and leaves FingerprintSHA256 empty, the ingester boundary
// derives the SHA256 fingerprint via certparse.ParsePEM before passing
// the cert to the dedup layer. Without this fix, every such cert would
// dedupe to the empty-string sentinel.
func TestIngest_FingerprintDerivedFromRawPEM(t *testing.T) {
	pemBytes := generateTestPEM(t)

	st := &ingestMockStore{}
	u := NewUnifiedIngester(st)

	result := &DiscoveryResult{
		Source:             "aws_acm",
		Timestamp:          time.Now().UTC(),
		SkipHostResolution: true,
		Certificates: []dedup.CertDiscovery{
			{
				// FingerprintSHA256 deliberately empty — adapter (AWS ACM)
				// supplies only RawPEM; ingester boundary derives the FP.
				Source:    "aws_acm",
				StoreType: "aws_acm",
				RawPEM:    string(pemBytes),
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(365 * 24 * time.Hour),
			},
		},
	}

	if _, err := u.Ingest(context.Background(), result); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	provs := st.provenanceCalls
	if len(provs) == 0 {
		t.Fatal("no RecordProvenance — ingester silently dropped the cert")
	}
	// AssetID is the FingerprintSHA256 in lowercase. Just assert it's a
	// 64-char lowercase hex string — proves derivation worked, without
	// over-binding to a specific cert.
	id := provs[0].AssetID
	if len(id) != 64 {
		t.Errorf("AssetID = %q (len %d), want 64-char hex (SHA256)", id, len(id))
	}
}

// CE-flavor: TestIngest_ProtocolEndpoints_AppearInIngestedAssets
// removed. It pinned the v1.10 Phase C contract that protocol_endpoints
// appear as IngestedAssets (used by AWS ELBv2 poller for per-listener
// ownership correlation). AWS poller + protocol_endpoints are EE-only.
