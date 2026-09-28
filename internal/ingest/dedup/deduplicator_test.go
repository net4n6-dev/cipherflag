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

package dedup

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type mockStore struct {
	store.CryptoStore
	certs     map[string]*model.Certificate
	sshKeys   map[string]*model.SSHKey
	libraries map[string]*model.CryptoLibrary
	configs   map[string]*model.CryptoConfig
}

func newMockStore() *mockStore {
	return &mockStore{
		certs:     map[string]*model.Certificate{},
		sshKeys:   map[string]*model.SSHKey{},
		libraries: map[string]*model.CryptoLibrary{},
		configs:   map[string]*model.CryptoConfig{},
	}
}

func (m *mockStore) GetCertificate(ctx context.Context, fp string) (*model.Certificate, error) {
	return m.certs[strings.ToLower(fp)], nil
}

func (m *mockStore) UpsertCertificate(ctx context.Context, cert *model.Certificate) error {
	m.certs[strings.ToLower(cert.FingerprintSHA256)] = cert
	return nil
}

func (m *mockStore) UpsertSSHKey(ctx context.Context, key *model.SSHKey) error {
	k := key.HostID + ":" + strings.ToLower(key.FingerprintSHA256)
	if key.ID == "" {
		key.ID = "key-" + k
	}
	m.sshKeys[k] = key
	return nil
}

func (m *mockStore) UpsertCryptoLibrary(ctx context.Context, lib *model.CryptoLibrary) error {
	k := lib.HostID + ":" + strings.ToLower(lib.LibraryName) + ":" + strings.TrimSpace(lib.Version)
	if lib.ID == "" {
		lib.ID = "lib-" + k
	}
	m.libraries[k] = lib
	return nil
}

func (m *mockStore) UpsertCryptoConfig(ctx context.Context, cfg *model.CryptoConfig) error {
	k := cfg.HostID + ":" + cfg.FilePath
	if cfg.ID == "" {
		cfg.ID = "cfg-" + k
	}
	m.configs[k] = cfg
	return nil
}

func TestDedupCertificate_New(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &CertDiscovery{
		FingerprintSHA256: "AABB1122",
		SubjectCN:         "test.example.com",
		KeyAlgorithm:      "RSA",
		KeySizeBits:       4096,
	}

	assetID, isNew, err := d.DedupCertificate(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	if !isNew {
		t.Error("expected isNew = true for new cert")
	}
	if assetID == "" {
		t.Error("expected non-empty assetID")
	}
}

func TestDedupCertificate_Existing(t *testing.T) {
	st := newMockStore()
	st.certs["aabb1122"] = &model.Certificate{
		FingerprintSHA256: "aabb1122",
	}
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &CertDiscovery{FingerprintSHA256: "AABB1122"}

	_, isNew, err := d.DedupCertificate(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	if isNew {
		t.Error("expected isNew = false for existing cert")
	}
}

// A re-observed certificate used to be written back with the last_seen it
// was read with, so last_seen never moved after the first ingest: reports
// showed stale dates and the Venafi push (last_seen > venafi_pushed_at)
// never picked a re-observed certificate up again.
func TestDedupCertificate_ExistingAdvancesLastSeen(t *testing.T) {
	st := newMockStore()
	firstSeen := time.Now().Add(-48 * time.Hour)
	st.certs["aabb1122"] = &model.Certificate{
		FingerprintSHA256: "aabb1122",
		FirstSeen:         firstSeen,
		LastSeen:          time.Now().Add(-24 * time.Hour),
	}
	before := time.Now()

	_, isNew, err := NewDeduplicator(st).DedupCertificate(context.Background(), "host-1", &CertDiscovery{FingerprintSHA256: "AABB1122"})
	if err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	if isNew {
		t.Fatal("expected isNew = false for existing cert")
	}
	got := st.certs["aabb1122"]
	if got.LastSeen.Before(before) {
		t.Errorf("LastSeen = %v, want at or after %v (the re-observation)", got.LastSeen, before)
	}
	if !got.FirstSeen.Equal(firstSeen) {
		t.Errorf("FirstSeen = %v, want unchanged %v", got.FirstSeen, firstSeen)
	}
}

// testCertPEM returns a freshly generated certificate carrying the metadata
// that only the certificate itself has (organization, key usage, key IDs,
// OCSP and CRL locations), and its fingerprint.
func testCertPEM(t *testing.T, cn string, isCA bool) (pemText, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Dedup Test Org"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SubjectKeyId:          []byte{9, 8, 7},
		OCSPServer:            []string{"http://ocsp.dedup.test"},
		CRLDistributionPoints: []string{"http://crl.dedup.test/ca.crl"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sum[:])
}

// requireFullMetadata fails unless c carries what only a parse of the PEM
// provides; the adapters' flat fields never include any of it.
func requireFullMetadata(t *testing.T, c *model.Certificate) {
	t.Helper()
	switch {
	case c == nil:
		t.Fatal("certificate not stored")
	case c.Subject.Organization != "Dedup Test Org":
		t.Errorf("organization = %q", c.Subject.Organization)
	case len(c.KeyUsage) == 0:
		t.Error("key usage not set")
	case !bytes.Equal(c.SubjectKeyID, []byte{9, 8, 7}):
		t.Errorf("subject key ID = %x", c.SubjectKeyID)
	case c.SPKIFingerprintSHA256 == "":
		t.Error("SPKI fingerprint not set")
	case strings.Join(c.OCSPResponderURLs, ",") != "http://ocsp.dedup.test":
		t.Errorf("OCSP = %v", c.OCSPResponderURLs)
	case strings.Join(c.CRLDistributionPoints, ",") != "http://crl.dedup.test/ca.crl":
		t.Errorf("CRL = %v", c.CRLDistributionPoints)
	}
}

// A discovery with a PEM used to be stored with only the handful of flat
// fields a CertDiscovery has, so the organization, key usage, key IDs, SPKI
// fingerprint and OCSP/CRL locations in the certificate were thrown away.
// The row is now built from the parsed certificate, and records the
// discovering source rather than the parser's default.
func TestDedupCertificate_NewFromPEMHasFullMetadata(t *testing.T) {
	st := newMockStore()
	pemText, fp := testCertPEM(t, "pem-only.dedup.test", false)

	_, isNew, err := NewDeduplicator(st).DedupCertificate(context.Background(), "host-1",
		&CertDiscovery{FingerprintSHA256: strings.ToUpper(fp), RawPEM: pemText, Source: "api"})
	if err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	if !isNew {
		t.Error("expected isNew = true")
	}
	got := st.certs[fp]
	requireFullMetadata(t, got)
	if got.Subject.CommonName != "pem-only.dedup.test" || got.RawPEM != pemText {
		t.Errorf("subject %q, PEM kept %v", got.Subject.CommonName, got.RawPEM == pemText)
	}
	if got.SourceDiscovery != "api" {
		t.Errorf("source = %q, want the discovering source", got.SourceDiscovery)
	}
	if got.FingerprintSHA256 != fp {
		t.Errorf("fingerprint = %q, want lower-case %q", got.FingerprintSHA256, fp)
	}
}

// Values the discovery supplies are kept over the parsed ones, except an
// 'Unknown' algorithm (what the Zeek mapper sends when it cannot tell), and
// a discovery cannot un-CA a CA certificate.
func TestDedupCertificate_DiscoveryValuesOverlayThePEM(t *testing.T) {
	st := newMockStore()
	pemText, fp := testCertPEM(t, "ca.dedup.test", true)

	if _, _, err := NewDeduplicator(st).DedupCertificate(context.Background(), "host-1", &CertDiscovery{
		FingerprintSHA256: fp, RawPEM: pemText, SubjectCN: "adapter name",
		KeyAlgorithm: string(model.KeyUnknown), SignatureAlgorithm: string(model.SigUnknown), IsCA: false,
	}); err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	got := st.certs[fp]
	requireFullMetadata(t, got)
	if got.Subject.CommonName != "adapter name" {
		t.Errorf("subject = %q, want the discovery's value", got.Subject.CommonName)
	}
	if got.KeyAlgorithm != model.KeyECDSA || got.SignatureAlgorithm != model.SigECDSAWithSHA256 {
		t.Errorf("algorithms = %q/%q, 'Unknown' must not replace the parsed ones", got.KeyAlgorithm, got.SignatureAlgorithm)
	}
	if !got.IsCA {
		t.Error("a CA certificate must stay a CA")
	}
}

// A fingerprint that names a different certificate than the PEM is a
// contradiction: nothing is stored and the caller can tell why.
func TestDedupCertificate_PEMMismatchIsRejected(t *testing.T) {
	st := newMockStore()
	pemText, _ := testCertPEM(t, "one.dedup.test", false)

	_, _, err := NewDeduplicator(st).DedupCertificate(context.Background(), "host-1",
		&CertDiscovery{FingerprintSHA256: "aabb1122", RawPEM: pemText})
	if !errors.Is(err, ErrPEMMismatch) {
		t.Fatalf("err = %v, want ErrPEMMismatch", err)
	}
	if len(st.certs) != 0 {
		t.Errorf("stored %d certificates, want none", len(st.certs))
	}
}

// A PEM that does not parse leaves the discovery's own fields, as before.
func TestDedupCertificate_UnparseablePEMUsesDiscoveryFields(t *testing.T) {
	st := newMockStore()
	if _, _, err := NewDeduplicator(st).DedupCertificate(context.Background(), "host-1",
		&CertDiscovery{FingerprintSHA256: "aabb1122", RawPEM: "not a pem", SubjectCN: "flat name"}); err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	if got := st.certs["aabb1122"]; got == nil || got.Subject.CommonName != "flat name" || got.RawPEM != "not a pem" {
		t.Errorf("stored %+v", got)
	}
}

// A certificate stored incomplete (earlier versions kept only the fingerprint
// of a PEM-only discovery) is given the full parsed row when seen again with
// its PEM; UpsertCertificate fills only the columns still empty. It keeps
// its first sighting.
func TestDedupCertificate_ExistingIncompleteRowGetsTheParsedCertificate(t *testing.T) {
	st := newMockStore()
	pemText, fp := testCertPEM(t, "blank.dedup.test", false)
	firstSeen := time.Now().Add(-48 * time.Hour)
	st.certs[fp] = &model.Certificate{FingerprintSHA256: fp, FirstSeen: firstSeen, LastSeen: firstSeen}
	before := time.Now()

	_, isNew, err := NewDeduplicator(st).DedupCertificate(context.Background(), "host-1",
		&CertDiscovery{FingerprintSHA256: fp, RawPEM: pemText})
	if err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	if isNew {
		t.Error("expected isNew = false")
	}
	got := st.certs[fp]
	requireFullMetadata(t, got)
	if !got.FirstSeen.Equal(firstSeen) || got.LastSeen.Before(before) {
		t.Errorf("first_seen %v (want %v), last_seen %v (want at or after %v)", got.FirstSeen, firstSeen, got.LastSeen, before)
	}
}

// A complete stored row is written back as read (only last_seen moves)
// without parsing the discovery's PEM again: a PEM for another certificate
// would otherwise be rejected here.
func TestDedupCertificate_ExistingCompleteRowIsNotReparsed(t *testing.T) {
	st := newMockStore()
	stored := &model.Certificate{
		FingerprintSHA256: "aabb1122", Subject: model.DistinguishedName{CommonName: "stored name"},
		NotAfter: time.Now().Add(time.Hour), KeyAlgorithm: model.KeyRSA, KeySizeBits: 2048,
		SignatureAlgorithm: model.SigSHA256WithRSA, RawPEM: "stored pem",
	}
	st.certs["aabb1122"] = stored
	otherPEM, _ := testCertPEM(t, "other.dedup.test", false)

	if _, _, err := NewDeduplicator(st).DedupCertificate(context.Background(), "host-1",
		&CertDiscovery{FingerprintSHA256: "AABB1122", RawPEM: otherPEM}); err != nil {
		t.Fatalf("DedupCertificate: %v (the PEM must not be parsed for a complete row)", err)
	}
	if got := st.certs["aabb1122"]; got != stored || got.RawPEM != "stored pem" {
		t.Errorf("want the stored row written back unchanged, got %+v", got)
	}
}

// The ingester parses a PEM once when it needs the fingerprint and hands the
// result over in Parsed, so dedup does not parse it again.
func TestDedupCertificate_UsesParsedFromTheIngester(t *testing.T) {
	st := newMockStore()
	pemText, fp := testCertPEM(t, "parsed.dedup.test", false)
	parsed := &model.Certificate{FingerprintSHA256: fp, Subject: model.DistinguishedName{CommonName: "from Parsed"}}

	if _, _, err := NewDeduplicator(st).DedupCertificate(context.Background(), "host-1",
		&CertDiscovery{FingerprintSHA256: fp, RawPEM: pemText, Parsed: parsed}); err != nil {
		t.Fatalf("DedupCertificate: %v", err)
	}
	if got := st.certs[fp]; got.Subject.CommonName != "from Parsed" {
		t.Errorf("subject = %q, want the value from Parsed", got.Subject.CommonName)
	}
}

func TestDedupCertificate_CaseInsensitive(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc1 := &CertDiscovery{FingerprintSHA256: "AAbb1122", SubjectCN: "test", KeyAlgorithm: "RSA", KeySizeBits: 2048}
	disc2 := &CertDiscovery{FingerprintSHA256: "aaBB1122", SubjectCN: "test", KeyAlgorithm: "RSA", KeySizeBits: 2048}

	id1, _, _ := d.DedupCertificate(ctx, "host-1", disc1)
	id2, isNew2, _ := d.DedupCertificate(ctx, "host-2", disc2)

	if id1 != id2 {
		t.Errorf("case-insensitive fingerprints should match: %q vs %q", id1, id2)
	}
	if isNew2 {
		t.Error("second cert with same fingerprint should not be new")
	}
}

func TestDedupSSHKey_New(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &SSHKeyDiscovery{
		KeyType: "ssh-ed25519", FingerprintSHA256: "keyFP123",
		KeySizeBits: 256,
	}

	assetID, isNew, err := d.DedupSSHKey(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupSSHKey: %v", err)
	}
	if !isNew {
		t.Error("expected isNew = true")
	}
	if assetID == "" {
		t.Error("expected non-empty assetID")
	}
}

func TestDedupLibrary_New(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &LibraryDiscovery{
		LibraryName: "OpenSSL", Version: " 3.0.12 ",
	}

	assetID, isNew, err := d.DedupLibrary(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupLibrary: %v", err)
	}
	if !isNew {
		t.Error("expected isNew = true")
	}
	if assetID == "" {
		t.Error("expected non-empty assetID")
	}

	// Verify normalization: "OpenSSL" should be stored as "openssl"
	key := "host-1:openssl:3.0.12"
	if _, ok := st.libraries[key]; !ok {
		t.Errorf("expected library at key %q, keys are: %v", key, st.libraries)
	}
}

func TestDedupConfig_New(t *testing.T) {
	st := newMockStore()
	d := NewDeduplicator(st)
	ctx := context.Background()

	disc := &ConfigDiscovery{
		ConfigType: "sshd_config", FilePath: "/etc/ssh/sshd_config",
		Settings: map[string]string{"Protocol": "2"},
	}

	assetID, isNew, err := d.DedupConfig(ctx, "host-1", disc)
	if err != nil {
		t.Fatalf("DedupConfig: %v", err)
	}
	if !isNew {
		t.Error("expected isNew = true")
	}
	if assetID == "" {
		t.Error("expected non-empty assetID")
	}
}

// ssh_comment producer coverage moved to
// internal/ingest/ingester_sshcomment_integration_test.go:TestIngest_SSHComment_EmitsSighting
// in v1.10 Phase 0. DedupSSHKey no longer emits sightings itself.
