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

	"github.com/stretchr/testify/require"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// A certificate that arrives with only RawPEM (the /api/v1/ingest API allows
// it) used to be stored with just the fingerprint derived: subject, issuer,
// CA flag, key and validity stayed empty, so it could not be scored
// meaningfully and never appeared in the PKI graph. The ingester now fills
// every empty field from the PEM, keeping any value the client supplied.

func testCAPEM(t *testing.T) (string, *model.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x1f2e3d),
		Subject:               pkix.Name{CommonName: "PEM Only Issuing CA", Organization: []string{"PEM Only Org"}},
		NotBefore:             time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		DNSNames:              []string{"ca.pem-only.test"},
		SubjectKeyId:          []byte{1, 2, 3, 4},
		OCSPServer:            []string{"http://ocsp.pem-only.test"},
		CRLDistributionPoints: []string{"http://crl.pem-only.test/ca.crl"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	parsed, err := certparse.ParsePEM([]byte(p))
	require.NoError(t, err)
	return p, parsed
}

func ingestOne(t *testing.T, disc dedup.CertDiscovery) *ingestMockStore {
	t.Helper()
	st := &ingestMockStore{}
	_, err := NewUnifiedIngester(st).Ingest(context.Background(), &DiscoveryResult{
		Source:             "api",
		Timestamp:          time.Now().UTC(),
		SkipHostResolution: true,
		Certificates:       []dedup.CertDiscovery{disc},
	})
	require.NoError(t, err)
	return st
}

func TestIngest_PEMOnlyCertificateGetsFullMetadata(t *testing.T) {
	p, want := testCAPEM(t)
	st := ingestOne(t, dedup.CertDiscovery{RawPEM: p})

	require.Len(t, st.upsertedCerts, 1)
	got := st.upsertedCerts[0]
	require.Equal(t, want.FingerprintSHA256, got.FingerprintSHA256)
	require.Equal(t, "PEM Only Issuing CA", got.Subject.CommonName)
	require.Equal(t, "PEM Only Issuing CA", got.Issuer.CommonName)
	require.Equal(t, want.SerialNumber, got.SerialNumber)
	require.True(t, want.NotBefore.Equal(got.NotBefore), "NotBefore %v, want %v", got.NotBefore, want.NotBefore)
	require.True(t, want.NotAfter.Equal(got.NotAfter), "NotAfter %v, want %v", got.NotAfter, want.NotAfter)
	require.Equal(t, want.KeyAlgorithm, got.KeyAlgorithm)
	require.Equal(t, 256, got.KeySizeBits)
	require.Equal(t, want.SignatureAlgorithm, got.SignatureAlgorithm)
	require.Equal(t, []string{"ca.pem-only.test"}, got.SubjectAltNames)
	require.True(t, got.IsCA, "a CA certificate must be stored as a CA, or it never appears in the PKI graph")
	// Everything else in the certificate, not only the fields a
	// CertDiscovery has.
	require.Equal(t, "PEM Only Org", got.Subject.Organization)
	require.Equal(t, want.KeyUsage, got.KeyUsage)
	require.Equal(t, []byte{1, 2, 3, 4}, got.SubjectKeyID)
	require.Equal(t, want.SPKIFingerprintSHA256, got.SPKIFingerprintSHA256)
	require.NotEmpty(t, got.SPKIFingerprintSHA256)
	require.Equal(t, []string{"http://ocsp.pem-only.test"}, got.OCSPResponderURLs)
	require.Equal(t, []string{"http://crl.pem-only.test/ca.crl"}, got.CRLDistributionPoints)
	require.Equal(t, model.DiscoverySource("api"), got.SourceDiscovery)
}

// Built-in adapters already fill these fields from the same PEM; values a
// client supplies are kept and only the empty ones are filled.
func TestIngest_ClientSuppliedCertFieldsAreKept(t *testing.T) {
	p, want := testCAPEM(t)
	st := ingestOne(t, dedup.CertDiscovery{RawPEM: p, SubjectCN: "client label", KeySizeBits: 999})

	require.Len(t, st.upsertedCerts, 1)
	got := st.upsertedCerts[0]
	require.Equal(t, "client label", got.Subject.CommonName)
	require.Equal(t, 999, got.KeySizeBits)
	require.Equal(t, "PEM Only Issuing CA", got.Issuer.CommonName, "empty fields are still filled")
	require.Equal(t, want.KeyAlgorithm, got.KeyAlgorithm)
}

// A fingerprint that names a different certificate than the PEM is a
// contradiction; storing either would be wrong.
func TestIngest_FingerprintContradictingPEMIsSkipped(t *testing.T) {
	p, _ := testCAPEM(t)
	st := ingestOne(t, dedup.CertDiscovery{RawPEM: p, FingerprintSHA256: strings.Repeat("ab", 32)})

	require.Empty(t, st.upsertedCerts)
	require.Empty(t, st.provenanceCalls)
}

// A client fingerprint that matches the PEM (in any case) is fine.
func TestIngest_FingerprintMatchingPEMIsAccepted(t *testing.T) {
	p, want := testCAPEM(t)
	st := ingestOne(t, dedup.CertDiscovery{RawPEM: p, FingerprintSHA256: strings.ToUpper(want.FingerprintSHA256)})

	require.Len(t, st.upsertedCerts, 1)
	require.Equal(t, "PEM Only Issuing CA", st.upsertedCerts[0].Subject.CommonName)
}

// Unchanged behaviour: a fingerprint with a PEM that does not parse is kept
// on the fingerprint's word, as before.
func TestIngest_FingerprintWithUnparseablePEMIsKept(t *testing.T) {
	st := ingestOne(t, dedup.CertDiscovery{RawPEM: "not a pem", FingerprintSHA256: strings.Repeat("cd", 32), SubjectCN: "kept"})

	require.Len(t, st.upsertedCerts, 1)
	require.Equal(t, "kept", st.upsertedCerts[0].Subject.CommonName)
}
