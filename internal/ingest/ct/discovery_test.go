// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ct

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"
)

func selfSignedPEM(t *testing.T, key crypto.Signer, tmpl *x509.Certificate) ([]byte, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

// A weak RSA-1024 leaf must come through with the key/signature fields
// the risk scorer grades — the fields the certspotter/static/multi paths
// used to leave empty.
func TestBuildCertDiscovery_PopulatesScoringFields_RSA1024(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	nb := time.Now().Add(-time.Hour).Truncate(time.Second).UTC()
	na := nb.Add(90 * 24 * time.Hour)
	pemBytes, der := selfSignedPEM(t, key, &x509.Certificate{
		SerialNumber:       big.NewInt(0xabcdef),
		Subject:            pkix.Name{CommonName: "weak.example.com"},
		NotBefore:          nb,
		NotAfter:           na,
		DNSNames:           []string{"weak.example.com", "www.weak.example.com"},
		SignatureAlgorithm: x509.SHA256WithRSA,
	})
	fp := sha256.Sum256(der)

	got, err := BuildCertDiscovery(CTEntry{
		Fingerprint: "provider-supplied-not-trusted",
		PEM:         pemBytes,
		IssuerName:  "C=US, O=Free-form provider DN, CN=weak.example.com",
		Source:      "ct_certspotter",
	}, "ct_certspotter", "ct_log")
	if err != nil {
		t.Fatalf("BuildCertDiscovery: %v", err)
	}

	checks := []struct {
		field     string
		got, want any
	}{
		{"Source", got.Source, "ct_certspotter"},
		{"StoreType", got.StoreType, "ct_log"},
		{"FingerprintSHA256", got.FingerprintSHA256, hex.EncodeToString(fp[:])},
		{"SubjectCN", got.SubjectCN, "weak.example.com"},
		{"IssuerCN", got.IssuerCN, "weak.example.com"},
		{"SerialNumber", got.SerialNumber, "abcdef"},
		{"KeyAlgorithm", got.KeyAlgorithm, "RSA"},
		{"KeySizeBits", got.KeySizeBits, 1024},
		{"SignatureAlgorithm", got.SignatureAlgorithm, "SHA256WithRSA"},
		{"IsCA", got.IsCA, false},
		{"NotBefore", got.NotBefore.Equal(nb), true},
		{"NotAfter", got.NotAfter.Equal(na), true},
		{"RawPEM", got.RawPEM, string(pemBytes)},
		{"FilePath (caller's job)", got.FilePath, ""},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if !slices.Equal(got.SubjectAltNames, []string{"weak.example.com", "www.weak.example.com"}) {
		t.Errorf("SubjectAltNames = %v", got.SubjectAltNames)
	}
}

func TestBuildCertDiscovery_ECDSA_CA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemBytes, _ := selfSignedPEM(t, key, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	})
	got, err := BuildCertDiscovery(CTEntry{PEM: pemBytes}, "ct_static", "ct_log")
	if err != nil {
		t.Fatalf("BuildCertDiscovery: %v", err)
	}
	if got.KeyAlgorithm != "ECDSA" || got.KeySizeBits != 256 || got.SignatureAlgorithm != "ECDSAWithSHA256" || !got.IsCA {
		t.Errorf("got KeyAlgorithm=%q KeySizeBits=%d SignatureAlgorithm=%q IsCA=%v; want ECDSA/256/ECDSAWithSHA256/true",
			got.KeyAlgorithm, got.KeySizeBits, got.SignatureAlgorithm, got.IsCA)
	}
}

func TestBuildCertDiscovery_RejectsMissingOrBadPEM(t *testing.T) {
	for name, e := range map[string]CTEntry{
		"empty PEM":     {Fingerprint: "x"},
		"not PEM":       {PEM: []byte("garbage")},
		"truncated DER": {PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 0x01}})},
	} {
		if _, err := BuildCertDiscovery(e, "ct_static", "ct_log"); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}
