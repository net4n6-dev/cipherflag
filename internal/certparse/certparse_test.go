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

package certparse

import (
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
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func generateTestCert(t *testing.T) []byte {
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
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Corp"},
			Country:      []string{"US"},
		},
		DNSNames:    []string{"test.example.com", "www.test.example.com"},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return pemBlock
}

func TestParsePEM(t *testing.T) {
	pemData := generateTestCert(t)

	cert, err := ParsePEM(pemData)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, "test.example.com")
	}

	if cert.KeyAlgorithm != model.KeyECDSA {
		t.Errorf("KeyAlgorithm = %q, want %q", cert.KeyAlgorithm, model.KeyECDSA)
	}

	if cert.KeySizeBits != 256 {
		t.Errorf("KeySizeBits = %d, want 256", cert.KeySizeBits)
	}

	if len(cert.SubjectAltNames) != 2 {
		t.Errorf("SubjectAltNames count = %d, want 2", len(cert.SubjectAltNames))
	}

	if cert.FingerprintSHA256 == "" {
		t.Error("FingerprintSHA256 is empty")
	}
	if len(cert.FingerprintSHA256) != 64 {
		t.Errorf("FingerprintSHA256 length = %d, want 64", len(cert.FingerprintSHA256))
	}

	if cert.RawPEM == "" {
		t.Error("RawPEM is empty")
	}

	if cert.SignatureAlgorithm != model.SigECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm = %q, want %q", cert.SignatureAlgorithm, model.SigECDSAWithSHA256)
	}

	if cert.Subject.Organization != "Test Corp" {
		t.Errorf("Subject.Organization = %q, want %q", cert.Subject.Organization, "Test Corp")
	}

	if cert.Subject.Country != "US" {
		t.Errorf("Subject.Country = %q, want %q", cert.Subject.Country, "US")
	}

	if cert.IsCA {
		t.Error("IsCA = true, want false")
	}

	if cert.SourceDiscovery != model.SourceZeekPassive {
		t.Errorf("SourceDiscovery = %q, want %q", cert.SourceDiscovery, model.SourceZeekPassive)
	}

	if cert.SerialNumber == "" {
		t.Error("SerialNumber is empty")
	}

	if cert.FirstSeen.IsZero() {
		t.Error("FirstSeen is zero")
	}

	if cert.LastSeen.IsZero() {
		t.Error("LastSeen is zero")
	}

	if len(cert.KeyUsage) == 0 {
		t.Error("KeyUsage is empty")
	}

	if len(cert.ExtendedKeyUsage) != 1 || cert.ExtendedKeyUsage[0] != "Server Authentication" {
		t.Errorf("ExtendedKeyUsage = %v, want [Server Authentication]", cert.ExtendedKeyUsage)
	}
}

func TestParsePEM_InvalidPEM(t *testing.T) {
	_, err := ParsePEM([]byte("not a PEM"))
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
}

func TestParseDER(t *testing.T) {
	pemData := generateTestCert(t)
	block, _ := pem.Decode(pemData)

	cert, err := ParseDER(block.Bytes)
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, "test.example.com")
	}

	if cert.RawPEM != "" {
		t.Errorf("RawPEM should be empty for DER parse, got %d bytes", len(cert.RawPEM))
	}
}

func TestParseDER_ExtractsAKIAndSKI(t *testing.T) {
	// Build a CA with a deterministic SubjectKeyId so AKI linkage is verifiable.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		// SP-1.6: deterministic SKI so the leaf AKI assertion is byte-exact.
		SubjectKeyId: []byte{0xCA, 0xCA, 0xCA, 0xCA},
		// Self-signed: AKI equals SKI — x509.CreateCertificate copies
		// SubjectKeyId into AuthorityKeyId when the template and parent are
		// the same object.
		AuthorityKeyId: []byte{0xCA, 0xCA, 0xCA, 0xCA},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	ca, err := ParseDER(caDER)
	if err != nil {
		t.Fatalf("ParseDER CA: %v", err)
	}

	wantCASKI := []byte{0xCA, 0xCA, 0xCA, 0xCA}
	if string(ca.SubjectKeyID) != string(wantCASKI) {
		t.Errorf("CA SubjectKeyID = %x, want %x", ca.SubjectKeyID, wantCASKI)
	}
	// Self-signed CA: AKI and SKI must both be set and equal.
	if string(ca.AuthorityKeyID) != string(ca.SubjectKeyID) {
		t.Errorf("CA AuthorityKeyID = %x, want equal to SubjectKeyID %x", ca.AuthorityKeyID, ca.SubjectKeyID)
	}

	// Build a leaf cert signed by the CA; AKI must match CA's SKI byte-for-byte.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour),
		SubjectKeyId:   []byte{0x1E, 0xAF},
		AuthorityKeyId: []byte{0xCA, 0xCA, 0xCA, 0xCA},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caTpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	leaf, err := ParseDER(leafDER)
	if err != nil {
		t.Fatalf("ParseDER leaf: %v", err)
	}

	wantLeafSKI := []byte{0x1E, 0xAF}
	if string(leaf.SubjectKeyID) != string(wantLeafSKI) {
		t.Errorf("leaf SubjectKeyID = %x, want %x", leaf.SubjectKeyID, wantLeafSKI)
	}
	// Leaf AKI must match CA SKI byte-for-byte (RFC 5280 §4.2.1.1).
	if string(leaf.AuthorityKeyID) != string(wantCASKI) {
		t.Errorf("leaf AuthorityKeyID = %x, want %x (CA's SubjectKeyID)", leaf.AuthorityKeyID, wantCASKI)
	}
}

func TestParseDER_StampsSPKIFingerprint(t *testing.T) {
	pemData := generateTestCert(t)

	cert, err := ParsePEM(pemData)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if cert.SPKIFingerprintSHA256 == "" {
		t.Fatal("SPKIFingerprintSHA256 empty; want 64-char hex")
	}
	if len(cert.SPKIFingerprintSHA256) != 64 {
		t.Errorf("SPKIFingerprintSHA256 len = %d, want 64", len(cert.SPKIFingerprintSHA256))
	}
	// Re-parse the PEM to get x509.Certificate and recompute the expected value.
	block, _ := pem.Decode(pemData)
	x, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	sum := sha256.Sum256(x.RawSubjectPublicKeyInfo)
	want := hex.EncodeToString(sum[:])
	if cert.SPKIFingerprintSHA256 != want {
		t.Errorf("SPKIFingerprintSHA256 = %s, want %s", cert.SPKIFingerprintSHA256, want)
	}
}
