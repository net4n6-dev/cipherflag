package certparse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
