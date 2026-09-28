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

package truststore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkcs12lib "software.sslmate.com/src/go-pkcs12"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// Trust-store and private-key rows reference certificates by fingerprint
// (foreign keys to certificates), but the scanner only reported the
// fingerprint, so scan-truststore could not store the certificate first and
// every row for a certificate CipherFlag had not already seen failed. On a
// fresh install that was every row. Each observation now carries the PEM of
// the certificate it names.

func requirePEMMatches(t *testing.T, what, pemText, fingerprint string) {
	t.Helper()
	if pemText == "" {
		t.Fatalf("%s: no certificate PEM carried", what)
	}
	c, err := certparse.ParsePEM([]byte(pemText))
	if err != nil {
		t.Fatalf("%s: carried PEM does not parse: %v", what, err)
	}
	if c.FingerprintSHA256 != fingerprint {
		t.Fatalf("%s: carried PEM is %s, observation names %s", what, c.FingerprintSHA256, fingerprint)
	}
}

func requireTrustPEMs(t *testing.T, what string, obs []model.TrustStoreObservation, want int) {
	t.Helper()
	if len(obs) != want {
		t.Fatalf("%s: %d trust observations, want %d", what, len(obs), want)
	}
	for i, o := range obs {
		requirePEMMatches(t, what+"["+string(rune('0'+i))+"]", o.CAPEM, o.CAFingerprint)
	}
}

func testCert(t *testing.T, cn string, isCA bool) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now, NotAfter: now.Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func TestObservationsCarryCertificatePEM_PEMBundle(t *testing.T) {
	s := &Scanner{}
	trust, _ := s.mapBundle(bundleObservation{Source: "os_bundle", SourceDetail: "bundle.pem", Format: "pem", Data: makePEMBundle(t, 3)})
	requireTrustPEMs(t, "pem bundle", trust, 3)
}

func TestObservationsCarryCertificatePEM_DER(t *testing.T) {
	c, _ := testCert(t, "der-ca", true)
	s := &Scanner{}
	trust, _ := s.mapBundle(bundleObservation{Source: "os_bundle", SourceDetail: "ca.der", Format: "der", Data: c.Raw})
	requireTrustPEMs(t, "der", trust, 1)
}

func TestObservationsCarryCertificatePEM_PKCS12(t *testing.T) {
	leaf, key := testCert(t, "p12-leaf", false)
	ca, _ := testCert(t, "p12-ca", true)
	data, err := pkcs12lib.Modern.Encode(key, leaf, []*x509.Certificate{ca}, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	s := &Scanner{jvmPasswords: []string{"changeit"}}
	trust, _ := s.mapBundle(bundleObservation{Source: "jvm_cacerts", SourceDetail: "store.p12", Format: "pkcs12", Data: data})
	requireTrustPEMs(t, "pkcs12", trust, 2)
}

func TestObservationsCarryCertificatePEM_JKS(t *testing.T) {
	s := &Scanner{jvmPasswords: []string{"changeit"}}
	trust, priv := s.mapJKS(bundleObservation{Source: "jvm_cacerts", SourceDetail: "test.jks", Format: "jks", Data: makeJKSFixture(t, "changeit")})
	requireTrustPEMs(t, "jks", trust, 2)
	if len(priv) != 1 {
		t.Fatalf("jks: %d private-key observations, want 1", len(priv))
	}
	requirePEMMatches(t, "jks private key", priv[0].CertPEM, priv[0].CertFingerprint)
}

func TestObservationsCarryCertificatePEM_AppConfig(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "cas.pem")
	if err := os.WriteFile(bundle, makePEMBundleN(t, 2), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := IngestAppConfigBundles([]TrustBundleRef{{Server: "nginx", ConfigPath: "/etc/nginx/nginx.conf", Directive: "ssl_trusted_certificate", BundlePath: bundle}})
	if err != nil {
		t.Fatal(err)
	}
	requireTrustPEMs(t, "app config", obs, 2)
}

// The carried PEM is a normal CERTIFICATE block, so the ingest path that
// stores it reads it like any other.
func TestCertificatePEMIsACertificateBlock(t *testing.T) {
	c, _ := testCert(t, "block", true)
	block, _ := pem.Decode([]byte(certPEM(c.Raw)))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("certPEM produced %+v, want a CERTIFICATE block", block)
	}
}
