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

package b1

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func genSelfSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func genPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func TestPEMDetector_CertificateFinding(t *testing.T) {
	d := &PEMDetector{}
	certPEM := genSelfSignedCertPEM(t)
	blob := enumerate.Blob{Path: "certs/test.pem", Size: int64(len(certPEM))}
	findings, err := d.Detect(context.Background(), blob, certPEM)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "KEY-MAT-CERT-IN-REPO" {
		t.Errorf("rule_id: %q", f.RuleID)
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("severity: %q", f.Severity)
	}
	if f.Bucket != finding.BucketB1 {
		t.Errorf("bucket: %q", f.Bucket)
	}
	if f.Fingerprint == "" {
		t.Error("fingerprint empty")
	}
}

func TestPEMDetector_PrivateKeyIsCritical(t *testing.T) {
	d := &PEMDetector{}
	keyPEM := genPrivateKeyPEM(t)
	blob := enumerate.Blob{Path: "secrets/server.key", Size: int64(len(keyPEM))}
	findings, err := d.Detect(context.Background(), blob, keyPEM)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "KEY-MAT-PRIVKEY-IN-REPO" {
		t.Errorf("rule_id: %q", f.RuleID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("want Critical, got %q", f.Severity)
	}
}

func TestPEMDetector_NoFindingsOnNonPEM(t *testing.T) {
	d := &PEMDetector{}
	blob := enumerate.Blob{Path: "README.md", Size: 5}
	findings, err := d.Detect(context.Background(), blob, []byte("hello"))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("want 0, got %d", len(findings))
	}
}

func TestPEMDetector_HandlesMultipleBlocksInOneFile(t *testing.T) {
	d := &PEMDetector{}
	combined := append(genSelfSignedCertPEM(t), genPrivateKeyPEM(t)...)
	blob := enumerate.Blob{Path: "both.pem", Size: int64(len(combined))}
	findings, err := d.Detect(context.Background(), blob, combined)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("want >=2, got %d", len(findings))
	}
}

func TestPEMDetector_PopulatesByteRange(t *testing.T) {
	d := &PEMDetector{}
	cert := genSelfSignedCertPEM(t)
	prefix := []byte("# leading garbage\n# more garbage\n")
	combined := append(append([]byte{}, prefix...), cert...)
	blob := enumerate.Blob{Path: "x.pem", Size: int64(len(combined))}
	findings, err := d.Detect(context.Background(), blob, combined)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	br := findings[0].ByteRange
	if br[0] != len(prefix) {
		t.Errorf("ByteRange start = %d, want %d (after prefix)", br[0], len(prefix))
	}
	if br[1] <= br[0] {
		t.Errorf("ByteRange end %d not after start %d", br[1], br[0])
	}
	if br[1] > len(combined) {
		t.Errorf("ByteRange end %d exceeds blob size %d", br[1], len(combined))
	}
	// The slice should reconstruct the cert PEM bytes.
	got := combined[br[0]:br[1]]
	if !bytes.HasPrefix(got, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Errorf("ByteRange does not start at PEM BEGIN marker: %q", got[:min(30, len(got))])
	}
}
