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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func genDERCert(t *testing.T) []byte {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return der
}

func TestDERDetector_RecognisesASN1Magic(t *testing.T) {
	d := &DERDetector{}
	der := genDERCert(t)
	blob := enumerate.Blob{Path: "certs/x.der", Size: int64(len(der))}
	findings, err := d.Detect(context.Background(), blob, der)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1, got %d", len(findings))
	}
	if findings[0].RuleID != "KEY-MAT-CERT-IN-REPO" {
		t.Errorf("rule_id: %q", findings[0].RuleID)
	}
	if findings[0].Severity != finding.SeverityMedium {
		t.Errorf("severity: %q", findings[0].Severity)
	}
	if findings[0].Fingerprint == "" {
		t.Error("fingerprint empty")
	}
}

func TestDERDetector_IgnoresNonCertDER(t *testing.T) {
	d := &DERDetector{}
	blob := enumerate.Blob{Path: "random.bin", Size: 10}
	data := []byte{0x30, 0x82, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	findings, err := d.Detect(context.Background(), blob, data)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("want 0 (garbage should not parse as cert), got %d", len(findings))
	}
}

func TestDERDetector_SkipsTextFiles(t *testing.T) {
	d := &DERDetector{}
	blob := enumerate.Blob{Path: "README.md", Size: 5}
	findings, _ := d.Detect(context.Background(), blob, []byte("hello"))
	if len(findings) != 0 {
		t.Error("text should not trigger DER path")
	}
}
