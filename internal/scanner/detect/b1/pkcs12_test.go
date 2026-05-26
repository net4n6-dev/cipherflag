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

	"software.sslmate.com/src/go-pkcs12"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func genP12(t *testing.T, password string) []byte {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	b, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatalf("encode p12: %v", err)
	}
	return b
}

func TestPKCS12_WeakPasswordDetected(t *testing.T) {
	d := &PKCS12Detector{CommonPasswords: []string{"", "changeit", "password"}}
	body := genP12(t, "changeit")
	blob := enumerate.Blob{Path: "certs/kit.p12", Size: int64(len(body))}
	findings, err := d.Detect(context.Background(), blob, body)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("want keystore-in-repo + weak-password findings, got %d", len(findings))
	}
	var hasWeak bool
	for _, f := range findings {
		if f.RuleID == "KEY-MAT-KEYSTORE-WEAK-PASSWORD" && f.Severity == finding.SeverityCritical {
			hasWeak = true
		}
	}
	if !hasWeak {
		t.Error("expected KEY-MAT-KEYSTORE-WEAK-PASSWORD Critical")
	}
}

func TestPKCS12_UncrackedEmitsOnlyHigh(t *testing.T) {
	d := &PKCS12Detector{CommonPasswords: []string{"", "changeit", "password"}}
	body := genP12(t, "a-strong-unique-password-that-is-not-in-the-list")
	blob := enumerate.Blob{Path: "certs/strong.p12", Size: int64(len(body))}
	findings, _ := d.Detect(context.Background(), blob, body)
	if len(findings) != 1 {
		t.Fatalf("want 1 (just KEYSTORE-IN-REPO), got %d", len(findings))
	}
	if findings[0].RuleID != "KEY-MAT-KEYSTORE-IN-REPO" {
		t.Errorf("rule_id: %q", findings[0].RuleID)
	}
	if findings[0].Severity != finding.SeverityHigh {
		t.Errorf("severity: %q", findings[0].Severity)
	}
}

func TestPKCS12_NotP12File(t *testing.T) {
	d := &PKCS12Detector{}
	blob := enumerate.Blob{Path: "README.md", Size: 5}
	findings, _ := d.Detect(context.Background(), blob, []byte("hello"))
	if len(findings) != 0 {
		t.Error("non-p12 should produce 0")
	}
}
