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
	"math/big"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func genJKS(t *testing.T, password string) []byte {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)

	ks := keystore.New()
	entry := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8,
		CertificateChain: []keystore.Certificate{
			{Type: "X509", Content: der},
		},
	}
	if err := ks.SetPrivateKeyEntry("alias", entry, []byte(password)); err != nil {
		t.Fatalf("set: %v", err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store: %v", err)
	}
	return buf.Bytes()
}

func TestJKS_ChangeitDetected(t *testing.T) {
	d := &JKSDetector{CommonPasswords: []string{"", "changeit", "password"}}
	body := genJKS(t, "changeit")
	blob := enumerate.Blob{Path: "certs/keystore.jks", Size: int64(len(body))}
	findings, err := d.Detect(context.Background(), blob, body)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	var hasWeak bool
	for _, f := range findings {
		if f.RuleID == "KEY-MAT-KEYSTORE-WEAK-PASSWORD" {
			hasWeak = true
		}
	}
	if !hasWeak {
		t.Errorf("want WEAK-PASSWORD finding, got %+v", findings)
	}
}

func TestJKS_StrongPasswordOnlyKeystoreFinding(t *testing.T) {
	d := &JKSDetector{CommonPasswords: []string{"", "changeit", "password"}}
	body := genJKS(t, "s0m3-un1que-un7uessable-pw!!")
	blob := enumerate.Blob{Path: "certs/strong.keystore", Size: int64(len(body))}
	findings, _ := d.Detect(context.Background(), blob, body)
	if len(findings) != 1 {
		t.Fatalf("want 1, got %d", len(findings))
	}
	if findings[0].RuleID != "KEY-MAT-KEYSTORE-IN-REPO" {
		t.Errorf("rule_id: %q", findings[0].RuleID)
	}
	if findings[0].Severity != finding.SeverityHigh {
		t.Errorf("severity: %q", findings[0].Severity)
	}
}
