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

package static

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// testECDSAPubPEM is Let's Encrypt Sycamore2026h2's real log key,
// verbatim from Google's log_list.json.
const testECDSAPubPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwR1FtiiMbpvxR+sIeiZ5JSCIDIdTAPh7OrpdchcrCcyNVDvNUq358pqJx2qdyrOI+EjGxZ7UiPcN3bL3Q99FqA==
-----END PUBLIC KEY-----`

const testEd25519PubPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----`

const testConfigOrigin = "log.sycamore.ct.letsencrypt.org/2026h2"

func pkixPEMForTest(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestValidateDomainConfig(t *testing.T) {
	const logURL = "https://mon.sycamore.ct.letsencrypt.org/2026h2/"
	cases := []struct {
		name, domain, logURL, origin, pubKey string
		wantErr                              string // "" = valid
	}{
		{"valid ECDSA P-256", "example.com", logURL, testConfigOrigin, testECDSAPubPEM, ""},
		{"valid Ed25519", "example.com", logURL, testConfigOrigin, testEd25519PubPEM, ""},
		{"missing domain", "", logURL, testConfigOrigin, testECDSAPubPEM, "domain is required"},
		{"missing log_url", "example.com", "", testConfigOrigin, testECDSAPubPEM, "log_url is required"},
		{"http rejected", "example.com", "http://mon.example/log/", testConfigOrigin, testECDSAPubPEM, "must be https"},
		{"no trailing slash", "example.com", "https://mon.example/log", testConfigOrigin, testECDSAPubPEM, "must end with /"},
		{"missing origin", "example.com", logURL, "", testECDSAPubPEM, "origin is required"},
		{"origin with scheme", "example.com", logURL, "https://" + testConfigOrigin, testECDSAPubPEM, "must not include a URL scheme"},
		{"origin with trailing slash", "example.com", logURL, testConfigOrigin + "/", testECDSAPubPEM, "must not end with /"},
		{"origin with space", "example.com", logURL, "log example", testECDSAPubPEM, "not a valid checkpoint key name"},
		{"origin with plus", "example.com", logURL, "log+example", testECDSAPubPEM, "not a valid checkpoint key name"},
		{"missing public key", "example.com", logURL, testConfigOrigin, "", "public_key_pem is required"},
		{"malformed public key", "example.com", logURL, testConfigOrigin, "not a pem", "PEM decode failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDomainConfig(tc.domain, tc.logURL, tc.origin, tc.pubKey)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateDomainConfig() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateDomainConfig() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseLogPublicKeyPEM_KeyTypes(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	k, err := ParseLogPublicKeyPEM(testECDSAPubPEM)
	if err != nil {
		t.Fatalf("P-256: %v", err)
	}
	if _, ok := k.Key.(*ecdsa.PublicKey); !ok || len(k.SPKI) != 91 {
		t.Errorf("P-256: Key=%T len(SPKI)=%d", k.Key, len(k.SPKI))
	}
	if _, err := ParseLogPublicKeyPEM(pkixPEMForTest(t, edPub)); err != nil {
		t.Errorf("Ed25519: %v", err)
	}
	if _, err := ParseLogPublicKeyPEM(pkixPEMForTest(t, &p384.PublicKey)); err == nil || !strings.Contains(err.Error(), "want P-256") {
		t.Errorf("P-384: err = %v, want P-256-only rejection", err)
	}
	if _, err := ParseLogPublicKeyPEM(pkixPEMForTest(t, &rsaKey.PublicKey)); err == nil || !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("RSA: err = %v, want unsupported key type", err)
	}
}
