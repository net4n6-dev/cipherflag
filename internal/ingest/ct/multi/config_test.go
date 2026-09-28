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

package multi

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

func pkixPEM(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func ed25519PEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pkixPEM(t, pub)
}

// p256PEM returns an ECDSA P-256 SPKI PEM — the key type every production
// Static CT log uses.
func p256PEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pkixPEM(t, &k.PublicKey)
}

func TestValidateGroup(t *testing.T) {
	validPEM := p256PEM(t)
	valid := config.CtMultiGroupConfig{
		Domain: "example.com",
		Children: []config.CtMultiChildConfig{
			{Crtsh: &config.CtMultiChildCrtshConfig{}},
			{Static: &config.CtMultiChildStaticConfig{Domain: "example.com", LogURL: "https://log.example/2026h1/", Origin: "log.example/2026h1", PublicKeyPEM: validPEM}},
			{Certspotter: &config.CtMultiChildCertspotterConfig{RequestsPerHour: 100}},
		},
	}
	if err := ValidateGroup(valid); err != nil {
		t.Fatalf("expected valid group to pass, got %v", err)
	}

	tooFewChildren := config.CtMultiGroupConfig{
		Domain:   "example.com",
		Children: []config.CtMultiChildConfig{{Crtsh: &config.CtMultiChildCrtshConfig{}}},
	}
	if err := ValidateGroup(tooFewChildren); err == nil {
		t.Fatal("expected error for <2 children")
	}

	mismatchedDomain := config.CtMultiGroupConfig{
		Domain: "example.com",
		Children: []config.CtMultiChildConfig{
			{Crtsh: &config.CtMultiChildCrtshConfig{}},
			{Static: &config.CtMultiChildStaticConfig{Domain: "other.com", LogURL: "https://log.example/", Origin: "log.example", PublicKeyPEM: validPEM}},
		},
	}
	if err := ValidateGroup(mismatchedDomain); err == nil {
		t.Fatal("expected error for mismatched child domain")
	}

	ambiguousChild := config.CtMultiGroupConfig{
		Domain: "example.com",
		Children: []config.CtMultiChildConfig{
			{Crtsh: &config.CtMultiChildCrtshConfig{}, Static: &config.CtMultiChildStaticConfig{}},
			{Certspotter: &config.CtMultiChildCertspotterConfig{}},
		},
	}
	if err := ValidateGroup(ambiguousChild); err == nil {
		t.Fatal("expected error for child with two non-nil kinds")
	}
}

// Final-review Fix 4: ValidateGroup must delegate to each child kind's own
// validator, so a misconfigured child fails fast at startup instead of
// failing silently every cycle.
func TestValidateGroup_DelegatesToPerKindValidators(t *testing.T) {
	validPEM := ed25519PEM(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	p384PEM := pkixPEM(t, &ecKey.PublicKey)

	okCrtsh := config.CtMultiChildConfig{Crtsh: &config.CtMultiChildCrtshConfig{}}
	static := func(logURL, pemStr string) config.CtMultiChildConfig {
		return config.CtMultiChildConfig{Static: &config.CtMultiChildStaticConfig{LogURL: logURL, Origin: "log.example", PublicKeyPEM: pemStr}}
	}
	certspotter := func(rph int) config.CtMultiChildConfig {
		return config.CtMultiChildConfig{Certspotter: &config.CtMultiChildCertspotterConfig{RequestsPerHour: rph}}
	}
	group := func(domain string, children ...config.CtMultiChildConfig) config.CtMultiGroupConfig {
		return config.CtMultiGroupConfig{Domain: domain, Children: children}
	}

	for _, tc := range []struct {
		name    string
		group   config.CtMultiGroupConfig
		wantErr string // substring of the per-kind validator's message
	}{
		// crtsh
		{"crtsh: invalid domain", group("Not A Domain", okCrtsh, certspotter(0)), "ct_crtsh"},
		// static
		{"static: http scheme", group("example.com", okCrtsh, static("http://log.example/", validPEM)), "must be https"},
		{"static: missing trailing slash", group("example.com", okCrtsh, static("https://log.example/2026h1", validPEM)), "must end with /"},
		{"static: empty log_url", group("example.com", okCrtsh, static("", validPEM)), "log_url is required"},
		{"static: empty public key", group("example.com", okCrtsh, static("https://log.example/", "")), "public_key_pem is required"},
		{"static: malformed public key", group("example.com", okCrtsh, static("https://log.example/", "not a pem")), "PEM decode failed"},
		{"static: non-P-256 ECDSA key", group("example.com", okCrtsh, static("https://log.example/", p384PEM)), "want P-256"},
		{"static: missing origin", group("example.com", okCrtsh, config.CtMultiChildConfig{Static: &config.CtMultiChildStaticConfig{LogURL: "https://log.example/", PublicKeyPEM: validPEM}}), "origin is required"},
		// certspotter
		{"certspotter: negative requests_per_hour", group("example.com", okCrtsh, certspotter(-1)), "requests_per_hour must be >= 0"},
		{"certspotter: requests_per_hour too high", group("example.com", okCrtsh, certspotter(100001)), "requests_per_hour must be <= 100000"},
		{"certspotter: invalid domain", group("EXAMPLE.COM", static("https://log.example/", validPEM), certspotter(10)), "ct_certspotter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGroup(tc.group)
			if err == nil {
				t.Fatalf("ValidateGroup: want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want substring %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), "children[1]") && !strings.Contains(err.Error(), "children[0]") {
				t.Errorf("err = %v, want the offending child index for operator context", err)
			}
		})
	}
}
