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

package b4

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
)

func TestOpensslConf_ProvidersDefault(t *testing.T) {
	body := `openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
`
	d := NewOpensslConfDetector()
	findings, err := d.Detect(context.Background(), enumerate.Blob{Path: "etc/ssl/openssl.cnf"}, []byte(body))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len=%d want 1", len(findings))
	}
	if findings[0].RuleID != "CFG-OPENSSL-PROVIDERS" {
		t.Errorf("rule=%q", findings[0].RuleID)
	}
	ap, _ := findings[0].Evidence["active_providers"].([]string)
	if len(ap) != 2 {
		t.Errorf("providers: %v", ap)
	}
}

func TestOpensslConf_FIPSMode(t *testing.T) {
	body := `[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[algorithm_sect]
default_properties = fips=yes

[provider_sect]
fips = fips_sect

[fips_sect]
activate = 1
`
	d := NewOpensslConfDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "etc/ssl/openssl.cnf"}, []byte(body))
	// Expect two: providers (fips provider activated) + fips marker.
	var sawFIPS, sawProv bool
	for _, f := range findings {
		if f.RuleID == "CFG-OPENSSL-FIPS" {
			sawFIPS = true
		}
		if f.RuleID == "CFG-OPENSSL-PROVIDERS" {
			sawProv = true
		}
	}
	if !sawFIPS {
		t.Error("expected CFG-OPENSSL-FIPS")
	}
	if !sawProv {
		t.Error("expected CFG-OPENSSL-PROVIDERS")
	}
}

func TestOpensslConf_IgnoresNonOpensslConfFiles(t *testing.T) {
	d := NewOpensslConfDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "etc/nginx/nginx.conf"}, []byte("activate = 1"))
	if len(findings) != 0 {
		t.Errorf("expected 0 on non-openssl.cnf; got %d", len(findings))
	}
}
