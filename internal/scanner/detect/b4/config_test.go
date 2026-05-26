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
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func TestNginx_WeakProtocol(t *testing.T) {
	d := &TLSConfigDetector{}
	data := []byte(`
server {
  listen 443 ssl;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_ciphers   HIGH:!aNULL:!MD5;
}
`)
	blob := enumerate.Blob{Path: "etc/nginx/sites-enabled/a.conf", Size: int64(len(data))}
	findings, err := d.Detect(context.Background(), blob, data)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["TLS-CFG-PROTOCOL-WEAK"] {
		t.Errorf("expected TLS-CFG-PROTOCOL-WEAK, got %+v", ruleIDs)
	}
}

func TestApache_WeakCipher(t *testing.T) {
	d := &TLSConfigDetector{}
	data := []byte(`
SSLProtocol -all +TLSv1.2
SSLCipherSuite RC4-SHA:HIGH
`)
	blob := enumerate.Blob{Path: "etc/apache2/conf-available/ssl.conf", Size: int64(len(data))}
	findings, _ := d.Detect(context.Background(), blob, data)
	hasWeak := false
	for _, f := range findings {
		if f.RuleID == "TLS-CFG-CIPHER-WEAK" && f.Severity != finding.SeverityInfo {
			hasWeak = true
		}
	}
	if !hasWeak {
		t.Errorf("expected TLS-CFG-CIPHER-WEAK non-Info, got findings %+v", findings)
	}
}

func TestEnvoy_DefaultParamsFineNoFinding(t *testing.T) {
	d := &TLSConfigDetector{}
	data := []byte(`
static_resources:
  listeners:
    - address: {socket_address: {address: 0.0.0.0, port_value: 8443}}
`)
	blob := enumerate.Blob{Path: "envoy.yaml", Size: int64(len(data))}
	findings, _ := d.Detect(context.Background(), blob, data)
	if len(findings) != 0 {
		t.Errorf("benign envoy produces 0 findings; got %d: %+v", len(findings), findings)
	}
}

func TestOpenSSLCnf_MinProtocol(t *testing.T) {
	d := &TLSConfigDetector{}
	data := []byte(`
[system_default_sect]
MinProtocol = TLSv1
CipherString = DEFAULT@SECLEVEL=1
`)
	blob := enumerate.Blob{Path: "etc/ssl/openssl.cnf", Size: int64(len(data))}
	findings, _ := d.Detect(context.Background(), blob, data)
	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["TLS-CFG-PROTOCOL-WEAK"] {
		t.Errorf("expected TLS-CFG-PROTOCOL-WEAK for TLSv1 MinProtocol, got %+v", ruleIDs)
	}
}
