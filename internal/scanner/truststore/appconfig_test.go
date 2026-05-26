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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTrustBundleDirectives_NginxAndApache(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "api.conf")
	payload := `# example
server {
    ssl_trusted_certificate /etc/nginx/trusted-cas.pem;
    ssl_certificate         /etc/nginx/leaf.crt;
    SSLCACertificateFile    /etc/apache/cas.pem
}
`
	if err := os.WriteFile(cfg, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ParseTrustBundleDirectives(cfg)
	if len(got) != 2 {
		t.Fatalf("got %d refs, want 2; refs=%+v", len(got), got)
	}
	foundNginx, foundApache := false, false
	for _, ref := range got {
		if ref.Server == "nginx" && ref.BundlePath == "/etc/nginx/trusted-cas.pem" {
			foundNginx = true
		}
		if ref.Server == "apache" && ref.BundlePath == "/etc/apache/cas.pem" {
			foundApache = true
		}
	}
	if !foundNginx || !foundApache {
		t.Errorf("missing refs; foundNginx=%v foundApache=%v", foundNginx, foundApache)
	}
}

func TestParseTrustBundleDirectives_MissingFileReturnsNil(t *testing.T) {
	got := ParseTrustBundleDirectives("/does/not/exist.conf")
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

// makePEMBundleN generates n self-signed CA certs and returns the PEM bytes.
func makePEMBundleN(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	now := time.Now()
	for i := 0; i < n; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: "test-ca-" + string(rune('a'+i))},
			NotBefore:             now,
			NotAfter:              now.Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("x509.CreateCertificate: %v", err)
		}
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
			t.Fatalf("pem.Encode: %v", err)
		}
	}
	return buf.Bytes()
}

func TestIngestAppConfigBundles_ThreeCerts(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "trusted-cas.pem")
	pemData := makePEMBundleN(t, 3)
	if err := os.WriteFile(bundlePath, pemData, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	refs := []TrustBundleRef{
		{
			Server:     "nginx",
			ConfigPath: "/etc/nginx/nginx.conf",
			Directive:  "ssl_trusted_certificate",
			BundlePath: bundlePath,
		},
	}

	obs, err := IngestAppConfigBundles(refs)
	if err != nil {
		t.Fatalf("IngestAppConfigBundles error: %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("got %d observations, want 3", len(obs))
	}
	wantDetail := "nginx:/etc/nginx/nginx.conf:ssl_trusted_certificate"
	for i, o := range obs {
		if o.Source != "app_config" {
			t.Errorf("obs[%d].Source = %q, want app_config", i, o.Source)
		}
		if o.SourceDetail != wantDetail {
			t.Errorf("obs[%d].SourceDetail = %q, want %q", i, o.SourceDetail, wantDetail)
		}
		if len(o.CAFingerprint) != 64 {
			t.Errorf("obs[%d].CAFingerprint len = %d, want 64 (hex SHA256)", i, len(o.CAFingerprint))
		}
		// HostID is stamped by the caller — must be empty here.
		if o.HostID != "" {
			t.Errorf("obs[%d].HostID = %q, want empty (caller stamps it)", i, o.HostID)
		}
	}
}

func TestIngestAppConfigBundles_MultiRef(t *testing.T) {
	dir := t.TempDir()

	bundle1 := filepath.Join(dir, "bundle1.pem")
	bundle2 := filepath.Join(dir, "bundle2.pem")
	if err := os.WriteFile(bundle1, makePEMBundleN(t, 2), 0o644); err != nil {
		t.Fatalf("write bundle1: %v", err)
	}
	if err := os.WriteFile(bundle2, makePEMBundleN(t, 1), 0o644); err != nil {
		t.Fatalf("write bundle2: %v", err)
	}

	cfgPath := "/etc/postgresql/postgresql.conf"
	refs := []TrustBundleRef{
		{Server: "nginx", ConfigPath: "/etc/nginx/nginx.conf",
			Directive: "ssl_trusted_certificate", BundlePath: bundle1},
		{Server: "postgres", ConfigPath: cfgPath,
			Directive: "ssl_ca_file", BundlePath: bundle2},
	}

	obs, err := IngestAppConfigBundles(refs)
	if err != nil {
		t.Fatalf("IngestAppConfigBundles error: %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("got %d observations, want 3 (2+1)", len(obs))
	}
	sourcesDetail := map[string]int{}
	for _, o := range obs {
		sourcesDetail[o.SourceDetail]++
		if o.Source != "app_config" {
			t.Errorf("Source = %q, want app_config", o.Source)
		}
	}
	if sourcesDetail["nginx:/etc/nginx/nginx.conf:ssl_trusted_certificate"] != 2 {
		t.Errorf("nginx ref count = %d, want 2", sourcesDetail["nginx:/etc/nginx/nginx.conf:ssl_trusted_certificate"])
	}
	if sourcesDetail["postgres:"+cfgPath+":ssl_ca_file"] != 1 {
		t.Errorf("postgres ref count = %d, want 1", sourcesDetail["postgres:"+cfgPath+":ssl_ca_file"])
	}
}

func TestIngestAppConfigBundles_MissingBundleSkipped(t *testing.T) {
	refs := []TrustBundleRef{
		{Server: "nginx", ConfigPath: "/etc/nginx/nginx.conf",
			Directive: "ssl_trusted_certificate", BundlePath: "/does/not/exist.pem"},
	}
	obs, err := IngestAppConfigBundles(refs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("got %d observations, want 0 for missing bundle", len(obs))
	}
}

func TestIngestAppConfigBundles_NonCertBlocksIgnored(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "mixed.pem")
	pemData := makePEMBundleN(t, 1)
	// Append a non-CERTIFICATE block — should be silently skipped.
	pemData = append(pemData, []byte("-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n")...)
	if err := os.WriteFile(bundlePath, pemData, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	refs := []TrustBundleRef{
		{Server: "apache", ConfigPath: "/etc/apache2/ssl.conf",
			Directive: "SSLCACertificateFile", BundlePath: bundlePath},
	}
	obs, err := IngestAppConfigBundles(refs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(obs) != 1 {
		t.Errorf("got %d observations, want 1 (non-cert block must be skipped)", len(obs))
	}
	if !strings.Contains(obs[0].SourceDetail, "apache") {
		t.Errorf("SourceDetail = %q, expected to contain 'apache'", obs[0].SourceDetail)
	}
}
