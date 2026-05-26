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

package configs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
)

func TestScanTrustBundles_NginxTwoDirectives(t *testing.T) {
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "nginx.conf")
	cfgContent := `
server {
    ssl_trusted_certificate /etc/nginx/trusted-cas.pem;
    ssl_trusted_certificate /etc/nginx/extra-cas.pem;
    ssl_certificate         /etc/nginx/leaf.crt;
}
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	s := New(&executil.OSRunner{})
	refs := s.ScanTrustBundles(context.Background(), []string{cfgPath})

	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2; refs=%+v", len(refs), refs)
	}
	for i, ref := range refs {
		if ref.Server != "nginx" {
			t.Errorf("refs[%d].Server = %q, want nginx", i, ref.Server)
		}
		if ref.ConfigPath != cfgPath {
			t.Errorf("refs[%d].ConfigPath = %q, want %q", i, ref.ConfigPath, cfgPath)
		}
		if ref.Directive != "ssl_trusted_certificate" {
			t.Errorf("refs[%d].Directive = %q, want ssl_trusted_certificate", i, ref.Directive)
		}
	}
	// BundlePaths should be distinct.
	if refs[0].BundlePath == refs[1].BundlePath {
		t.Errorf("expected distinct BundlePaths, got duplicate %q", refs[0].BundlePath)
	}
}

func TestScanTrustBundles_ApacheAndPostgres(t *testing.T) {
	dir := t.TempDir()

	apacheCfg := filepath.Join(dir, "ssl.conf")
	apacheContent := "SSLCACertificateFile /etc/ssl/certs/my-ca-bundle.pem\n"
	if err := os.WriteFile(apacheCfg, []byte(apacheContent), 0o644); err != nil {
		t.Fatalf("write apache config: %v", err)
	}

	pgCfg := filepath.Join(dir, "postgresql.conf")
	pgContent := "ssl_ca_file = '/etc/ssl/certs/pg-ca.pem'\n"
	if err := os.WriteFile(pgCfg, []byte(pgContent), 0o644); err != nil {
		t.Fatalf("write postgres config: %v", err)
	}

	s := New(&executil.OSRunner{})
	refs := s.ScanTrustBundles(context.Background(), []string{apacheCfg, pgCfg})

	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2; refs=%+v", len(refs), refs)
	}
	servers := map[string]bool{}
	for _, ref := range refs {
		servers[ref.Server] = true
	}
	if !servers["apache"] {
		t.Error("expected apache ref not found")
	}
	if !servers["postgres"] {
		t.Error("expected postgres ref not found")
	}
}

func TestScanTrustBundles_MissingPathsSkipped(t *testing.T) {
	s := New(&executil.OSRunner{})
	refs := s.ScanTrustBundles(context.Background(), []string{
		"/does/not/exist/nginx.conf",
		"/also/missing/postgresql.conf",
	})
	if len(refs) != 0 {
		t.Errorf("got %d refs, want 0 for all-missing paths; refs=%+v", len(refs), refs)
	}
}

func TestScanTrustBundles_EmptyPathList(t *testing.T) {
	s := New(&executil.OSRunner{})
	refs := s.ScanTrustBundles(context.Background(), nil)
	// Only glob expansions could add refs; on a dev machine these paths
	// likely don't exist, so we just assert no panic and the result is a
	// slice (possibly non-nil if postgres happens to be installed).
	_ = refs
}
