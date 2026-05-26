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
	"runtime"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func TestScanSSHDConfig(t *testing.T) {
	s := New(&executil.OSRunner{})
	finding, err := s.ScanSSHDConfig(context.Background(), filepath.Join(testdataDir(), "sshd_config"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected non-nil finding")
	}
	if finding.ConfigType != "sshd_config" {
		t.Errorf("ConfigType = %q", finding.ConfigType)
	}
	if finding.Settings["Ciphers"] != "aes256-gcm@openssh.com,aes128-gcm@openssh.com" {
		t.Errorf("Ciphers = %q", finding.Settings["Ciphers"])
	}
	if finding.Settings["MACs"] != "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com" {
		t.Errorf("MACs = %q", finding.Settings["MACs"])
	}
	if finding.Settings["KexAlgorithms"] != "curve25519-sha256,diffie-hellman-group16-sha512" {
		t.Errorf("KexAlgorithms = %q", finding.Settings["KexAlgorithms"])
	}
	// Drop-in should override: PasswordAuthentication yes → no
	if finding.Settings["PasswordAuthentication"] != "no" {
		t.Errorf("PasswordAuthentication = %q, want no (drop-in override)", finding.Settings["PasswordAuthentication"])
	}
}

func TestScanOpenSSLConfig(t *testing.T) {
	s := New(&executil.OSRunner{})
	finding, err := s.ScanOpenSSLConfig(context.Background(), filepath.Join(testdataDir(), "openssl.cnf"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected non-nil finding")
	}
	if finding.ConfigType != "openssl_cnf" {
		t.Errorf("ConfigType = %q", finding.ConfigType)
	}
	if finding.Settings["default_bits"] != "4096" {
		t.Errorf("default_bits = %q", finding.Settings["default_bits"])
	}
	if finding.Settings["default_md"] != "sha256" {
		t.Errorf("default_md = %q", finding.Settings["default_md"])
	}
	if finding.Settings["fips"] != "enabled" {
		t.Errorf("fips = %q, want enabled", finding.Settings["fips"])
	}
}

func TestScanJavaSecurity(t *testing.T) {
	s := New(&executil.OSRunner{})
	finding, err := s.ScanJavaSecurity(context.Background(), filepath.Join(testdataDir(), "java.security"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected non-nil finding")
	}
	if finding.ConfigType != "java_security" {
		t.Errorf("ConfigType = %q", finding.ConfigType)
	}
	if finding.Settings["keystore.type"] != "pkcs12" {
		t.Errorf("keystore.type = %q", finding.Settings["keystore.type"])
	}
	if finding.Settings["jdk.tls.disabledAlgorithms"] == "" {
		t.Error("expected jdk.tls.disabledAlgorithms to be set")
	}
}

func TestScanNginxSSL(t *testing.T) {
	s := New(&executil.OSRunner{})
	finding, err := s.ScanNginxSSL(context.Background(), filepath.Join(testdataDir(), "nginx.conf"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected non-nil finding")
	}
	if finding.ConfigType != "nginx_ssl" {
		t.Errorf("ConfigType = %q", finding.ConfigType)
	}
	if finding.Settings["ssl_protocols"] != "TLSv1.2 TLSv1.3" {
		t.Errorf("ssl_protocols = %q", finding.Settings["ssl_protocols"])
	}
	if finding.Settings["ssl_prefer_server_ciphers"] != "on" {
		t.Errorf("ssl_prefer_server_ciphers = %q", finding.Settings["ssl_prefer_server_ciphers"])
	}
}

func TestScanApacheSSL(t *testing.T) {
	s := New(&executil.OSRunner{})
	finding, err := s.ScanApacheSSL(context.Background(), filepath.Join(testdataDir(), "apache-ssl.conf"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected non-nil finding")
	}
	if finding.ConfigType != "apache_ssl" {
		t.Errorf("ConfigType = %q", finding.ConfigType)
	}
	if finding.Settings["SSLProtocol"] != "all -SSLv3 -TLSv1 -TLSv1.1" {
		t.Errorf("SSLProtocol = %q", finding.Settings["SSLProtocol"])
	}
}

func TestScanSSHDConfig_NonExistent(t *testing.T) {
	s := New(&executil.OSRunner{})
	finding, err := s.ScanSSHDConfig(context.Background(), "/nonexistent/sshd_config")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if finding != nil {
		t.Error("expected nil finding for missing file")
	}
}

func TestScanSSHDConfig_PermissionDenied(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "sshd_config")
	if err := os.WriteFile(path, []byte("Port 22\n"), 0000); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Skip if running as root (root bypasses permission checks).
	if os.Geteuid() == 0 {
		t.Skip("cannot test permission denied as root")
	}

	s := New(&executil.OSRunner{})
	_, err := s.ScanSSHDConfig(context.Background(), path)
	if err == nil {
		t.Error("expected error for permission-denied file")
	}
}
