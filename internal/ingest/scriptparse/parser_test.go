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

package scriptparse_test

import (
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest/scriptparse"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("mustParseTime: %v", err)
	}
	return ts
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_Certificate
// ---------------------------------------------------------------------------

func TestParseNDJSON_Certificate(t *testing.T) {
	line := `{"type":"certificate","fingerprint_sha256":"abc123","subject_cn":"*.example.com","issuer_cn":"DigiCert","not_before":"2024-01-01T00:00:00Z","not_after":"2027-01-15T00:00:00Z","key_algorithm":"RSA","key_size":2048,"signature_algorithm":"sha256WithRSA","serial_number":"0A1B","file_path":"/etc/ssl/certs/ex.pem","store_type":"pem"}`

	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(line), "script", "host1")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected 0 parse errors, got %d: %v", len(errs), errs)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(result.Certificates))
	}

	c := result.Certificates[0]
	if c.FingerprintSHA256 != "abc123" {
		t.Errorf("FingerprintSHA256: got %q, want %q", c.FingerprintSHA256, "abc123")
	}
	if c.SubjectCN != "*.example.com" {
		t.Errorf("SubjectCN: got %q, want %q", c.SubjectCN, "*.example.com")
	}
	if c.IssuerCN != "DigiCert" {
		t.Errorf("IssuerCN: got %q, want %q", c.IssuerCN, "DigiCert")
	}
	if c.SerialNumber != "0A1B" {
		t.Errorf("SerialNumber: got %q, want %q", c.SerialNumber, "0A1B")
	}
	wantNotBefore := mustParseTime(t, "2024-01-01T00:00:00Z")
	if !c.NotBefore.Equal(wantNotBefore) {
		t.Errorf("NotBefore: got %v, want %v", c.NotBefore, wantNotBefore)
	}
	wantNotAfter := mustParseTime(t, "2027-01-15T00:00:00Z")
	if !c.NotAfter.Equal(wantNotAfter) {
		t.Errorf("NotAfter: got %v, want %v", c.NotAfter, wantNotAfter)
	}
	if c.KeyAlgorithm != "RSA" {
		t.Errorf("KeyAlgorithm: got %q, want %q", c.KeyAlgorithm, "RSA")
	}
	if c.KeySizeBits != 2048 {
		t.Errorf("KeySizeBits: got %d, want %d", c.KeySizeBits, 2048)
	}
	if c.SignatureAlgorithm != "sha256WithRSA" {
		t.Errorf("SignatureAlgorithm: got %q, want %q", c.SignatureAlgorithm, "sha256WithRSA")
	}
	if c.FilePath != "/etc/ssl/certs/ex.pem" {
		t.Errorf("FilePath: got %q, want %q", c.FilePath, "/etc/ssl/certs/ex.pem")
	}
	if c.StoreType != "pem" {
		t.Errorf("StoreType: got %q, want %q", c.StoreType, "pem")
	}
	if c.Source != "script" {
		t.Errorf("Source: got %q, want %q", c.Source, "script")
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_SSHKey
// ---------------------------------------------------------------------------

func TestParseNDJSON_SSHKey(t *testing.T) {
	line := `{"type":"ssh_key","fingerprint_sha256":"SHA256:abc","key_type":"ed25519","key_size":256,"file_path":"/home/admin/.ssh/id_ed25519","owner":"admin","is_protected":true,"is_authorized":false,"grants_root":false}`

	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(line), "script", "host1")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected 0 parse errors, got %d: %v", len(errs), errs)
	}
	if len(result.SSHKeys) != 1 {
		t.Fatalf("expected 1 SSH key, got %d", len(result.SSHKeys))
	}

	k := result.SSHKeys[0]
	if k.FingerprintSHA256 != "SHA256:abc" {
		t.Errorf("FingerprintSHA256: got %q, want %q", k.FingerprintSHA256, "SHA256:abc")
	}
	if k.KeyType != "ed25519" {
		t.Errorf("KeyType: got %q, want %q", k.KeyType, "ed25519")
	}
	if k.KeySizeBits != 256 {
		t.Errorf("KeySizeBits: got %d, want %d", k.KeySizeBits, 256)
	}
	if k.FilePath != "/home/admin/.ssh/id_ed25519" {
		t.Errorf("FilePath: got %q, want %q", k.FilePath, "/home/admin/.ssh/id_ed25519")
	}
	if k.OwnerUser != "admin" {
		t.Errorf("OwnerUser: got %q, want %q", k.OwnerUser, "admin")
	}
	if !k.IsProtected {
		t.Errorf("IsProtected: got false, want true")
	}
	if k.IsAuthorized {
		t.Errorf("IsAuthorized: got true, want false")
	}
	if k.GrantsRoot {
		t.Errorf("GrantsRoot: got true, want false")
	}
	if k.Source != "script" {
		t.Errorf("Source: got %q, want %q", k.Source, "script")
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_Library
// ---------------------------------------------------------------------------

func TestParseNDJSON_Library(t *testing.T) {
	line := `{"type":"library","name":"openssl","version":"3.0.14","package_name":"libssl3","package_manager":"dpkg","install_path":"/usr/lib/libssl.so.3"}`

	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(line), "script", "host1")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected 0 parse errors, got %d: %v", len(errs), errs)
	}
	if len(result.Libraries) != 1 {
		t.Fatalf("expected 1 library, got %d", len(result.Libraries))
	}

	l := result.Libraries[0]
	if l.LibraryName != "openssl" {
		t.Errorf("LibraryName: got %q, want %q", l.LibraryName, "openssl")
	}
	if l.Version != "3.0.14" {
		t.Errorf("Version: got %q, want %q", l.Version, "3.0.14")
	}
	if l.PackageName != "libssl3" {
		t.Errorf("PackageName: got %q, want %q", l.PackageName, "libssl3")
	}
	if l.PackageManager != "dpkg" {
		t.Errorf("PackageManager: got %q, want %q", l.PackageManager, "dpkg")
	}
	if l.InstallPath != "/usr/lib/libssl.so.3" {
		t.Errorf("InstallPath: got %q, want %q", l.InstallPath, "/usr/lib/libssl.so.3")
	}
	if l.Source != "script" {
		t.Errorf("Source: got %q, want %q", l.Source, "script")
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_Config
// ---------------------------------------------------------------------------

func TestParseNDJSON_Config(t *testing.T) {
	line := `{"type":"config","config_type":"sshd_config","file_path":"/etc/ssh/sshd_config","settings":{"Ciphers":"aes256-gcm@openssh.com","MACs":"hmac-sha2-256-etm@openssh.com"}}`

	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(line), "script", "host1")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected 0 parse errors, got %d: %v", len(errs), errs)
	}
	if len(result.Configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(result.Configs))
	}

	cfg := result.Configs[0]
	if cfg.ConfigType != "sshd_config" {
		t.Errorf("ConfigType: got %q, want %q", cfg.ConfigType, "sshd_config")
	}
	if cfg.FilePath != "/etc/ssh/sshd_config" {
		t.Errorf("FilePath: got %q, want %q", cfg.FilePath, "/etc/ssh/sshd_config")
	}
	if cfg.Source != "script" {
		t.Errorf("Source: got %q, want %q", cfg.Source, "script")
	}
	if cfg.Settings == nil {
		t.Fatal("Settings map is nil")
	}
	if v, ok := cfg.Settings["Ciphers"]; !ok || v != "aes256-gcm@openssh.com" {
		t.Errorf("Settings[Ciphers]: got %q, want %q", v, "aes256-gcm@openssh.com")
	}
	if v, ok := cfg.Settings["MACs"]; !ok || v != "hmac-sha2-256-etm@openssh.com" {
		t.Errorf("Settings[MACs]: got %q, want %q", v, "hmac-sha2-256-etm@openssh.com")
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_MultipleAssets
// ---------------------------------------------------------------------------

func TestParseNDJSON_MultipleAssets(t *testing.T) {
	input := strings.Join([]string{
		`{"type":"certificate","fingerprint_sha256":"fp1","subject_cn":"a.com","issuer_cn":"CA","not_before":"2024-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","key_algorithm":"RSA","key_size":2048,"signature_algorithm":"sha256WithRSA","serial_number":"01","file_path":"/a.pem","store_type":"pem"}`,
		`{"type":"ssh_key","fingerprint_sha256":"SHA256:xyz","key_type":"rsa","key_size":4096,"file_path":"/root/.ssh/id_rsa","owner":"root","is_protected":false,"is_authorized":true,"grants_root":true}`,
		`{"type":"library","name":"libgcrypt","version":"1.10.1","package_name":"libgcrypt20","package_manager":"dpkg","install_path":"/usr/lib/libgcrypt.so"}`,
		`{"type":"config","config_type":"openssl.cnf","file_path":"/etc/ssl/openssl.cnf","settings":{}}`,
	}, "\n")

	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(input), "script", "host1")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected 0 parse errors, got %d: %v", len(errs), errs)
	}
	if len(result.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(result.Certificates))
	}
	if len(result.SSHKeys) != 1 {
		t.Errorf("expected 1 SSH key, got %d", len(result.SSHKeys))
	}
	if len(result.Libraries) != 1 {
		t.Errorf("expected 1 library, got %d", len(result.Libraries))
	}
	if len(result.Configs) != 1 {
		t.Errorf("expected 1 config, got %d", len(result.Configs))
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_MalformedLineSkipped
// ---------------------------------------------------------------------------

func TestParseNDJSON_MalformedLineSkipped(t *testing.T) {
	input := strings.Join([]string{
		`{"type":"library","name":"openssl","version":"3.0.14","package_name":"libssl3","package_manager":"dpkg","install_path":"/usr/lib/libssl.so.3"}`,
		`{not valid json`,
		`{"type":"library","name":"libgcrypt","version":"1.10.1","package_name":"libgcrypt20","package_manager":"dpkg","install_path":"/usr/lib/libgcrypt.so"}`,
	}, "\n")

	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(input), "script", "host1")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 parse error, got %d: %v", len(errs), errs)
	}
	if errs[0].Line != 2 {
		t.Errorf("error line: got %d, want 2", errs[0].Line)
	}
	if len(result.Libraries) != 2 {
		t.Errorf("expected 2 libraries, got %d", len(result.Libraries))
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_UnknownType
// ---------------------------------------------------------------------------

func TestParseNDJSON_UnknownType(t *testing.T) {
	line := `{"type":"unknown_asset","foo":"bar"}`

	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(line), "script", "host1")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 parse error, got %d", len(errs))
	}
	if errs[0].Line != 1 {
		t.Errorf("error line: got %d, want 1", errs[0].Line)
	}
	// No assets should be added
	if len(result.Certificates)+len(result.SSHKeys)+len(result.Libraries)+len(result.Configs) != 0 {
		t.Errorf("expected 0 assets for unknown type")
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_MissingRequiredFields
// ---------------------------------------------------------------------------

func TestParseNDJSON_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "certificate missing fingerprint_sha256",
			input: `{"type":"certificate","subject_cn":"a.com","issuer_cn":"CA","not_before":"2024-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","key_algorithm":"RSA","key_size":2048,"signature_algorithm":"sha256WithRSA","serial_number":"01","file_path":"/a.pem","store_type":"pem"}`,
		},
		{
			name:  "ssh_key missing file_path",
			input: `{"type":"ssh_key","fingerprint_sha256":"SHA256:xyz","key_type":"ed25519","key_size":256,"owner":"admin","is_protected":true,"is_authorized":false,"grants_root":false}`,
		},
		{
			name:  "library missing name",
			input: `{"type":"library","version":"3.0.14","package_name":"libssl3","package_manager":"dpkg","install_path":"/usr/lib/libssl.so.3"}`,
		},
		{
			name:  "library missing version",
			input: `{"type":"library","name":"openssl","package_name":"libssl3","package_manager":"dpkg","install_path":"/usr/lib/libssl.so.3"}`,
		},
		{
			name:  "config missing config_type",
			input: `{"type":"config","file_path":"/etc/ssh/sshd_config","settings":{}}`,
		},
		{
			name:  "config missing file_path",
			input: `{"type":"config","config_type":"sshd_config","settings":{}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(tc.input), "script", "host1")
			if err != nil {
				t.Fatalf("unexpected fatal error: %v", err)
			}
			if len(errs) != 1 {
				t.Fatalf("expected 1 parse error for missing required field, got %d", len(errs))
			}
			total := len(result.Certificates) + len(result.SSHKeys) + len(result.Libraries) + len(result.Configs)
			if total != 0 {
				t.Errorf("expected 0 assets for missing required field, got %d", total)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_EmptyInput
// ---------------------------------------------------------------------------

func TestParseNDJSON_EmptyInput(t *testing.T) {
	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(""), "myscript", "myhost")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected 0 parse errors, got %d", len(errs))
	}
	if result.Source != "myscript" {
		t.Errorf("Source: got %q, want %q", result.Source, "myscript")
	}
	if result.Hostname != "myhost" {
		t.Errorf("Hostname: got %q, want %q", result.Hostname, "myhost")
	}
	total := len(result.Certificates) + len(result.SSHKeys) + len(result.Libraries) + len(result.Configs)
	if total != 0 {
		t.Errorf("expected 0 assets for empty input, got %d", total)
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_BlankLines
// ---------------------------------------------------------------------------

func TestParseNDJSON_BlankLines(t *testing.T) {
	input := strings.Join([]string{
		"",
		`{"type":"library","name":"openssl","version":"3.0.14","package_name":"libssl3","package_manager":"dpkg","install_path":"/usr/lib/libssl.so.3"}`,
		"",
		"   ",
		`{"type":"library","name":"libgcrypt","version":"1.10.1","package_name":"libgcrypt20","package_manager":"dpkg","install_path":"/usr/lib/libgcrypt.so"}`,
		"",
	}, "\n")

	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(input), "script", "host1")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected 0 parse errors from blank lines, got %d: %v", len(errs), errs)
	}
	if len(result.Libraries) != 2 {
		t.Errorf("expected 2 libraries, got %d", len(result.Libraries))
	}
}

// ---------------------------------------------------------------------------
// TestParseNDJSON_SourceAndHostnameSet
// ---------------------------------------------------------------------------

func TestParseNDJSON_SourceAndHostnameSet(t *testing.T) {
	line := `{"type":"library","name":"openssl","version":"3.0.14","package_name":"libssl3","package_manager":"dpkg","install_path":"/usr/lib/libssl.so.3"}`

	result, errs, err := scriptparse.ParseNDJSON(strings.NewReader(line), "discovery-script-v2", "db-server-01")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected 0 parse errors, got %d", len(errs))
	}
	if result.Source != "discovery-script-v2" {
		t.Errorf("Source: got %q, want %q", result.Source, "discovery-script-v2")
	}
	if result.Hostname != "db-server-01" {
		t.Errorf("Hostname: got %q, want %q", result.Hostname, "db-server-01")
	}
	// Also verify the per-asset Source is propagated
	if len(result.Libraries) == 1 && result.Libraries[0].Source != "discovery-script-v2" {
		t.Errorf("Libraries[0].Source: got %q, want %q", result.Libraries[0].Source, "discovery-script-v2")
	}
}
