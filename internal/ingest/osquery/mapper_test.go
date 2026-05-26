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

package osquery_test

import (
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest/osquery"
)

// ----------------------------------------------------------------------------
// NormalizeKeyType
// ----------------------------------------------------------------------------

func TestNormalizeKeyType_DelegatesToNormalize(t *testing.T) {
	// Sanity check: the wrapper delegates to internal/normalize.
	// Full coverage lives in internal/normalize/normalize_test.go.
	if got := osquery.NormalizeKeyType("ssh-ed25519"); got != "ed25519" {
		t.Errorf("NormalizeKeyType(\"ssh-ed25519\") = %q, want \"ed25519\"", got)
	}
}

// ----------------------------------------------------------------------------
// NormalizePlatform
// ----------------------------------------------------------------------------

func TestNormalizePlatform_DelegatesToNormalize(t *testing.T) {
	// Sanity check: the wrapper delegates to internal/normalize.
	// Full coverage lives in internal/normalize/normalize_test.go.
	if got := osquery.NormalizePlatform("ubuntu"); got != "linux" {
		t.Errorf("NormalizePlatform(\"ubuntu\") = %q, want \"linux\"", got)
	}
}

// ----------------------------------------------------------------------------
// PackageToLibraryName
// ----------------------------------------------------------------------------

func TestPackageToLibraryName_DelegatesToNormalize(t *testing.T) {
	// Sanity check: the wrapper delegates to internal/normalize.
	// Full coverage lives in internal/normalize/normalize_test.go.
	if got := osquery.PackageToLibraryName("libssl3"); got != "openssl" {
		t.Errorf("PackageToLibraryName(\"libssl3\") = %q, want \"openssl\"", got)
	}
}

// ----------------------------------------------------------------------------
// MapCertificateColumns
// ----------------------------------------------------------------------------

func TestMapCertificateColumns_Basic(t *testing.T) {
	cols := map[string]string{
		"sha256_fingerprint": "AA:BB:CC:DD",
		"common_name":        "example.com",
		"issuer":             "My CA",
		"serial":             "0123456789",
		"key_algorithm":      "RSA",
		"key_strength":       "2048",
		"signing_algorithm":  "sha256WithRSAEncryption",
		"not_valid_after":    "1893456000", // 2030-01-01 00:00:00 UTC
		"not_valid_before":   "1577836800", // 2020-01-01 00:00:00 UTC
		"ca":                 "1",
		"path":               "/etc/ssl/certs/example.pem",
		"username":           "",
	}

	disc := osquery.MapCertificateColumns(cols)

	if disc.FingerprintSHA256 != "aa:bb:cc:dd" {
		t.Errorf("fingerprint not lowercased: %q", disc.FingerprintSHA256)
	}
	if disc.SubjectCN != "example.com" {
		t.Errorf("SubjectCN = %q, want %q", disc.SubjectCN, "example.com")
	}
	if disc.IssuerCN != "My CA" {
		t.Errorf("IssuerCN = %q, want %q", disc.IssuerCN, "My CA")
	}
	if disc.SerialNumber != "0123456789" {
		t.Errorf("SerialNumber = %q, want %q", disc.SerialNumber, "0123456789")
	}
	if disc.KeyAlgorithm != "RSA" {
		t.Errorf("KeyAlgorithm = %q, want %q", disc.KeyAlgorithm, "RSA")
	}
	if disc.KeySizeBits != 2048 {
		t.Errorf("KeySizeBits = %d, want 2048", disc.KeySizeBits)
	}
	if disc.SignatureAlgorithm != "sha256WithRSAEncryption" {
		t.Errorf("SignatureAlgorithm = %q", disc.SignatureAlgorithm)
	}
	if disc.IsCA != true {
		t.Error("IsCA should be true when ca=1")
	}
	if disc.FilePath != "/etc/ssl/certs/example.pem" {
		t.Errorf("FilePath = %q", disc.FilePath)
	}
	if disc.StoreType != "os_store" {
		t.Errorf("StoreType = %q, want os_store", disc.StoreType)
	}
	if disc.Source != "osquery" {
		t.Errorf("Source = %q, want osquery", disc.Source)
	}

	wantAfter := time.Unix(1893456000, 0).UTC()
	if !disc.NotAfter.Equal(wantAfter) {
		t.Errorf("NotAfter = %v, want %v", disc.NotAfter, wantAfter)
	}
	wantBefore := time.Unix(1577836800, 0).UTC()
	if !disc.NotBefore.Equal(wantBefore) {
		t.Errorf("NotBefore = %v, want %v", disc.NotBefore, wantBefore)
	}
}

func TestMapCertificateColumns_CaZero(t *testing.T) {
	cols := map[string]string{
		"ca":                 "0",
		"sha256_fingerprint": "FF:EE",
		"not_valid_after":    "0",
		"not_valid_before":   "0",
		"key_strength":       "4096",
	}
	disc := osquery.MapCertificateColumns(cols)
	if disc.IsCA {
		t.Error("IsCA should be false when ca=0")
	}
	if disc.KeySizeBits != 4096 {
		t.Errorf("KeySizeBits = %d, want 4096", disc.KeySizeBits)
	}
}

func TestMapCertificateColumns_InvalidKeyStrength(t *testing.T) {
	cols := map[string]string{
		"key_strength":       "not-a-number",
		"sha256_fingerprint": "AA",
		"not_valid_after":    "0",
		"not_valid_before":   "0",
	}
	disc := osquery.MapCertificateColumns(cols)
	// Should not panic; KeySizeBits defaults to 0
	if disc.KeySizeBits != 0 {
		t.Errorf("KeySizeBits should be 0 for invalid input, got %d", disc.KeySizeBits)
	}
}

func TestMapCertificateColumns_FingerprintAlwaysLower(t *testing.T) {
	cols := map[string]string{
		"sha256_fingerprint": "AB:CD:EF:01",
		"not_valid_after":    "0",
		"not_valid_before":   "0",
	}
	disc := osquery.MapCertificateColumns(cols)
	if disc.FingerprintSHA256 != strings.ToLower("AB:CD:EF:01") {
		t.Errorf("fingerprint not lowercased: %q", disc.FingerprintSHA256)
	}
}

// ----------------------------------------------------------------------------
// MapSSHKeyColumns
// ----------------------------------------------------------------------------

func TestMapSSHKeyColumns_Basic(t *testing.T) {
	cols := map[string]string{
		"path":        "/home/alice/.ssh/id_rsa",
		"encrypted":   "1",
		"key_type":    "ssh-rsa",
		"uid":         "1000",
		"username":    "alice",
		"fingerprint": "SHA256:AbCdEf",
		"key_size":    "4096",
	}

	disc := osquery.MapSSHKeyColumns(cols)

	if disc.FilePath != "/home/alice/.ssh/id_rsa" {
		t.Errorf("FilePath = %q", disc.FilePath)
	}
	if !disc.IsProtected {
		t.Error("IsProtected should be true when encrypted=1")
	}
	if disc.KeyType != "rsa" {
		t.Errorf("KeyType = %q, want rsa", disc.KeyType)
	}
	if disc.OwnerUser != "alice" {
		t.Errorf("OwnerUser = %q, want alice", disc.OwnerUser)
	}
	if disc.FingerprintSHA256 != "sha256:abcdef" {
		t.Errorf("FingerprintSHA256 = %q, want sha256:abcdef", disc.FingerprintSHA256)
	}
	if disc.IsAuthorized {
		t.Error("IsAuthorized should be false for user_ssh_keys")
	}
	if disc.GrantsRoot {
		t.Error("GrantsRoot should be false when uid != 0")
	}
	if disc.Source != "osquery" {
		t.Errorf("Source = %q, want osquery", disc.Source)
	}
	if disc.KeySizeBits != 4096 {
		t.Errorf("KeySizeBits = %d, want 4096", disc.KeySizeBits)
	}
}

func TestMapSSHKeyColumns_NotEncrypted(t *testing.T) {
	cols := map[string]string{
		"path":        "/root/.ssh/id_ed25519",
		"encrypted":   "0",
		"key_type":    "ssh-ed25519",
		"uid":         "0",
		"username":    "root",
		"fingerprint": "SHA256:XyZ",
	}

	disc := osquery.MapSSHKeyColumns(cols)

	if disc.IsProtected {
		t.Error("IsProtected should be false when encrypted=0")
	}
	if disc.KeyType != "ed25519" {
		t.Errorf("KeyType = %q, want ed25519", disc.KeyType)
	}
}

func TestMapSSHKeyColumns_ECDSAKeyType(t *testing.T) {
	cols := map[string]string{
		"path":        "/home/bob/.ssh/id_ecdsa",
		"encrypted":   "0",
		"key_type":    "ecdsa-sha2-nistp256",
		"uid":         "501",
		"username":    "bob",
		"fingerprint": "SHA256:Ecdsa",
	}

	disc := osquery.MapSSHKeyColumns(cols)
	if disc.KeyType != "ecdsa" {
		t.Errorf("KeyType = %q, want ecdsa", disc.KeyType)
	}
}

func TestMapSSHKeyColumns_DSAKeyType(t *testing.T) {
	cols := map[string]string{
		"path":        "/home/bob/.ssh/id_dsa",
		"encrypted":   "0",
		"key_type":    "ssh-dss",
		"uid":         "501",
		"username":    "bob",
		"fingerprint": "SHA256:Dsa",
	}

	disc := osquery.MapSSHKeyColumns(cols)
	if disc.KeyType != "dsa" {
		t.Errorf("KeyType = %q, want dsa", disc.KeyType)
	}
}

// ----------------------------------------------------------------------------
// MapAuthorizedKeyColumns
// ----------------------------------------------------------------------------

func TestMapAuthorizedKeyColumns_NonRoot(t *testing.T) {
	cols := map[string]string{
		"path":        "/home/deploy/.ssh/authorized_keys",
		"key_type":    "ssh-rsa",
		"uid":         "1001",
		"username":    "deploy",
		"fingerprint": "SHA256:AuthFp",
		"key_file":    "/home/deploy/.ssh/authorized_keys",
	}

	disc := osquery.MapAuthorizedKeyColumns(cols)

	if !disc.IsAuthorized {
		t.Error("IsAuthorized should always be true for authorized_keys")
	}
	if disc.GrantsRoot {
		t.Error("GrantsRoot should be false when uid != 0")
	}
	if disc.FilePath != "/home/deploy/.ssh/authorized_keys" {
		t.Errorf("FilePath = %q", disc.FilePath)
	}
	if disc.KeyType != "rsa" {
		t.Errorf("KeyType = %q, want rsa", disc.KeyType)
	}
	if disc.OwnerUser != "deploy" {
		t.Errorf("OwnerUser = %q, want deploy", disc.OwnerUser)
	}
	if disc.Source != "osquery" {
		t.Errorf("Source = %q, want osquery", disc.Source)
	}
}

func TestMapAuthorizedKeyColumns_Root(t *testing.T) {
	cols := map[string]string{
		"path":        "/root/.ssh/authorized_keys",
		"key_type":    "ssh-ed25519",
		"uid":         "0",
		"username":    "root",
		"fingerprint": "SHA256:RootFp",
		"key_file":    "/root/.ssh/authorized_keys",
	}

	disc := osquery.MapAuthorizedKeyColumns(cols)

	if !disc.IsAuthorized {
		t.Error("IsAuthorized should be true")
	}
	if !disc.GrantsRoot {
		t.Error("GrantsRoot should be true when uid == 0")
	}
	if disc.KeyType != "ed25519" {
		t.Errorf("KeyType = %q, want ed25519", disc.KeyType)
	}
}

func TestMapAuthorizedKeyColumns_FingerprintLowercased(t *testing.T) {
	cols := map[string]string{
		"path":        "/home/user/.ssh/authorized_keys",
		"key_type":    "ssh-rsa",
		"uid":         "1000",
		"username":    "user",
		"fingerprint": "SHA256:UPPERCASE",
		"key_file":    "/home/user/.ssh/authorized_keys",
	}

	disc := osquery.MapAuthorizedKeyColumns(cols)
	if disc.FingerprintSHA256 != "sha256:uppercase" {
		t.Errorf("FingerprintSHA256 not lowercased: %q", disc.FingerprintSHA256)
	}
}

// ----------------------------------------------------------------------------
// MapLibraryColumns
// ----------------------------------------------------------------------------

func TestMapLibraryColumns_DebPackage(t *testing.T) {
	cols := map[string]string{
		"name":    "libssl3",
		"version": "3.0.2-0ubuntu1.12",
		"path":    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
	}

	disc := osquery.MapLibraryColumns(cols, "deb")

	if disc.LibraryName != "openssl" {
		t.Errorf("LibraryName = %q, want openssl", disc.LibraryName)
	}
	if disc.PackageName != "libssl3" {
		t.Errorf("PackageName = %q, want libssl3", disc.PackageName)
	}
	if disc.Version != "3.0.2-0ubuntu1.12" {
		t.Errorf("Version = %q", disc.Version)
	}
	if disc.PackageManager != "deb" {
		t.Errorf("PackageManager = %q, want deb", disc.PackageManager)
	}
	if disc.InstallPath != "/usr/lib/x86_64-linux-gnu/libssl.so.3" {
		t.Errorf("InstallPath = %q", disc.InstallPath)
	}
	if disc.Source != "osquery" {
		t.Errorf("Source = %q, want osquery", disc.Source)
	}
	if disc.PQCCapable {
		t.Error("PQCCapable should default to false")
	}
}

func TestMapLibraryColumns_RpmPackage(t *testing.T) {
	cols := map[string]string{
		"name":    "openssl-libs",
		"version": "1:3.0.7-18.el9_2",
		"path":    "/usr/lib64/libssl.so.3",
	}

	disc := osquery.MapLibraryColumns(cols, "rpm")

	if disc.LibraryName != "openssl" {
		t.Errorf("LibraryName = %q, want openssl", disc.LibraryName)
	}
	if disc.PackageManager != "rpm" {
		t.Errorf("PackageManager = %q, want rpm", disc.PackageManager)
	}
}

func TestMapLibraryColumns_GnuTLS(t *testing.T) {
	cols := map[string]string{
		"name":    "libgnutls30",
		"version": "3.7.3-4ubuntu1.3",
		"path":    "/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
	}

	disc := osquery.MapLibraryColumns(cols, "deb")
	if disc.LibraryName != "gnutls" {
		t.Errorf("LibraryName = %q, want gnutls", disc.LibraryName)
	}
}

func TestMapLibraryColumns_NSS(t *testing.T) {
	cols := map[string]string{
		"name":    "libnss3",
		"version": "2:3.68.1-1ubuntu1",
		"path":    "/usr/lib/x86_64-linux-gnu/libnss3.so",
	}

	disc := osquery.MapLibraryColumns(cols, "deb")
	if disc.LibraryName != "nss" {
		t.Errorf("LibraryName = %q, want nss", disc.LibraryName)
	}
}

func TestMapLibraryColumns_Libgcrypt(t *testing.T) {
	cols := map[string]string{
		"name":    "libgcrypt20",
		"version": "1.9.4-3ubuntu3",
		"path":    "/usr/lib/x86_64-linux-gnu/libgcrypt.so.20",
	}

	disc := osquery.MapLibraryColumns(cols, "deb")
	if disc.LibraryName != "libgcrypt" {
		t.Errorf("LibraryName = %q, want libgcrypt", disc.LibraryName)
	}
}

func TestMapLibraryColumns_Libsodium(t *testing.T) {
	cols := map[string]string{
		"name":    "libsodium23",
		"version": "1.0.18-1",
		"path":    "/usr/lib/x86_64-linux-gnu/libsodium.so.23",
	}

	disc := osquery.MapLibraryColumns(cols, "deb")
	if disc.LibraryName != "libsodium" {
		t.Errorf("LibraryName = %q, want libsodium", disc.LibraryName)
	}
}

func TestMapLibraryColumns_Wolfssl(t *testing.T) {
	cols := map[string]string{
		"name":    "libwolfssl-dev",
		"version": "5.6.0-stable",
		"path":    "/usr/lib/libwolfssl.so",
	}

	disc := osquery.MapLibraryColumns(cols, "deb")
	if disc.LibraryName != "wolfssl" {
		t.Errorf("LibraryName = %q, want wolfssl", disc.LibraryName)
	}
}

func TestMapLibraryColumns_UnknownPackage(t *testing.T) {
	cols := map[string]string{
		"name":    "curl",
		"version": "7.81.0",
		"path":    "/usr/bin/curl",
	}

	disc := osquery.MapLibraryColumns(cols, "deb")
	// Unknown packages: LibraryName == PackageName
	if disc.LibraryName != "curl" {
		t.Errorf("LibraryName = %q, want curl (passthrough)", disc.LibraryName)
	}
}
