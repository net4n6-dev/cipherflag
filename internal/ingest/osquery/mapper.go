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

// Package osquery provides column-mapping functions that convert osquery result
// rows (map[string]string from FleetDM webhooks) into CipherFlag discovery
// types for use with the deduplication layer.
package osquery

import (
	"strconv"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/normalize"
)

// MapCertificateColumns converts an osquery `certificates` table row into a
// dedup.CertDiscovery. Fingerprints are lowercased. Timestamps are parsed from
// Unix epoch strings. StoreType is always "os_store".
func MapCertificateColumns(cols map[string]string) dedup.CertDiscovery {
	return dedup.CertDiscovery{
		FingerprintSHA256:  strings.ToLower(cols["sha256_fingerprint"]),
		SubjectCN:          cols["common_name"],
		IssuerCN:           cols["issuer"],
		SerialNumber:       cols["serial"],
		NotBefore:          parseUnixTimestamp(cols["not_valid_before"]),
		NotAfter:           parseUnixTimestamp(cols["not_valid_after"]),
		KeyAlgorithm:       cols["key_algorithm"],
		KeySizeBits:        parseInt(cols["key_strength"]),
		SignatureAlgorithm: cols["signing_algorithm"],
		IsCA:               cols["ca"] == "1",
		FilePath:           cols["path"],
		StoreType:          "os_store",
		Source:             "osquery",
	}
}

// MapSSHKeyColumns converts an osquery `user_ssh_keys` table row into a
// dedup.SSHKeyDiscovery. The `encrypted` column maps "1" → IsProtected=true.
// KeyType is normalized via NormalizeKeyType. IsAuthorized is always false.
func MapSSHKeyColumns(cols map[string]string) dedup.SSHKeyDiscovery {
	return dedup.SSHKeyDiscovery{
		KeyType:           NormalizeKeyType(cols["key_type"]),
		KeySizeBits:       parseInt(cols["key_size"]),
		FingerprintSHA256: strings.ToLower(cols["fingerprint"]),
		FilePath:          cols["path"],
		OwnerUser:         cols["username"],
		IsAuthorized:      false,
		IsProtected:       cols["encrypted"] == "1",
		GrantsRoot:        false,
		Comment:           cols["comment"],
		Source:            "osquery",
	}
}

// MapAuthorizedKeyColumns converts an osquery `authorized_keys` table row into
// a dedup.SSHKeyDiscovery. IsAuthorized is always true. GrantsRoot is true
// when the uid column equals "0".
func MapAuthorizedKeyColumns(cols map[string]string) dedup.SSHKeyDiscovery {
	// Prefer key_file for the path; fall back to path.
	filePath := cols["key_file"]
	if filePath == "" {
		filePath = cols["path"]
	}

	return dedup.SSHKeyDiscovery{
		KeyType:           NormalizeKeyType(cols["key_type"]),
		KeySizeBits:       parseInt(cols["key_size"]),
		FingerprintSHA256: strings.ToLower(cols["fingerprint"]),
		FilePath:          filePath,
		OwnerUser:         cols["username"],
		IsAuthorized:      true,
		IsProtected:       false,
		GrantsRoot:        cols["uid"] == "0",
		Comment:           cols["comment"],
		Source:            "osquery",
	}
}

// MapLibraryColumns converts an osquery `deb_packages` or `rpm_packages` table
// row into a dedup.LibraryDiscovery. pkgManager should be "deb" or "rpm".
// The package name is mapped to a canonical library name via PackageToLibraryName.
func MapLibraryColumns(cols map[string]string, pkgManager string) dedup.LibraryDiscovery {
	pkgName := cols["name"]
	return dedup.LibraryDiscovery{
		LibraryName:    PackageToLibraryName(pkgName),
		Version:        cols["version"],
		PackageName:    pkgName,
		PackageManager: pkgManager,
		InstallPath:    cols["path"],
		PQCCapable:     false,
		Source:         "osquery",
	}
}

// NormalizeKeyType maps SSH key type strings to canonical short names.
//
//	"ssh-rsa"           → "rsa"
//	"ssh-ed25519"       → "ed25519"
//	"ecdsa-sha2-*"      → "ecdsa"
//	"ssh-dss"           → "dsa"
//	sk-* variants are resolved to their base algorithm.
//	Unknown types are returned as-is.
func NormalizeKeyType(kt string) string {
	return normalize.KeyType(kt)
}

// NormalizePlatform maps platform strings to canonical OS families.
//
//	ubuntu, centos, rhel, debian, fedora, arch, kali, linux → "linux"
//	darwin, macos                                           → "darwin"
//	windows, win*                                           → "windows"
//	anything else is returned as-is (lowercased).
func NormalizePlatform(platform string) string {
	return normalize.Platform(platform)
}

// PackageToLibraryName maps OS package names to canonical cryptographic library
// names. Unknown packages are returned as-is.
func PackageToLibraryName(pkg string) string {
	return normalize.LibraryName(pkg)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// parseUnixTimestamp converts a Unix epoch string to time.Time (UTC).
// Returns zero time on parse failure.
func parseUnixTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(ts, 0).UTC()
}

// parseInt parses a decimal integer string. Returns 0 on failure.
func parseInt(s string) int {
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}
