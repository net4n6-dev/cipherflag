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

// Package normalize provides shared normalization functions for SSH key types,
// crypto library names, and platform identifiers. Used by all scanners and
// ingest adapters to ensure consistent naming.
package normalize

import "strings"

// KeyType maps SSH key type strings to canonical short names.
//
//	"ssh-rsa"           → "rsa"
//	"ssh-ed25519"       → "ed25519"
//	"ecdsa-sha2-*"      → "ecdsa"
//	"ssh-dss"           → "dsa"
//	sk-* variants are resolved to their base algorithm.
//	Unknown types are returned as-is.
func KeyType(kt string) string {
	if kt == "" {
		return ""
	}
	lower := strings.ToLower(kt)
	lower = strings.TrimPrefix(lower, "sk-")
	if idx := strings.Index(lower, "@"); idx != -1 {
		lower = lower[:idx]
	}

	switch {
	case lower == "ssh-rsa":
		return "rsa"
	case lower == "ssh-ed25519":
		return "ed25519"
	case strings.HasPrefix(lower, "ecdsa-sha2-"):
		return "ecdsa"
	case lower == "ssh-dss":
		return "dsa"
	default:
		return lower
	}
}

// LibraryName maps OS package names to canonical cryptographic library names.
// Unknown packages are returned as-is.
func LibraryName(pkg string) string {
	switch pkg {
	case "openssl", "libssl3", "libssl1.1", "openssl-libs":
		return "openssl"
	case "libgnutls30", "gnutls":
		return "gnutls"
	case "libnss3", "nss":
		return "nss"
	case "libgcrypt20", "libgcrypt":
		return "libgcrypt"
	case "libsodium23", "libsodium":
		return "libsodium"
	case "libwolfssl-dev", "wolfssl":
		return "wolfssl"
	default:
		return pkg
	}
}

// Platform maps platform strings to canonical OS families.
//
//	ubuntu, centos, rhel, debian, etc. → "linux"
//	darwin, macos                       → "darwin"
//	windows, win*                       → "windows"
//	anything else is returned as-is (lowercased).
func Platform(platform string) string {
	if platform == "" {
		return ""
	}
	lower := strings.ToLower(platform)

	linuxDistros := []string{
		"ubuntu", "centos", "rhel", "debian", "fedora",
		"arch", "kali", "linux", "suse", "opensuse",
		"mint", "pop", "elementary", "manjaro", "gentoo",
	}
	for _, d := range linuxDistros {
		if lower == d {
			return "linux"
		}
	}

	darwinNames := []string{"darwin", "macos", "mac os", "osx"}
	for _, d := range darwinNames {
		if lower == d {
			return "darwin"
		}
	}

	if lower == "windows" || strings.HasPrefix(lower, "win") {
		return "windows"
	}

	return lower
}
