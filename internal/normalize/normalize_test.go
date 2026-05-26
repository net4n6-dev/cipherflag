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

package normalize

import "testing"

func TestNormalizeKeyType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ssh-rsa", "rsa"},
		{"ssh-ed25519", "ed25519"},
		{"ecdsa-sha2-nistp256", "ecdsa"},
		{"ecdsa-sha2-nistp384", "ecdsa"},
		{"ecdsa-sha2-nistp521", "ecdsa"},
		{"ssh-dss", "dsa"},
		{"RSA", "rsa"},
		{"sk-ssh-ed25519@openssh.com", "ed25519"},
		{"sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa"},
		{"", ""},
		{"unknown-type", "unknown-type"},
	}

	for _, tt := range tests {
		got := KeyType(tt.input)
		if got != tt.want {
			t.Errorf("KeyType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeLibraryName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"openssl", "openssl"},
		{"libssl3", "openssl"},
		{"libssl1.1", "openssl"},
		{"openssl-libs", "openssl"},
		{"libgnutls30", "gnutls"},
		{"gnutls", "gnutls"},
		{"libnss3", "nss"},
		{"nss", "nss"},
		{"libgcrypt20", "libgcrypt"},
		{"libgcrypt", "libgcrypt"},
		{"libsodium23", "libsodium"},
		{"libsodium", "libsodium"},
		{"libwolfssl-dev", "wolfssl"},
		{"wolfssl", "wolfssl"},
		{"unknown-pkg", "unknown-pkg"},
	}

	for _, tt := range tests {
		got := LibraryName(tt.input)
		if got != tt.want {
			t.Errorf("LibraryName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizePlatform(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ubuntu", "linux"},
		{"centos", "linux"},
		{"rhel", "linux"},
		{"debian", "linux"},
		{"fedora", "linux"},
		{"arch", "linux"},
		{"kali", "linux"},
		{"linux", "linux"},
		{"darwin", "darwin"},
		{"macos", "darwin"},
		{"windows", "windows"},
		{"win10", "windows"},
		{"", ""},
		{"freebsd", "freebsd"},
	}

	for _, tt := range tests {
		got := Platform(tt.input)
		if got != tt.want {
			t.Errorf("Platform(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
