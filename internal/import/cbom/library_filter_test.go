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

package cbomimport

import "testing"

func TestIsCryptoLibrary(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// Exact canonical names
		{"openssl", true},
		{"boringssl", true},
		{"gnutls", true},
		{"nss", true},
		{"libsodium", true},
		{"wolfssl", true},
		{"bouncycastle", true},
		{"libressl", true},
		{"mbedtls", true},
		{"nettle", true},
		{"libgcrypt", true},

		// Debian-style package naming
		{"libssl1.1", true},
		{"libssl3", true},
		{"libgnutls30", true},
		{"libnss3", true},
		{"libgcrypt20", true},
		{"libsodium23", true},
		{"libwolfssl-dev", true},

		// Homebrew/versioned naming
		{"openssl@3", true},
		{"openssl-libs", true},

		// Case insensitive
		{"OpenSSL", true},
		{"OPENSSL", true},
		{"GnuTLS", true},

		// Empty and whitespace
		{"", false},
		{"   ", false},

		// Non-crypto libraries that should NOT match
		{"lodash", false},
		{"express", false},
		{"requests", false},
		{"numpy", false},
		{"jackson-databind", false},
		{"zlib", false},
		{"curl", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCryptoLibrary(tt.name); got != tt.want {
				t.Errorf("IsCryptoLibrary(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
