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

package cbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecomposeTLSSuite_TLS13Suites(t *testing.T) {
	cases := []struct {
		name                           string
		wantBulk, wantHash, wantKEX, wantSig string
		wantMode string
	}{
		{"TLS_AES_128_GCM_SHA256", "aes-128", "sha256", "", "", "gcm"},
		{"TLS_AES_256_GCM_SHA384", "aes-256", "sha384", "", "", "gcm"},
		{"TLS_CHACHA20_POLY1305_SHA256", "chacha20-poly1305", "sha256", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := DecomposeTLSSuite(tc.name)
			require.Equal(t, tc.wantBulk, d.Bulk)
			require.Equal(t, tc.wantHash, d.Hash)
			require.Equal(t, tc.wantMode, d.Mode)
		})
	}
}

func TestDecomposeTLSSuite_TLS12Suites(t *testing.T) {
	cases := []struct {
		name                           string
		wantBulk, wantHash, wantKEX, wantSig string
		wantMode string
	}{
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "aes-128", "sha256", "ecdhe", "rsa", "gcm"},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "aes-256", "sha384", "ecdhe", "ecdsa", "gcm"},
		{"TLS_RSA_WITH_AES_128_CBC_SHA", "aes-128", "sha1", "rsa", "rsa", "cbc"},
		{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "chacha20-poly1305", "sha256", "dhe", "rsa", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := DecomposeTLSSuite(tc.name)
			require.Equal(t, tc.wantBulk, d.Bulk)
			require.Equal(t, tc.wantHash, d.Hash)
			require.Equal(t, tc.wantKEX, d.KEX)
			require.Equal(t, tc.wantSig, d.Sig)
			require.Equal(t, tc.wantMode, d.Mode)
		})
	}
}

func TestDecomposeTLSSuite_UnknownSuite(t *testing.T) {
	d := DecomposeTLSSuite("TLS_UNKNOWN_NONSENSE")
	require.Empty(t, d.Bulk)
	require.Empty(t, d.Hash)
	require.False(t, d.Recognized)
}
