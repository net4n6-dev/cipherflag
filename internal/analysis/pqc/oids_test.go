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

package pqc

import (
	"testing"
	"github.com/stretchr/testify/require"
)

func TestOIDLookup_KnownEntries(t *testing.T) {
	cases := []struct {
		canonical string
		wantOID   string
	}{
		// Classical (RFC 5912 §6 + RFC 3279 + RFC 4055):
		{"rsa", "1.2.840.113549.1.1.1"},
		{"sha256", "2.16.840.1.101.3.4.2.1"},
		{"sha384", "2.16.840.1.101.3.4.2.2"},
		{"sha512", "2.16.840.1.101.3.4.2.3"},
		{"sha1", "1.3.14.3.2.26"},
		{"md5", "1.2.840.113549.2.5"},
		{"ecdsa", "1.2.840.10045.2.1"},
		{"ed25519", "1.3.101.112"},
		{"ed448", "1.3.101.113"},
		{"aes-128", "2.16.840.1.101.3.4.1.1"},
		{"aes-256", "2.16.840.1.101.3.4.1.41"},
		// NIST PQC (CSOR / FIPS 203/204/205):
		{"ml-kem-512", "2.16.840.1.101.3.4.4.1"},
		{"ml-kem-768", "2.16.840.1.101.3.4.4.2"},
		{"ml-kem-1024", "2.16.840.1.101.3.4.4.3"},
		{"ml-dsa-44", "2.16.840.1.101.3.4.3.17"},
		{"ml-dsa-65", "2.16.840.1.101.3.4.3.18"},
		{"ml-dsa-87", "2.16.840.1.101.3.4.3.19"},
	}
	for _, tc := range cases {
		t.Run(tc.canonical, func(t *testing.T) {
			oid, ok := OID(tc.canonical)
			require.True(t, ok, "expected OID for %q", tc.canonical)
			require.Equal(t, tc.wantOID, oid)
		})
	}
}

func TestOIDLookup_UnknownEntry(t *testing.T) {
	_, ok := OID("never-heard-of-it")
	require.False(t, ok)
}

// TestOIDCoverage_PQCStandardized fails if a NIST-standardized PQC
// algorithm lands in the catalog without an OID decision in this map.
// Drift guard.
func TestOIDCoverage_PQCStandardized(t *testing.T) {
	standardized := []string{
		"ml-kem-512", "ml-kem-768", "ml-kem-1024",
		"ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
		"slh-dsa-sha2-128s", "slh-dsa-sha2-128f",
		"slh-dsa-sha2-192s", "slh-dsa-sha2-192f",
		"slh-dsa-sha2-256s", "slh-dsa-sha2-256f",
	}
	for _, name := range standardized {
		_, ok := OID(name)
		require.True(t, ok, "OID missing for standardized PQC algo %q — extend internal/analysis/pqc/oids.go", name)
	}
}
