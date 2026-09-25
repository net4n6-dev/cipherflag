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

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Imported assets must use the same canonical names as scanner- and
// adapter-discovered ones (normalize.KeyType / normalize.LibraryName), or the
// inventory holds two spellings of the same key type or library and lookups
// keyed on the canonical name (analytics, FIPS library lookup) miss the import.

func TestClassifyComponent_SSHKeyType_Canonical(t *testing.T) {
	cases := []struct {
		algoRef string
		want    string
	}{
		{"algo:ed25519", "ed25519"},
		{"algo:rsa", "rsa"},
		{"algo:ecdsa-p256", "ecdsa"},
		{"algo:ecdsa-p384", "ecdsa"},
		{"algo:ecdsa-p521", "ecdsa"},
		// Our own exporter already emits canonical refs; they must survive.
		{"algo:ecdsa", "ecdsa"},
		{"algo:dsa", "dsa"},
		{"ssh-dss", "dsa"},
	}
	for _, tc := range cases {
		t.Run(tc.algoRef, func(t *testing.T) {
			got := ClassifyComponent(cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				BOMRef: "sshkey:fp1",
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						Type:         cdx.RelatedCryptoMaterialTypePublicKey,
						AlgorithmRef: cdx.BOMReference(tc.algoRef),
					},
				},
			})
			if got.Kind != KindSSHKey || got.SSHKey == nil {
				t.Fatalf("Kind = %v, want SSHKey", got.Kind)
			}
			if got.SSHKey.KeyType != tc.want {
				t.Errorf("KeyType = %q, want %q", got.SSHKey.KeyType, tc.want)
			}
		})
	}
}

func TestClassifyComponent_LibraryName_Canonical(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"libssl3", "openssl"},
		{"libssl1.1", "openssl"},
		{"openssl-libs", "openssl"},
		{"libgnutls30", "gnutls"},
		{"libnss3", "nss"},
		{"libgcrypt20", "libgcrypt"},
		{"libsodium23", "libsodium"},
		{"libwolfssl-dev", "wolfssl"},
		// Already canonical / mixed case: unchanged after lowercasing.
		{"openssl", "openssl"},
		{"OpenSSL", "openssl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyComponent(cdx.Component{
				Type:    cdx.ComponentTypeLibrary,
				BOMRef:  "lib:x",
				Name:    tc.name,
				Version: "1.0",
			})
			if got.Kind != KindLibrary || got.Lib == nil {
				t.Fatalf("Kind = %v, want Library", got.Kind)
			}
			if got.Lib.LibraryName != tc.want {
				t.Errorf("LibraryName = %q, want %q", got.Lib.LibraryName, tc.want)
			}
		})
	}
}
