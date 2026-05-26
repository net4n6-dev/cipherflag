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

package assets

import "testing"

// TestAssetTypeConstants_MatchInternalLiterals guards against a constant drifting
// away from the raw string literals used across Layers 0–5 (which are not yet
// migrated to use these constants). When future work migrates those sites to the
// constants, they must pass the exact string values here.
func TestAssetTypeConstants_MatchInternalLiterals(t *testing.T) {
	cases := map[string]string{
		"certificate":    AssetTypeCertificate,
		"ssh_key":        AssetTypeSSHKey,
		"crypto_library": AssetTypeCryptoLibrary,
		"crypto_config":  AssetTypeCryptoConfig,
		"host":           AssetTypeHost,
		"repository":     AssetTypeRepository,
	}
	for want, got := range cases {
		if got != want {
			t.Errorf("expected constant value %q, got %q", want, got)
		}
	}
}

// TestAllTypes_ContainsRepository ensures the exported slice (used by future
// enumeration code in 6.1b handlers) includes the new repository type.
func TestAllTypes_ContainsRepository(t *testing.T) {
	var found bool
	for _, tp := range AllTypes {
		if tp == AssetTypeRepository {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("AllTypes must include AssetTypeRepository")
	}
}
