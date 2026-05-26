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

// Package assets defines the canonical string constants for the values stored
// in the asset_type columns of asset_health_reports and asset_provenance.
// Layers 0-5 currently use the raw string literals directly; new code (Layer
// 6.1 onward) should import these constants. A future refactor may migrate
// existing literals — the parity test in types_test.go guards the invariant
// that the constants remain equal to those literals.
package assets

const (
	AssetTypeCertificate   = "certificate"
	AssetTypeSSHKey        = "ssh_key"
	AssetTypeCryptoLibrary = "crypto_library"
	AssetTypeCryptoConfig  = "crypto_config"
	AssetTypeHost          = "host"

	// New in Layer 6.1a.
	AssetTypeRepository = "repository"
)

// AllTypes is the enumeration used by generic handlers and sweep queries.
var AllTypes = []string{
	AssetTypeCertificate,
	AssetTypeSSHKey,
	AssetTypeCryptoLibrary,
	AssetTypeCryptoConfig,
	AssetTypeHost,
	AssetTypeRepository,
}
