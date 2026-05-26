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

// Signer abstracts the Ed25519 signing operation so that key material can be
// sourced from a file (FileSigner) or an environment variable (EnvSigner)
// without the CBOM generation pipeline being aware of the difference.
type Signer interface {
	// Algorithm returns the JWA algorithm name, e.g. "Ed25519".
	Algorithm() string

	// Sign returns the raw signature over canonical (the JCS-canonicalized BOM
	// bytes). The caller is responsible for encoding the result as needed.
	Sign(canonical []byte) ([]byte, error)

	// PublicKey returns the raw public key bytes corresponding to the signing key.
	// For Ed25519 this is the 32-byte public key.
	PublicKey() ([]byte, error)
}
