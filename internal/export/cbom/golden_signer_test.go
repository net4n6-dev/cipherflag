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
	"crypto/ed25519"
	"crypto/sha256"
)

// goldenFixtureSigner is the fixed key the golden CBOM tests sign with, so
// the signature block's publicKey is byte-stable across runs (the
// signature value itself is scrubbed). It is derived from a public seed at
// test time rather than committed as a private key file:
//
//	seed = SHA-256("cipherflag-golden-cbom-fixture-v1")
//	key  = ed25519.NewKeyFromSeed(seed)
//
// This is exactly the key that testdata/golden/fixture-signing.key held
// (public key 145ecff4...d99d18b9), so the goldens are unchanged. It has no
// purpose outside these tests.
func goldenFixtureSigner() *FileSigner {
	seed := sha256.Sum256([]byte("cipherflag-golden-cbom-fixture-v1"))
	return &FileSigner{priv: ed25519.NewKeyFromSeed(seed[:])}
}
