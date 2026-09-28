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

package main

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
)

// checkCBOMSigning loads the [cbom.signing] key, the only place serve reads
// it, and returns the signer (nil when signing is disabled). serve builds one
// Generator from it for the CBOM runtime and every CBOM download handler, so
// all of them sign with the key logged here. When signing is enabled but the
// key cannot be loaded it exits the process with one line naming the key and
// the way out, before the database is touched (a bad key used to get serve
// past startup and panic in a constructor, which crash-loops a container
// under `restart: unless-stopped`).
//
// With a loadable key it logs the public key's fingerprint for operators to
// compare against their out-of-band record. It is logged here because this
// runs whenever signing is enabled; the CBOM runtime is built only when
// [cbom] enabled is true, but the API download handlers sign regardless.
//
// Ported from CipherFlag EE (rm:0795).
func checkCBOMSigning(cfg config.CBOMSigningConfig) cbom.Signer {
	signer, err := cbom.LoadSigner(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("[cbom.signing] is enabled but its key cannot be loaded; fix the key or set [cbom.signing] enabled = false")
	}
	if signer == nil {
		return nil
	}
	pub, err := signer.PublicKey()
	if err != nil {
		log.Fatal().Err(err).Msg("[cbom.signing] is enabled but its public key cannot be derived")
	}
	sum := sha256.Sum256(pub)
	log.Info().
		Str("algorithm", signer.Algorithm()).
		Str("public_key_sha256", hex.EncodeToString(sum[:])).
		Msg("CBOM signing enabled; compare public_key_sha256 against your trusted copy")
	return signer
}
