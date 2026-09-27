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
	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
)

// checkCBOMSigning exits the process when [cbom.signing] is enabled but its
// key cannot be loaded. The CBOM runtime and the CBOM download handlers load
// the key while they are constructed and panic if it fails; without this
// check a bad key got serve past startup and then panicked in whichever
// constructor ran first, which crash-loops a container under
// `restart: unless-stopped`. Called before the database is touched, so the
// operator gets one line naming the key and the way out.
//
// Ported from CipherFlag EE (rm:0795).
func checkCBOMSigning(cfg config.CBOMSigningConfig) {
	if _, err := cbom.LoadSigner(cfg); err != nil {
		log.Fatal().Err(err).Msg("[cbom.signing] is enabled but its key cannot be loaded; fix the key or set [cbom.signing] enabled = false")
	}
}
