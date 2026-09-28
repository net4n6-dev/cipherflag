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
	"fmt"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

// LoadSigner is the one place [cbom.signing] key material is loaded. It
// returns (nil, nil) when signing is disabled, the signer when the key
// loads, and otherwise an error naming, once, the key file, environment
// variable or signer type the operator has to fix (the signers name their
// own source, so LoadSigner does not add it again). NewGeneratorWithSigning reaches
// its verdict through it, and serve calls it once at startup so a bad key
// stops the process before the database is touched.
//
// Ported from CipherFlag EE (rm:0795).
func LoadSigner(cfg config.CBOMSigningConfig) (Signer, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	switch cfg.Signer {
	case "file":
		s, err := NewFileSigner(cfg.Path)
		if err != nil {
			return nil, err
		}
		return s, nil
	case "env":
		s, err := NewEnvSigner(cfg.EnvVar)
		if err != nil {
			return nil, err
		}
		return s, nil
	default:
		return nil, fmt.Errorf("signer %q is not supported (want \"file\" or \"env\")", cfg.Signer)
	}
}
