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

// Package cbom generates CycloneDX 1.6 Cryptography Bill of Materials (CBOM)
// documents from scored crypto assets (target: 1.7; constrained by cyclonedx-go v0.10.0)
// and delivers them via synchronous download and operator-configured push.
package cbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/net4n6-dev/cipherflag/internal/analysis/scoring"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/rs/zerolog/log"
)

// cbomVersion is embedded in BOM metadata. Set via ldflags in release builds:
//
//	-ldflags "-X github.com/net4n6-dev/cipherflag/internal/export/cbom.cbomVersion=1.2.3"
var cbomVersion = "dev"

// NewGenerator returns a Generator with no signing configured.
// Existing callers (tests, handlers, NewRuntime) that do not need signing
// use this constructor unchanged. To enable signing, use NewGeneratorWithSigning.
// The scoring-package LibraryFIPSLevel lookup is wired in automatically.
func NewGenerator() *Generator {
	return &Generator{libraryFIPSLevel: scoring.LibraryFIPSLevel}
}

// NewGeneratorWithSigning returns a Generator that signs every emitted BOM
// when signingCfg.Enabled is true. The key material is loaded at construction
// time and the constructor fails fast if the key is absent or malformed.
//
// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13 Step 5.
func NewGeneratorWithSigning(signingCfg config.CBOMSigningConfig) (*Generator, error) {
	if !signingCfg.Enabled {
		return &Generator{}, nil
	}
	var signer Signer
	switch signingCfg.Signer {
	case "file":
		s, err := NewFileSigner(signingCfg.Path)
		if err != nil {
			return nil, fmt.Errorf("cbom: signing: %w", err)
		}
		signer = s
	case "env":
		s, err := NewEnvSigner(signingCfg.EnvVar)
		if err != nil {
			return nil, fmt.Errorf("cbom: signing: %w", err)
		}
		signer = s
	default:
		return nil, fmt.Errorf("cbom: signing: signer %q is not supported (want \"file\" or \"env\")", signingCfg.Signer)
	}
	return &Generator{signer: signer, libraryFIPSLevel: scoring.LibraryFIPSLevel}, nil
}

// NewRuntime constructs a Runtime from a store and CBOMConfig.
// Call Start(ctx) to begin background emission goroutines.
// Panics if signing is enabled but the key material is invalid — callers
// should validate config (including signing config) before calling NewRuntime.
func NewRuntime(st store.CryptoStore, cfg *config.CBOMConfig) *Runtime {
	gen, err := NewGeneratorWithSigning(cfg.Signing)
	if err != nil {
		// Fail-fast: signing misconfiguration is a startup error. The operator
		// enabled signing but provided an invalid key — surface it loudly
		// rather than silently emitting unsigned BOMs.
		panic("cbom: NewRuntime: " + err.Error())
	}

	// Startup logging: when signing is enabled, emit the public-key SHA-256
	// fingerprint so operators can verify it against their out-of-band copy.
	// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 13 Step 6.
	if gen.signer != nil {
		if pubKey, pkErr := gen.signer.PublicKey(); pkErr == nil {
			sum := sha256.Sum256(pubKey)
			log.Info().
				Str("algorithm", gen.signer.Algorithm()).
				Str("public_key_sha256", hex.EncodeToString(sum[:])).
				Msg("CBOM signing enabled — compare public_key_sha256 against your trusted copy")
		}
	}

	scopes := ScopesFromConfig(cfg.Scopes)
	byName := make(map[string]*Scope, len(scopes))
	for i := range scopes {
		byName[scopes[i].Name] = &scopes[i]
	}
	return &Runtime{
		store:       st,
		generator:   gen,
		scopes:      scopes,
		scopeByName: byName,
		dirty:       newDirtySet(),
		cfg:         cfg,
		notifyCh:    make(chan notifyEvent, 1024),
		sinkCache:   map[string]Sink{},
	}
}
