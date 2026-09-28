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
	"fmt"

	"github.com/net4n6-dev/cipherflag/internal/analysis/scoring"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/store"
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
	signer, err := LoadSigner(signingCfg)
	if err != nil {
		return nil, fmt.Errorf("cbom: signing: %w", err)
	}
	g := NewGenerator()
	g.signer = signer
	return g, nil
}

// NewRuntime constructs a Runtime from a store and CBOMConfig.
// Call Start(ctx) to begin background emission goroutines.
// Panics if signing is enabled but the key cannot be loaded. serve checks
// the key with LoadSigner first and exits cleanly on an error
// (checkCBOMSigning in cmd/cipherflag), so the panic is only a backstop.
func NewRuntime(st store.CryptoStore, cfg *config.CBOMConfig) *Runtime {
	gen, err := NewGeneratorWithSigning(cfg.Signing)
	if err != nil {
		// Backstop only: never emit unsigned BOMs while signing is enabled.
		panic("cbom: NewRuntime: " + err.Error())
	}

	// The signing-key fingerprint is logged by serve's startup check
	// (checkCBOMSigning), which runs whenever signing is enabled; logging it
	// here too would miss configs without the runtime and double it with.

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
