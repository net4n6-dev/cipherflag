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

// cbomVersion is the CipherFlag version embedded in every BOM's
// metadata.tools and in the CBOM push User-Agent. serve sets it from its
// Version at startup (SetToolVersion); "dev" remains only in tests and
// programs that never call it.
var cbomVersion = "dev"

// SetToolVersion records the CipherFlag version that BOMs name as their
// producing tool. Call once at startup, before any BOM is generated. An
// empty version is ignored.
func SetToolVersion(version string) {
	if version != "" {
		cbomVersion = version
	}
}

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
	return NewGeneratorFromSigner(signer), nil
}

// NewGeneratorFromSigner returns a Generator that signs with signer, or an
// unsigned one when signer is nil. serve loads the key once (LoadSigner, in
// its startup check) and hands the one Generator to the CBOM runtime and
// every CBOM download handler, so all of them sign with the key it logged
// and none reads the key file again. A Generator is safe for concurrent use.
func NewGeneratorFromSigner(signer Signer) *Generator {
	g := NewGenerator()
	g.signer = signer
	return g
}

// NewRuntime constructs a Runtime from a store, CBOMConfig and the Generator
// every emitted BOM is built (and signed) with. Call Start(ctx) to begin
// background emission goroutines.
func NewRuntime(st store.CryptoStore, cfg *config.CBOMConfig, gen *Generator) *Runtime {
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
