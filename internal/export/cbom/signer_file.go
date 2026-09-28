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
	"encoding/pem"
	"fmt"
	"os"
)

// FileSigner implements Signer by reading an Ed25519 private key from a PEM
// file. The PEM block type must be "PRIVATE KEY" or "ED25519 PRIVATE KEY" and
// the body a PKCS#8 or raw 64-byte Ed25519 key (parseEd25519PrivateKey).
type FileSigner struct {
	priv ed25519.PrivateKey
}

// NewFileSigner reads and parses the Ed25519 private key PEM at path. Every
// error names path once.
func NewFileSigner(path string) (*FileSigner, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// os.ReadFile's error already names the path.
		return nil, fmt.Errorf("file signer: %w", err)
	}
	priv, err := parseEd25519PrivateKeyPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("file signer %q: %w", path, err)
	}
	return &FileSigner{priv: priv}, nil
}

// parseEd25519PrivateKeyPEM decodes a PRIVATE KEY PEM block. Shared by
// FileSigner and EnvSigner (PEM path); its errors name no source, so each
// caller adds its own once.
func parseEd25519PrivateKeyPEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if block.Type != "PRIVATE KEY" && block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("expected Ed25519 PRIVATE KEY PEM, got %q", block.Type)
	}
	return parseEd25519PrivateKey(block.Bytes)
}

// Algorithm implements Signer.
func (s *FileSigner) Algorithm() string { return "Ed25519" }

// Sign implements Signer.
func (s *FileSigner) Sign(canonical []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, canonical), nil
}

// PublicKey implements Signer.
func (s *FileSigner) PublicKey() ([]byte, error) {
	return s.priv.Public().(ed25519.PublicKey), nil
}
