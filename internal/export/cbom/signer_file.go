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
// the block body must be exactly ed25519.PrivateKeySize (64) bytes.
type FileSigner struct {
	priv ed25519.PrivateKey
}

// NewFileSigner reads and parses the Ed25519 private key PEM at path.
func NewFileSigner(path string) (*FileSigner, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file signer: read %q: %w", path, err)
	}
	return newFileSignerFromPEM(raw)
}

// newFileSignerFromPEM is shared by FileSigner and EnvSigner (PEM path).
func newFileSignerFromPEM(pemBytes []byte) (*FileSigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("file signer: no PEM block")
	}
	if block.Type != "PRIVATE KEY" && block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("file signer: expected Ed25519 PRIVATE KEY PEM, got %q", block.Type)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("file signer: Ed25519 key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(block.Bytes))
	}
	return &FileSigner{priv: ed25519.PrivateKey(block.Bytes)}, nil
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
