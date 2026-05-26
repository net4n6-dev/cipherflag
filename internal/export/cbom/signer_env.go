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
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// EnvSigner implements Signer by reading an Ed25519 private key from an
// environment variable. Two encodings are accepted:
//
//   - PEM: the env var value starts with "-----BEGIN"; delegated to newFileSignerFromPEM.
//   - Base64 (StdEncoding): any other non-empty value is decoded as standard
//     base64 and must decode to exactly ed25519.PrivateKeySize (64) bytes.
type EnvSigner struct {
	priv ed25519.PrivateKey
}

// NewEnvSigner constructs an EnvSigner from the environment variable named by
// envVar. Returns an error if the variable is unset, empty, or contains an
// invalid key.
func NewEnvSigner(envVar string) (*EnvSigner, error) {
	raw := os.Getenv(envVar)
	if raw == "" {
		return nil, fmt.Errorf("env signer: %s is empty or unset", envVar)
	}
	// PEM path: value starts with "-----BEGIN".
	if strings.HasPrefix(raw, "-----BEGIN") {
		fs, err := newFileSignerFromPEM([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("env signer: %w", err)
		}
		return &EnvSigner{priv: fs.priv}, nil
	}
	// Base64 fallback.
	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("env signer: invalid base64: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("env signer: expected %d bytes, got %d",
			ed25519.PrivateKeySize, len(privBytes))
	}
	return &EnvSigner{priv: ed25519.PrivateKey(privBytes)}, nil
}

// Algorithm implements Signer.
func (s *EnvSigner) Algorithm() string { return "Ed25519" }

// Sign implements Signer.
func (s *EnvSigner) Sign(canonical []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, canonical), nil
}

// PublicKey implements Signer.
func (s *EnvSigner) PublicKey() ([]byte, error) {
	return s.priv.Public().(ed25519.PublicKey), nil
}
