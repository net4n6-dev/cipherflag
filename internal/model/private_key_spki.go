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

package model

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// PrivateKeySPKIFingerprint returns hex-encoded SHA-256 of the
// SubjectPublicKeyInfo DER derived from the private key's public part.
// Used to match a discovered private-key file to its corresponding cert
// via certificates.spki_fingerprint_sha256.
func PrivateKeySPKIFingerprint(k any) (string, error) {
	var pub any
	switch v := k.(type) {
	case *rsa.PrivateKey:
		pub = &v.PublicKey
	case *ecdsa.PrivateKey:
		pub = &v.PublicKey
	case ed25519.PrivateKey:
		pub = v.Public()
	default:
		return "", fmt.Errorf("unsupported private key type: %T", k)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:]), nil
}
