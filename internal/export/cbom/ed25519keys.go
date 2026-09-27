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
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Ed25519 key bodies for signing keys. Every reader of a signing or trusted
// key goes through parseEd25519PrivateKey or ParseEd25519PublicKey, so the
// accepted formats cannot drift between the file signer, the env signer and
// the trusted-key loader.
//
// Two encodings are accepted, under the usual "PRIVATE KEY" and
// "PUBLIC KEY" PEM labels:
//   - standard: PKCS#8 private keys and SPKI public keys, as written by
//     `openssl genpkey -algorithm ed25519` and `openssl pkey -pubout`, HSMs,
//     cloud KMS exports and EE 4.11+;
//   - raw: Go's 64-byte ed25519.PrivateKey and 32-byte ed25519.PublicKey,
//     as written by earlier versions of `cipherflag generate-signing-key`.
//
// Ported from CipherFlag EE (rm:0796).

// parseEd25519PrivateKey decodes a PKCS#8 or raw 64-byte Ed25519 private
// key. A raw key must be internally consistent: its second half is the
// public key of its first half, because ed25519.Sign embeds that half in
// every signature and a mismatched key signs with a public key no verifier
// will accept.
func parseEd25519PrivateKey(der []byte) (ed25519.PrivateKey, error) {
	key, pkcs8Err := x509.ParsePKCS8PrivateKey(der)
	if pkcs8Err == nil {
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is %T, want an Ed25519 key", key)
		}
		return priv, nil
	}
	if len(der) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key is neither PKCS#8 Ed25519 nor a raw %d-byte Ed25519 key (got %d bytes)%s",
			ed25519.PrivateKeySize, len(der), derReason("PKCS#8", der, pkcs8Err))
	}
	priv := ed25519.NewKeyFromSeed(der[:ed25519.SeedSize])
	if !bytes.Equal(priv[ed25519.SeedSize:], der[ed25519.SeedSize:]) {
		return nil, fmt.Errorf("raw Ed25519 key is inconsistent: its public half does not match its seed")
	}
	return priv, nil
}

// ParseEd25519PublicKey decodes an SPKI or raw 32-byte Ed25519 public key.
func ParseEd25519PublicKey(der []byte) (ed25519.PublicKey, error) {
	key, spkiErr := x509.ParsePKIXPublicKey(der)
	if spkiErr == nil {
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("SPKI key is %T, want an Ed25519 key", key)
		}
		return pub, nil
	}
	if len(der) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key is neither SPKI Ed25519 nor a raw %d-byte Ed25519 key (got %d bytes)%s",
			ed25519.PublicKeySize, len(der), derReason("SPKI", der, spkiErr))
	}
	return ed25519.PublicKey(bytes.Clone(der)), nil
}

// LoadTrustedKeys reads each PEM file into an ed25519.PublicKey. The block
// must be a "PUBLIC KEY" holding an SPKI or raw 32-byte Ed25519 key
// (ParseEd25519PublicKey). Fails fast on the first unreadable or undecodable
// key, naming its file, so a misconfiguration is reported rather than
// compared against garbage bytes.
func LoadTrustedKeys(paths []string) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("trusted key %q: %w", p, err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("trusted key %q: no PEM block", p)
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("trusted key %q: expected PUBLIC KEY PEM, got %q", p, block.Type)
		}
		pub, err := ParseEd25519PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trusted key %q: %w", p, err)
		}
		keys = append(keys, pub)
	}
	return keys, nil
}

// derReason keeps the x509 parser's reason when the bytes look like DER (an
// ASN.1 SEQUENCE), so a malformed or unusual PKCS#8/SPKI key says why it was
// refused instead of only reporting its length.
func derReason(format string, der []byte, err error) string {
	if len(der) == 0 || der[0] != 0x30 || err == nil {
		return ""
	}
	return fmt.Sprintf("; %s parse: %v", format, err)
}
