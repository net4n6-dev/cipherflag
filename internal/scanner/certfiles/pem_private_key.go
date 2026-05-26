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

package certfiles

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// SPKILookup answers "is there a cert in inventory whose SPKI matches this
// private key's public part?" Implemented by *store.PostgresStore at
// runtime via the certificates.spki_fingerprint_sha256 index.
type SPKILookup interface {
	CertFingerprintBySPKI(ctx context.Context, spkiFingerprint string) (certFingerprint string, found bool)
}

// privateKeyPEMTypes are the BEGIN ... PRIVATE KEY block types we accept.
var privateKeyPEMTypes = map[string]bool{
	"PRIVATE KEY":         true, // PKCS#8
	"RSA PRIVATE KEY":     true,
	"EC PRIVATE KEY":      true,
	"DSA PRIVATE KEY":     true,
	"ED25519 PRIVATE KEY": true,
}

// DetectPEMPrivateKey reads a candidate PEM file, finds any private-key
// blocks, computes the public SPKI fingerprint of each, and emits one
// PrivateKeyObservation per cert in inventory whose SPKI matches. No
// match → no emission (cert may simply not have been scanned yet; the
// next scan cycle will retry).
func DetectPEMPrivateKey(ctx context.Context, path string, lookup SPKILookup) ([]model.PrivateKeyObservation, error) {
	if lookup == nil {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var out []model.PrivateKeyObservation
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !privateKeyPEMTypes[block.Type] {
			continue
		}
		key, err := parsePrivateKey(block)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Str("type", block.Type).Msg("private-key parse failed")
			continue
		}
		spki, err := model.PrivateKeySPKIFingerprint(key)
		if err != nil {
			log.Warn().Err(err).Msg("SPKI fingerprint failed")
			continue
		}
		certFP, ok := lookup.CertFingerprintBySPKI(ctx, spki)
		if !ok {
			continue
		}
		out = append(out, model.PrivateKeyObservation{
			CertFingerprint: certFP,
			Evidence:        "colocated_pem",
			Source:          "certfiles",
			SourceDetail:    path,
		})
	}
	return out, nil
}

func parsePrivateKey(block *pem.Block) (any, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}
