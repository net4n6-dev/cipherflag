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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// DetectPKCS12 attempts each provided password against the bundle. On
// success, emits one PrivateKeyObservation{evidence='pkcs12_entry'} for
// the (cert, privateKey) pair in the bundle. Passwords list mirrors the
// JVM keystore password ladder shape.
func DetectPKCS12(ctx context.Context, path string, passwords []string) ([]model.PrivateKeyObservation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	for _, pw := range append(passwords, "") {
		_, cert, _, err := pkcs12.DecodeChain(data, pw)
		if err != nil {
			continue
		}
		if cert == nil {
			return nil, nil
		}
		sum := sha256.Sum256(cert.Raw)
		return []model.PrivateKeyObservation{{
			CertFingerprint: hex.EncodeToString(sum[:]),
			Evidence:        "pkcs12_entry",
			Source:          "certfiles",
			SourceDetail:    path,
		}}, nil
	}
	log.Warn().Str("path", path).Msg("PKCS#12 password mismatch — skipping")
	return nil, nil
}
