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

package truststore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

var jvmCacertsPathPatterns = []string{
	"/usr/lib/jvm/*/lib/security/cacerts",
	"/opt/java/*/lib/security/cacerts",
	"/usr/lib/jvm/default/lib/security/cacerts",
}

func discoverJVMKeystores(_ context.Context, _ *Scanner) ([]bundleObservation, error) {
	var out []bundleObservation
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		path := filepath.Join(javaHome, "lib/security/cacerts")
		if data, err := os.ReadFile(path); err == nil {
			out = append(out, bundleObservation{
				Path: path, Source: "jvm_cacerts", SourceDetail: path,
				Format: "jks", Data: data,
			})
		}
	}
	for _, pat := range jvmCacertsPathPatterns {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			data, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			out = append(out, bundleObservation{
				Path: m, Source: "jvm_cacerts", SourceDetail: m,
				Format: "jks", Data: data,
			})
		}
	}
	return out, nil
}

// mapJKS parses a JKS bundle with the password ladder; emits Trusted/Priv
// observations per the entry types in the keystore.
func (s *Scanner) mapJKS(b bundleObservation) ([]model.TrustStoreObservation, []model.PrivateKeyObservation) {
	ks, password, err := loadJKS(b.Data, s.jvmPasswords)
	if err != nil {
		log.Warn().Err(err).Str("path", b.Path).Msg("JKS load failed (password mismatch?)")
		return nil, nil
	}
	var trust []model.TrustStoreObservation
	var priv []model.PrivateKeyObservation
	for _, alias := range ks.Aliases() {
		if tce, err := ks.GetTrustedCertificateEntry(alias); err == nil {
			sum := sha256.Sum256(tce.Certificate.Content)
			trust = append(trust, model.TrustStoreObservation{
				CAFingerprint: hex.EncodeToString(sum[:]),
				Source:        b.Source,
				SourceDetail:  b.SourceDetail,
			})
			continue
		}
		if pke, err := ks.GetPrivateKeyEntry(alias, []byte(password)); err == nil {
			for _, cert := range pke.CertificateChain {
				sum := sha256.Sum256(cert.Content)
				priv = append(priv, model.PrivateKeyObservation{
					CertFingerprint: hex.EncodeToString(sum[:]),
					Evidence:        "jks_private_key_entry",
					Source:          "truststore",
					SourceDetail:    b.SourceDetail,
				})
			}
		}
	}
	return trust, priv
}

func loadJKS(data []byte, passwords []string) (keystore.KeyStore, string, error) {
	var last error
	for _, pw := range passwords {
		ks := keystore.New()
		if err := ks.Load(bytes.NewReader(data), []byte(pw)); err == nil {
			return ks, pw, nil
		} else {
			last = err
		}
	}
	return keystore.KeyStore{}, "", last
}
