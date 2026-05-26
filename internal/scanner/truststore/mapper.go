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
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"

	"github.com/rs/zerolog/log"
	pkcs12lib "software.sslmate.com/src/go-pkcs12"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/model"
)

// mapBundle decodes a single bundleObservation per its Format.
func (s *Scanner) mapBundle(b bundleObservation) ([]model.TrustStoreObservation, []model.PrivateKeyObservation) {
	switch b.Format {
	case "pem":
		return s.mapPEM(b), nil
	case "der":
		return s.mapDER(b), nil
	case "jks":
		return s.mapJKS(b)
	case "pkcs12":
		return s.mapPKCS12(b)
	}
	return nil, nil
}

func (s *Scanner) mapPEM(b bundleObservation) []model.TrustStoreObservation {
	var out []model.TrustStoreObservation
	rest := b.Data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := certparse.ParseDER(block.Bytes)
		if err != nil {
			log.Warn().Err(err).Str("source", b.SourceDetail).Msg("PEM cert parse failed")
			continue
		}
		out = append(out, model.TrustStoreObservation{
			CAFingerprint: cert.FingerprintSHA256,
			Source:        b.Source,
			SourceDetail:  b.SourceDetail,
		})
	}
	return out
}

func (s *Scanner) mapDER(b bundleObservation) []model.TrustStoreObservation {
	cert, err := certparse.ParseDER(b.Data)
	if err != nil {
		log.Warn().Err(err).Str("source", b.SourceDetail).Msg("DER cert parse failed")
		return nil
	}
	return []model.TrustStoreObservation{{
		CAFingerprint: cert.FingerprintSHA256,
		Source:        b.Source,
		SourceDetail:  b.SourceDetail,
	}}
}

// mapPKCS12 routes per Source. Trust-bundle sources (os_bundle, app_config,
// jvm_cacerts, lang_runtime) treat all certs in the bundle as trust
// declarations. Key-bundle sources are anything else (currently no such
// source exists for the truststore scanner; this branch is reserved for
// when certfiles delegates PKCS#12 parsing here — for now, default to
// trust-bundle interpretation).
func (s *Scanner) mapPKCS12(b bundleObservation) ([]model.TrustStoreObservation, []model.PrivateKeyObservation) {
	var trust []model.TrustStoreObservation
	var priv []model.PrivateKeyObservation
	for _, pw := range append(s.jvmPasswords, "") {
		_, cert, caCerts, err := pkcs12lib.DecodeChain(b.Data, pw)
		if err != nil {
			continue
		}
		if isTrustBundleSource(b.Source) {
			if cert != nil {
				sum := sha256.Sum256(cert.Raw)
				trust = append(trust, model.TrustStoreObservation{
					CAFingerprint: hex.EncodeToString(sum[:]),
					Source:        b.Source, SourceDetail: b.SourceDetail,
				})
			}
			for _, c := range caCerts {
				sum := sha256.Sum256(c.Raw)
				trust = append(trust, model.TrustStoreObservation{
					CAFingerprint: hex.EncodeToString(sum[:]),
					Source:        b.Source, SourceDetail: b.SourceDetail,
				})
			}
		} else {
			if cert != nil {
				sum := sha256.Sum256(cert.Raw)
				priv = append(priv, model.PrivateKeyObservation{
					CertFingerprint: hex.EncodeToString(sum[:]),
					Evidence:        "pkcs12_entry",
					Source:          "truststore",
					SourceDetail:    b.SourceDetail,
				})
			}
			// caCerts from key-bundles intentionally not written to trust store.
		}
		return trust, priv
	}
	log.Warn().Str("path", b.Path).Msg("PKCS#12 password mismatch — skipping")
	return nil, nil
}

func isTrustBundleSource(src string) bool {
	return src == "os_bundle" || src == "app_config" || src == "jvm_cacerts" || src == "lang_runtime"
}
