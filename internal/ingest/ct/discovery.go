// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ct

import (
	"fmt"

	"github.com/net4n6-dev/cipherflag/internal/certparse"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
)

// BuildCertDiscovery converts one CTEntry into the dedup.CertDiscovery
// the ingest pipeline consumes, by fully parsing entry.PEM with
// certparse — the same parse the standalone ct_crtsh poller performs.
// This is the single mapping used by the ct_certspotter, ct_static and
// ct_multi pollers.
//
// Why it exists: the dedup layer copies CertDiscovery fields straight
// into model.Certificate, and the risk scorer (internal/analysis/
// scorer.go) grades KeyAlgorithm/KeySizeBits/SignatureAlgorithm. The
// three pollers previously built CertDiscovery from CTEntry's summary
// fields only, leaving those (plus SerialNumber and IsCA) at their zero
// values — so e.g. an RSA-1024 or SHA-1-signed cert found only via
// CertSpotter silently skipped weak-key/weak-signature scoring.
//
// Every certificate field is taken from the parsed bytes, not from the
// CTEntry summary (FingerprintSHA256 is recomputed from the DER; IssuerCN
// is the issuer's CN, not a provider's free-form issuer string). The
// caller supplies source/storeType and layers any source-specific fields
// (FilePath, RawMetadata) on the result. An error means the PEM is absent
// or unparseable; callers skip that entry.
func BuildCertDiscovery(entry CTEntry, source, storeType string) (dedup.CertDiscovery, error) {
	if len(entry.PEM) == 0 {
		return dedup.CertDiscovery{}, fmt.Errorf("ct: BuildCertDiscovery: entry %q (source %q) has no PEM", entry.Fingerprint, entry.Source)
	}
	parsed, err := certparse.ParsePEM(entry.PEM)
	if err != nil {
		return dedup.CertDiscovery{}, fmt.Errorf("ct: BuildCertDiscovery: entry %q (source %q): %w", entry.Fingerprint, entry.Source, err)
	}
	return dedup.CertDiscovery{
		Source:             source,
		StoreType:          storeType,
		FingerprintSHA256:  parsed.FingerprintSHA256,
		SubjectCN:          parsed.Subject.CommonName,
		IssuerCN:           parsed.Issuer.CommonName,
		SerialNumber:       parsed.SerialNumber,
		NotBefore:          parsed.NotBefore,
		NotAfter:           parsed.NotAfter,
		KeyAlgorithm:       string(parsed.KeyAlgorithm),
		KeySizeBits:        parsed.KeySizeBits,
		SignatureAlgorithm: string(parsed.SignatureAlgorithm),
		SubjectAltNames:    parsed.SubjectAltNames,
		IsCA:               parsed.IsCA,
		RawPEM:             string(entry.PEM),
	}, nil
}
