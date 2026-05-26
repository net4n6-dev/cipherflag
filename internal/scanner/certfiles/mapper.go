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

import "github.com/net4n6-dev/cipherflag/internal/ingest/dedup"

// MapFindings converts cert file scanner findings to dedup.CertDiscovery
// types for the ingestion pipeline. Scanner metadata fields (FileMode,
// ModifiedAt, CertIndex) are not mapped.
func MapFindings(findings []CertFileFinding) []dedup.CertDiscovery {
	if len(findings) == 0 {
		return nil
	}
	discoveries := make([]dedup.CertDiscovery, 0, len(findings))
	for _, f := range findings {
		discoveries = append(discoveries, dedup.CertDiscovery{
			FingerprintSHA256:  f.FingerprintSHA256,
			SubjectCN:          f.SubjectCN,
			IssuerCN:           f.IssuerCN,
			SerialNumber:       f.SerialNumber,
			NotBefore:          f.NotBefore,
			NotAfter:           f.NotAfter,
			KeyAlgorithm:       f.KeyAlgorithm,
			KeySizeBits:        f.KeySizeBits,
			SignatureAlgorithm: f.SignatureAlgorithm,
			SubjectAltNames:    f.SubjectAltNames,
			IsCA:               f.IsCA,
			RawPEM:             f.RawPEM,
			FilePath:           f.FilePath,
			StoreType:          f.StoreType,
		})
	}
	return discoveries
}
