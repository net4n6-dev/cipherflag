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

package b1

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

type DERDetector struct{}

func (d *DERDetector) Name() string { return "b1.der" }

// derLikelyExtensions is the set of file extensions that commonly hold DER
// certs. Outside this set, we still check the ASN.1 magic bytes to catch
// renamed or extension-less files.
var derLikelyExtensions = map[string]struct{}{
	".der": {}, ".cer": {}, ".crt": {},
}

func (d *DERDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	if !looksLikeDER(data) {
		return nil, nil
	}
	// Extra guard: PEM files are handled by PEMDetector — don't double-report
	// when a PEM happens to start with bytes that look DER-ish.
	ext := strings.ToLower(filepath.Ext(b.Path))
	_, extOK := derLikelyExtensions[ext]
	if !extOK && looksLikePEM(data) {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, nil
	}
	spki := cert.RawSubjectPublicKeyInfo
	sum := sha256.Sum256(spki)
	return []finding.FindingRecord{{
		RuleID:           "KEY-MAT-CERT-IN-REPO",
		Severity:         finding.SeverityMedium,
		Bucket:           finding.BucketB1,
		Path:             b.Path,
		ByteRange:        [2]int{0, len(data)},
		Fingerprint:      "sha256:" + hex.EncodeToString(sum[:]),
		DetectedBy:       []string{"det:KEY-MAT-CERT-IN-REPO"},
		ModelAttribution: "deterministic",
		Confidence:       0.98,
		Evidence:         map[string]any{"encoding": "der"},
	}}, nil
}

// looksLikeDER checks for ASN.1 SEQUENCE with long-form length. Real
// certificates are almost always > 256 bytes, so the 0x30 0x82 prefix
// (SEQUENCE + 2-byte length) is reliable.
func looksLikeDER(data []byte) bool {
	return len(data) > 4 && data[0] == 0x30 && data[1] == 0x82
}
