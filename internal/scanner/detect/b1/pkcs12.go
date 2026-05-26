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
	"path/filepath"
	"strings"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// PKCS12Detector emits a Medium "keystore in repo" finding on every .p12/.pfx
// file AND a Critical "weak-password" finding if any entry in CommonPasswords
// decrypts the keystore.
type PKCS12Detector struct {
	CommonPasswords []string
}

func (d *PKCS12Detector) Name() string { return "b1.pkcs12" }

var p12Extensions = map[string]struct{}{".p12": {}, ".pfx": {}}

func (d *PKCS12Detector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	ext := strings.ToLower(filepath.Ext(b.Path))
	if _, ok := p12Extensions[ext]; !ok {
		return nil, nil
	}

	out := []finding.FindingRecord{{
		RuleID:           "KEY-MAT-KEYSTORE-IN-REPO",
		Severity:         finding.SeverityHigh,
		Bucket:           finding.BucketB1,
		Path:             b.Path,
		ByteRange:        [2]int{0, len(data)},
		DetectedBy:       []string{"det:KEY-MAT-KEYSTORE-IN-REPO"},
		ModelAttribution: "deterministic",
		Confidence:       0.98,
		Evidence:         map[string]any{"format": "pkcs12"},
	}}

	for _, pw := range d.CommonPasswords {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if weakP12(data, pw) {
			out = append(out, finding.FindingRecord{
				RuleID:           "KEY-MAT-KEYSTORE-WEAK-PASSWORD",
				Severity:         finding.SeverityCritical,
				Bucket:           finding.BucketB1,
				Path:             b.Path,
				ByteRange:        [2]int{0, len(data)},
				DetectedBy:       []string{"det:KEY-MAT-KEYSTORE-WEAK-PASSWORD"},
				ModelAttribution: "deterministic",
				Confidence:       0.99,
				Evidence:         map[string]any{"format": "pkcs12", "matched_password_empty_or_common": true},
			})
			break
		}
	}
	return out, nil
}

// weakP12 returns true iff pw successfully decodes data as a PKCS#12.
// Any non-nil error is treated as a reject.
func weakP12(data []byte, pw string) bool {
	_, _, _, err := pkcs12.DecodeChain(data, pw)
	return err == nil
}
