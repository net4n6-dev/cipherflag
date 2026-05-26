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
	"bytes"
	"context"
	"path/filepath"
	"strings"

	"github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

type JKSDetector struct {
	CommonPasswords []string
}

func (d *JKSDetector) Name() string { return "b1.jks" }

var jksExtensions = map[string]struct{}{".jks": {}, ".keystore": {}}

// JKS files always start with a 4-byte magic: 0xFEEDFEED.
var jksMagic = []byte{0xFE, 0xED, 0xFE, 0xED}

func (d *JKSDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	ext := strings.ToLower(filepath.Ext(b.Path))
	_, extMatch := jksExtensions[ext]
	magicMatch := len(data) >= 4 && bytes.Equal(data[:4], jksMagic)
	if !extMatch && !magicMatch {
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
		Evidence:         map[string]any{"format": "jks"},
	}}

	for _, pw := range d.CommonPasswords {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		ks := keystore.New()
		err := ks.Load(bytes.NewReader(data), []byte(pw))
		if err == nil {
			out = append(out, finding.FindingRecord{
				RuleID:           "KEY-MAT-KEYSTORE-WEAK-PASSWORD",
				Severity:         finding.SeverityCritical,
				Bucket:           finding.BucketB1,
				Path:             b.Path,
				ByteRange:        [2]int{0, len(data)},
				DetectedBy:       []string{"det:KEY-MAT-KEYSTORE-WEAK-PASSWORD"},
				ModelAttribution: "deterministic",
				Confidence:       0.99,
				Evidence:         map[string]any{"format": "jks"},
			})
			break
		}
	}
	return out, nil
}
