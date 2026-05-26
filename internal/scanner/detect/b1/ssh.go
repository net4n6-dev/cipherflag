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

	"golang.org/x/crypto/ssh"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

type SSHDetector struct{}

func (d *SSHDetector) Name() string { return "b1.ssh" }

// privKeyFileStems matches the canonical SSH private key filenames.
var privKeyFileStems = map[string]struct{}{
	"id_rsa": {}, "id_ed25519": {}, "id_ecdsa": {}, "id_dsa": {},
}

func (d *SSHDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	base := filepath.Base(b.Path)
	switch {
	case base == "authorized_keys":
		return d.detectAuthorizedKeys(b, data), nil
	case base == "known_hosts":
		return []finding.FindingRecord{{
			RuleID:           "KEY-MAT-SSH-KNOWNHOSTS-IN-REPO",
			Severity:         finding.SeverityInfo,
			Bucket:           finding.BucketB1,
			Path:             b.Path,
			ByteRange:        [2]int{0, len(data)},
			DetectedBy:       []string{"det:KEY-MAT-SSH-KNOWNHOSTS-IN-REPO"},
			ModelAttribution: "deterministic",
			Confidence:       0.9,
		}}, nil
	}

	stemMatch := false
	if _, ok := privKeyFileStems[strings.TrimSuffix(base, filepath.Ext(base))]; ok {
		stemMatch = true
	}
	armourMatch := bytes.Contains(data, []byte("-----BEGIN OPENSSH PRIVATE KEY-----"))

	// PEM-armoured private keys (including OpenSSH) are caught by PEMDetector.
	// SSHDetector defers to PEM when armour is present and only fires on
	// stem-match-without-armour to flag binary or placeholder id_* files
	// that PEM wouldn't catch. This keeps dispatcher dedup simple.
	if armourMatch {
		return nil, nil
	}
	if stemMatch {
		return []finding.FindingRecord{{
			RuleID:           "KEY-MAT-SSH-PRIVKEY-IN-REPO",
			Severity:         finding.SeverityCritical,
			Bucket:           finding.BucketB1,
			Path:             b.Path,
			ByteRange:        [2]int{0, len(data)},
			DetectedBy:       []string{"det:KEY-MAT-SSH-PRIVKEY-IN-REPO"},
			ModelAttribution: "deterministic",
			Confidence:       0.9,
			Evidence:         map[string]any{"match": "filename_stem"},
		}}, nil
	}

	return nil, nil
}

func (d *SSHDetector) detectAuthorizedKeys(b enumerate.Blob, data []byte) []finding.FindingRecord {
	var out []finding.FindingRecord
	rest := data
	byteOffset := 0
	for len(rest) > 0 {
		pub, _, _, remaining, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			if idx := bytes.IndexByte(rest, '\n'); idx >= 0 {
				rest = rest[idx+1:]
				byteOffset += idx + 1
				continue
			}
			break
		}
		consumed := len(rest) - len(remaining)
		fp := ssh.FingerprintSHA256(pub)
		out = append(out, finding.FindingRecord{
			RuleID:           "KEY-MAT-SSH-AUTHKEYS-IN-REPO",
			Severity:         finding.SeverityLow,
			Bucket:           finding.BucketB1,
			Path:             b.Path,
			ByteRange:        [2]int{byteOffset, byteOffset + consumed},
			Fingerprint:      fp,
			DetectedBy:       []string{"det:KEY-MAT-SSH-AUTHKEYS-IN-REPO"},
			ModelAttribution: "deterministic",
			Confidence:       0.95,
			Evidence:         map[string]any{"key_type": pub.Type()},
		})
		rest = remaining
		byteOffset += consumed
	}
	return out
}
