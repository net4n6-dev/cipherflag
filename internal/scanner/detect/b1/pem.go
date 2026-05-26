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

// Package b1 detects committed cryptographic key material.
package b1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// PEMDetector parses ASCII-armoured blocks: certs, private keys, and CSRs.
// Multiple blocks in one file produce multiple findings.
type PEMDetector struct{}

func (d *PEMDetector) Name() string { return "b1.pem" }

func (d *PEMDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	if !looksLikePEM(data) {
		return nil, nil
	}
	var out []finding.FindingRecord
	rest := data
	lineOffset := 1
	byteOffset := 0
	for {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		// Locate the BEGIN marker in `rest` so the ByteRange points at the
		// PEM block proper, not whatever garbage preceded it. pem.Decode
		// happily skips garbage; bytes.Index gives us the real start.
		beginIdx := bytes.Index(rest, []byte("-----BEGIN"))
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		consumed := len(rest) - len(remaining)
		if beginIdx < 0 {
			beginIdx = 0
		}
		blockStartLine := lineOffset
		blockEndLine := lineOffset + strings.Count(string(rest[:consumed]), "\n")
		blockStartByte := byteOffset + beginIdx
		blockEndByte := byteOffset + consumed

		switch {
		case block.Type == "CERTIFICATE":
			out = append(out, buildCertFinding(b.Path, block.Bytes, blockStartLine, blockEndLine, blockStartByte, blockEndByte))
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			out = append(out, buildPrivateKeyFinding(b.Path, block, blockStartLine, blockEndLine, blockStartByte, blockEndByte))
		case block.Type == "CERTIFICATE REQUEST":
			out = append(out, finding.FindingRecord{
				RuleID:           "KEY-MAT-CSR-IN-REPO",
				Severity:         finding.SeverityMedium,
				Bucket:           finding.BucketB1,
				Path:             b.Path,
				LineRange:        [2]int{blockStartLine, blockEndLine},
				ByteRange:        [2]int{blockStartByte, blockEndByte},
				DetectedBy:       []string{"det:KEY-MAT-CSR-IN-REPO"},
				ModelAttribution: "deterministic",
				Confidence:       0.95,
			})
		}
		rest = remaining
		lineOffset = blockEndLine + 1
		byteOffset = blockEndByte
	}
	return out, nil
}

func buildCertFinding(path string, der []byte, startLine, endLine, startByte, endByte int) finding.FindingRecord {
	f := finding.FindingRecord{
		RuleID:           "KEY-MAT-CERT-IN-REPO",
		Severity:         finding.SeverityMedium,
		Bucket:           finding.BucketB1,
		Path:             path,
		LineRange:        [2]int{startLine, endLine},
		ByteRange:        [2]int{startByte, endByte},
		DetectedBy:       []string{"det:KEY-MAT-CERT-IN-REPO"},
		ModelAttribution: "deterministic",
		Confidence:       0.98,
	}
	if cert, err := x509.ParseCertificate(der); err == nil {
		// SHA-256 of SubjectPublicKeyInfo — matches Layer 2/3 convention (spec §4).
		spki := cert.RawSubjectPublicKeyInfo
		sum := sha256.Sum256(spki)
		f.Fingerprint = "sha256:" + hex.EncodeToString(sum[:])
	}
	return f
}

func buildPrivateKeyFinding(path string, block *pem.Block, startLine, endLine, startByte, endByte int) finding.FindingRecord {
	// Any private key in a repo is Critical regardless of encryption state —
	// encrypted keys are also a leak (the key material is still recoverable
	// given the passphrase, which is often committed alongside).
	return finding.FindingRecord{
		RuleID:           "KEY-MAT-PRIVKEY-IN-REPO",
		Severity:         finding.SeverityCritical,
		Bucket:           finding.BucketB1,
		Path:             path,
		LineRange:        [2]int{startLine, endLine},
		ByteRange:        [2]int{startByte, endByte},
		Evidence:         map[string]any{"pem_type": block.Type, "encrypted": isEncryptedPEM(block)},
		DetectedBy:       []string{"det:KEY-MAT-PRIVKEY-IN-REPO"},
		ModelAttribution: "deterministic",
		Confidence:       0.99,
	}
}

// Quick heuristic: files not containing "-----BEGIN" are definitely not PEM.
func looksLikePEM(data []byte) bool {
	return strings.Contains(string(data), "-----BEGIN ")
}

func isEncryptedPEM(block *pem.Block) bool {
	_, ok := block.Headers["DEK-Info"]
	return ok
}
