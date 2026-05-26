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

// Package b4 detects weak crypto in TLS/crypto config files.
package b4

import (
	"bufio"
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// TLSConfigDetector covers nginx, apache, envoy, haproxy, caddy, OpenSSL (.cnf),
// and java.security — all single-concern: detect weak TLS protocols + weak
// cipher suites + cert references for cross-correlation.
type TLSConfigDetector struct{}

func (d *TLSConfigDetector) Name() string { return "b4.tls_config" }

// Matches: ssl_protocols / SSLProtocol / MinProtocol — any line that declares
// accepted TLS protocols.
var protocolLineRe = regexp.MustCompile(`(?i)(ssl_protocols|sslprotocol|minprotocol)\s*[= ]\s*(.+)$`)

// Weak protocol tokens (case-insensitive).
var weakProtocols = map[string]struct{}{
	"sslv2": {}, "sslv3": {}, "tlsv1": {}, "tlsv1.0": {}, "tlsv1.1": {},
}

// Matches: ssl_ciphers / SSLCipherSuite / ssl-default-bind-ciphers.
var cipherLineRe = regexp.MustCompile(`(?i)(ssl_ciphers|sslciphersuite|ssl-default-bind-ciphers|cipherstring|ciphers)\s*[= ]\s*(.+)$`)

// Weak cipher tokens substring-matched within the cipher-list value.
var weakCipherTokens = []string{"rc4", "3des", "des-cbc", "export", "null", "md5", "adh", "aecdh"}

// MatchesPath returns true when the blob path is one we should parse.
var tlsConfigPathMatchers = []func(string) bool{
	func(p string) bool {
		return strings.Contains(p, "/nginx") || (strings.HasSuffix(filepath.Base(p), ".conf") && strings.Contains(p, "nginx"))
	},
	func(p string) bool { return strings.Contains(p, "/apache") || strings.Contains(p, "/httpd") },
	func(p string) bool { return strings.HasPrefix(filepath.Base(p), "envoy") },
	func(p string) bool { return strings.Contains(p, "haproxy") },
	func(p string) bool { return strings.Contains(filepath.Base(p), "Caddyfile") },
	func(p string) bool {
		base := filepath.Base(p)
		return strings.HasSuffix(base, ".cnf") && strings.Contains(strings.ToLower(base), "openssl")
	},
	func(p string) bool {
		return filepath.Base(p) == "java.security" || strings.HasSuffix(p, "/security/java.security")
	},
}

func (d *TLSConfigDetector) MatchesPath(p string) bool {
	for _, m := range tlsConfigPathMatchers {
		if m(p) {
			return true
		}
	}
	return false
}

func (d *TLSConfigDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	if !d.MatchesPath(b.Path) {
		return nil, nil
	}
	var out []finding.FindingRecord
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		if m := protocolLineRe.FindStringSubmatch(line); len(m) == 3 {
			for _, tok := range tokenize(m[2]) {
				if _, weak := weakProtocols[strings.ToLower(tok)]; weak {
					out = append(out, finding.FindingRecord{
						RuleID:           "TLS-CFG-PROTOCOL-WEAK",
						Severity:         finding.SeverityHigh,
						Bucket:           finding.BucketB4,
						Path:             b.Path,
						LineRange:        [2]int{lineNum, lineNum},
						DetectedBy:       []string{"det:TLS-CFG-PROTOCOL-WEAK"},
						ModelAttribution: "deterministic",
						Confidence:       0.95,
						Evidence:         map[string]any{"token": tok, "directive": m[1]},
					})
				}
			}
		}
		if m := cipherLineRe.FindStringSubmatch(line); len(m) == 3 {
			for _, tok := range weakCipherTokens {
				if strings.Contains(strings.ToLower(m[2]), tok) {
					out = append(out, finding.FindingRecord{
						RuleID:           "TLS-CFG-CIPHER-WEAK",
						Severity:         finding.SeverityMedium,
						Bucket:           finding.BucketB4,
						Path:             b.Path,
						LineRange:        [2]int{lineNum, lineNum},
						DetectedBy:       []string{"det:TLS-CFG-CIPHER-WEAK"},
						ModelAttribution: "deterministic",
						Confidence:       0.9,
						Evidence:         map[string]any{"token": tok, "directive": m[1]},
					})
				}
			}
		}
	}
	return out, scanner.Err()
}

// tokenize splits on whitespace, semicolons, colons; strips quotes/punctuation.
func tokenize(s string) []string {
	s = strings.ReplaceAll(s, ";", " ")
	s = strings.ReplaceAll(s, "+", " ")
	s = strings.ReplaceAll(s, "-", " ")
	s = strings.ReplaceAll(s, ":", " ")
	parts := strings.Fields(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimFunc(p, func(r rune) bool { return r == '"' || r == '\'' })
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
