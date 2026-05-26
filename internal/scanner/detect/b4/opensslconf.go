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

// Derivative work of the opensslconf plugin from cbomkit-theia
// (PQCA, Apache License 2.0). Ported into this package so CipherFlag
// can answer OpenSSL provider / FIPS-mode questions on container
// images without forking the upstream binary.
//
// Source: https://github.com/PQCA/cbomkit-theia
// License: Apache 2.0; NOTICE file in LICENSE directory of this repo.
package b4

import (
	"bufio"
	"bytes"
	"context"
	"path/filepath"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// OpensslConfDetector parses /etc/ssl/openssl.cnf (and sibling locations)
// to extract provider configuration and FIPS-mode indicators.
type OpensslConfDetector struct{}

func NewOpensslConfDetector() *OpensslConfDetector { return &OpensslConfDetector{} }

func (d *OpensslConfDetector) Name() string { return "b4.opensslconf" }

var opensslConfPaths = map[string]struct{}{
	"etc/ssl/openssl.cnf":       {},
	"etc/pki/tls/openssl.cnf":   {},
	"usr/lib/ssl/openssl.cnf":   {},
	"usr/local/ssl/openssl.cnf": {},
}

func (d *OpensslConfDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	if _, ok := opensslConfPaths[b.Path]; !ok {
		// Also accept any openssl.cnf by basename (container-specific paths).
		if filepath.Base(b.Path) != "openssl.cnf" {
			return nil, nil
		}
	}

	section := ""
	activeProviders := []string{}
	fipsMode := false
	defaultPropertyQuery := ""

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if !strings.Contains(line, "=") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		// Strip inline comments.
		if i := strings.Index(val, "#"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}

		// provider section: each key names an active provider. The value
		// is typically a section reference (e.g. `default = default_sect`)
		// or an activation literal (`activate`/`1`/`yes`). In either case
		// the provider is considered active; its absence from
		// `*provider_sect` means it is not loaded.
		if strings.HasSuffix(section, "provider_sect") {
			activeProviders = append(activeProviders, key)
		}
		// FIPS signal: fipsmodule.cnf-referenced section, or explicit fips = yes.
		if key == "fips" && strings.EqualFold(val, "yes") {
			fipsMode = true
		}
		if key == "default_properties" {
			defaultPropertyQuery = val
			if strings.Contains(val, "fips=yes") {
				fipsMode = true
			}
		}
	}

	var out []finding.FindingRecord
	if len(activeProviders) > 0 {
		out = append(out, finding.FindingRecord{
			RuleID:           "CFG-OPENSSL-PROVIDERS",
			Severity:         finding.SeverityInfo,
			Bucket:           finding.BucketB4,
			Path:             b.Path,
			DetectedBy:       []string{"det:CFG-OPENSSL-PROVIDERS"},
			ModelAttribution: "deterministic",
			Confidence:       0.98,
			Evidence: map[string]any{
				"active_providers":       activeProviders,
				"default_property_query": defaultPropertyQuery,
			},
		})
	}
	if fipsMode {
		out = append(out, finding.FindingRecord{
			RuleID:           "CFG-OPENSSL-FIPS",
			Severity:         finding.SeverityInfo,
			Bucket:           finding.BucketB4,
			Path:             b.Path,
			DetectedBy:       []string{"det:CFG-OPENSSL-FIPS"},
			ModelAttribution: "deterministic",
			Confidence:       1.0,
			Evidence: map[string]any{
				"fips_mode":              true,
				"default_property_query": defaultPropertyQuery,
			},
		})
	}
	return out, scanner.Err()
}
