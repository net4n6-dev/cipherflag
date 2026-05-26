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

// Package fpreduce provides false-positive reduction post-filters for
// scanner findings. v1 ships three operator-opt-in filters:
//   - path_context: demote findings in test/ fixtures/ etc to Info
//   - allowlist: suppress findings matching (image_digest, path, sha256)
//   - diff_from_base: demote findings also present in the upstream base
//
// This file implements the allow-list. Curated content is pre-GA work
// (see docs/roadmap.md); v1 ships with an empty seed.
package fpreduce

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// AllowlistEntry keys a benign artifact. All three fields are required
// for a match; partial matches are ignored.
type AllowlistEntry struct {
	ImageDigest string `yaml:"image_digest"` // sha256:... (the image this entry applies to)
	Path        string `yaml:"path"`         // file path inside the image
	SHA256      string `yaml:"sha256"`       // blob SHA-256
	Comment     string `yaml:"comment"`      // optional; for human curation notes
}

// Allowlist is the loaded allow-list content.
type Allowlist struct {
	entries []AllowlistEntry
}

// LoadAllowlist reads a YAML file of allow-list entries. Missing file is
// NOT an error — operators may run without an allow-list. Malformed YAML
// IS an error; fail loud so operators fix the config.
func LoadAllowlist(path string) (*Allowlist, error) {
	if path == "" {
		return &Allowlist{}, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Allowlist{}, nil
		}
		return nil, fmt.Errorf("allowlist read: %w", err)
	}
	var entries []AllowlistEntry
	if err := yaml.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("allowlist parse: %w", err)
	}
	return &Allowlist{entries: entries}, nil
}

// Allowed reports whether (imageDigest, path, sha256) matches an entry.
// Normalises digests (strips sha256: prefix and any @platform suffix) for
// comparison so entries can use either form. The pipeline's AssetID in
// container mode is "<digest>@<platform>" (per 6.2a D3); without the
// @platform strip, entries written as "sha256:abc" would never match
// assetIDs like "sha256:abc@linux/amd64".
func (a *Allowlist) Allowed(imageDigest, path, sha256 string) bool {
	iDigest := normalizeDigest(imageDigest)
	sDigest := normalizeDigest(sha256)
	for _, e := range a.entries {
		if normalizeDigest(e.ImageDigest) == iDigest &&
			e.Path == path &&
			normalizeDigest(e.SHA256) == sDigest {
			return true
		}
	}
	return false
}

// Apply filters a slice of findings, returning only those NOT on the
// allow-list. The image digest is passed in because findings don't carry
// it individually (the whole scan shares one image). When the allow-list
// is empty the input is returned unchanged.
func (a *Allowlist) Apply(findings []finding.FindingRecord, imageDigest string) []finding.FindingRecord {
	if len(a.entries) == 0 {
		return findings
	}
	out := make([]finding.FindingRecord, 0, len(findings))
	for _, f := range findings {
		// SHA-256 of the finding's source bytes lives in Fingerprint when
		// B1 emits it; for B5 findings it's often absent. Skip entries
		// without a fingerprint; the allow-list only suppresses when we
		// can confirm the (path, sha256) pair.
		if f.Fingerprint == "" {
			out = append(out, f)
			continue
		}
		if a.Allowed(imageDigest, f.Path, f.Fingerprint) {
			continue // suppressed
		}
		out = append(out, f)
	}
	return out
}

func normalizeDigest(s string) string {
	s = strings.TrimPrefix(s, "sha256:")
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	return s
}
