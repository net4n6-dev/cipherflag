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

package b4

import (
	"bufio"
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// ManifestDetector covers K8s manifests, Dockerfiles, and systemd unit files.
type ManifestDetector struct{}

func (d *ManifestDetector) Name() string { return "b4.manifests" }

func (d *ManifestDetector) MatchesPath(p string) bool {
	base := filepath.Base(p)
	switch {
	case strings.HasSuffix(base, ".yaml"), strings.HasSuffix(base, ".yml"):
		return true
	case strings.HasPrefix(base, "Dockerfile"):
		return true
	case strings.HasSuffix(base, ".service"), strings.HasSuffix(base, ".socket"), strings.HasSuffix(base, ".timer"):
		return true
	}
	return false
}

func (d *ManifestDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	if !d.MatchesPath(b.Path) {
		return nil, nil
	}
	base := filepath.Base(b.Path)
	switch {
	case strings.HasPrefix(base, "Dockerfile"):
		return d.detectDockerfile(b, data), nil
	case strings.HasSuffix(base, ".service"), strings.HasSuffix(base, ".socket"), strings.HasSuffix(base, ".timer"):
		return d.detectSystemd(b, data), nil
	default:
		return d.detectK8s(b, data), nil
	}
}

func (d *ManifestDetector) detectK8s(b enumerate.Blob, data []byte) []finding.FindingRecord {
	docs := bytes.Split(data, []byte("\n---"))
	var out []finding.FindingRecord
	for _, doc := range docs {
		var m struct {
			Kind string `yaml:"kind"`
			Type string `yaml:"type"`
		}
		if err := yaml.Unmarshal(doc, &m); err != nil || m.Kind != "Secret" {
			continue
		}
		if m.Type == "kubernetes.io/tls" {
			out = append(out, finding.FindingRecord{
				RuleID:           "K8S-TLS-SECRET-IN-REPO",
				Severity:         finding.SeverityCritical,
				Bucket:           finding.BucketB4,
				Path:             b.Path,
				DetectedBy:       []string{"det:K8S-TLS-SECRET-IN-REPO"},
				ModelAttribution: "deterministic",
				Confidence:       0.98,
			})
		}
	}
	return out
}

var dockerfileCopyRe = regexp.MustCompile(`(?m)^(?:COPY|ADD)\s+(\S+)\s+\S+`)
var keyMaterialExtRe = regexp.MustCompile(`\.(pem|crt|cer|der|key|p12|pfx|jks|keystore)$`)

func (d *ManifestDetector) detectDockerfile(b enumerate.Blob, data []byte) []finding.FindingRecord {
	var out []finding.FindingRecord
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if m := dockerfileCopyRe.FindStringSubmatch(line); len(m) == 2 {
			if keyMaterialExtRe.MatchString(strings.ToLower(m[1])) {
				out = append(out, finding.FindingRecord{
					RuleID:           "DOCKERFILE-COPY-KEY-MATERIAL",
					Severity:         finding.SeverityHigh,
					Bucket:           finding.BucketB4,
					Path:             b.Path,
					LineRange:        [2]int{lineNum, lineNum},
					DetectedBy:       []string{"det:DOCKERFILE-COPY-KEY-MATERIAL"},
					ModelAttribution: "deterministic",
					Confidence:       0.9,
					Evidence:         map[string]any{"source": m[1]},
				})
			}
		}
	}
	return out
}

var systemdLoadCredRe = regexp.MustCompile(`(?m)^LoadCredential\s*=\s*(\S+)`)

func (d *ManifestDetector) detectSystemd(b enumerate.Blob, data []byte) []finding.FindingRecord {
	var out []finding.FindingRecord
	for _, m := range systemdLoadCredRe.FindAllStringSubmatch(string(data), -1) {
		out = append(out, finding.FindingRecord{
			RuleID:           "SYSTEMD-LOAD-CREDENTIAL",
			Severity:         finding.SeverityInfo,
			Bucket:           finding.BucketB4,
			Path:             b.Path,
			DetectedBy:       []string{"det:SYSTEMD-LOAD-CREDENTIAL"},
			ModelAttribution: "deterministic",
			Confidence:       0.95,
			Evidence:         map[string]any{"directive": m[1]},
		})
	}
	return out
}
