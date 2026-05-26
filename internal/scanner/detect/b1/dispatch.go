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

	"github.com/net4n6-dev/cipherflag/internal/scanner/detect"
	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// DispatcherOptions configures the B1 dispatcher.
type DispatcherOptions struct {
	CommonPasswords []string
	IncludeZIP      bool // set true to enable ZIP/JAR recursion
}

// DefaultCommonPasswords are always tried, even if operator config does not
// supply any. Operator config extends (does not replace) this list.
var DefaultCommonPasswords = []string{"", "changeit", "password", "1234", "admin"}

// NewDispatcher builds a B1 dispatcher pre-wired with all format detectors.
func NewDispatcher(opts DispatcherOptions) *Dispatcher {
	passwords := append([]string(nil), DefaultCommonPasswords...)
	passwords = append(passwords, opts.CommonPasswords...)

	pem := &PEMDetector{}
	der := &DERDetector{}
	sshd := &SSHDetector{}
	p12 := &PKCS12Detector{CommonPasswords: passwords}
	jks := &JKSDetector{CommonPasswords: passwords}

	inner := []detect.Detector{pem, der, sshd, p12, jks}
	var all []detect.Detector
	all = append(all, inner...)
	if opts.IncludeZIP {
		all = append(all, &ZIPDetector{Inner: inner})
	}
	return &Dispatcher{detectors: all}
}

type Dispatcher struct {
	detectors []detect.Detector
}

func (d *Dispatcher) Name() string { return "b1" }

// Detect runs every per-format detector and dedupes by (path, rule_id).
// Dedup is important because e.g. a PEM-armoured OpenSSH private key
// named id_rsa matches both PEMDetector and SSHDetector.
func (d *Dispatcher) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	var out []finding.FindingRecord
	seen := map[string]bool{} // path|rule_id
	for _, det := range d.detectors {
		fs, err := det.Detect(ctx, b, data)
		if err != nil && ctx.Err() != nil {
			return out, err
		}
		for _, f := range fs {
			key := f.Path + "|" + f.RuleID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	return out, nil
}
