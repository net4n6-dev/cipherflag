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
	"context"
	"strconv"

	"github.com/net4n6-dev/cipherflag/internal/scanner/detect"
	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func NewDispatcher() *Dispatcher {
	return &Dispatcher{detectors: []detect.Detector{
		&TLSConfigDetector{},
		&ManifestDetector{},
		NewOpensslConfDetector(),
	}}
}

type Dispatcher struct {
	detectors []detect.Detector
}

func (d *Dispatcher) Name() string { return "b4" }

func (d *Dispatcher) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	var out []finding.FindingRecord
	seen := map[string]bool{}
	for _, det := range d.detectors {
		fs, err := det.Detect(ctx, b, data)
		if err != nil && ctx.Err() != nil {
			return out, err
		}
		for _, f := range fs {
			key := f.Path + "|" + f.RuleID + "|" + strconv.Itoa(f.LineRange[0])
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	return out, nil
}
