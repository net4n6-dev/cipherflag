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
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/net4n6-dev/cipherflag/internal/scanner/detect"
	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

// ZIPDetector opens ZIP/JAR/WAR/APK/AAR archives and dispatches each inner
// file through the configured Inner detectors. Depth-limited (no
// recursive zips-in-zips in v1).
type ZIPDetector struct {
	Inner         []detect.Detector
	MaxInnerBytes int64 // skip inner files larger than this (default 10 MiB)
}

func (d *ZIPDetector) Name() string { return "b1.zip" }

var zipExtensions = map[string]struct{}{
	".zip": {}, ".jar": {}, ".war": {}, ".apk": {}, ".aar": {},
}

var zipMagic = []byte{0x50, 0x4B, 0x03, 0x04}

func (d *ZIPDetector) Detect(ctx context.Context, b enumerate.Blob, data []byte) ([]finding.FindingRecord, error) {
	ext := strings.ToLower(filepath.Ext(b.Path))
	_, extOK := zipExtensions[ext]
	magicOK := len(data) >= 4 && bytes.Equal(data[:4], zipMagic)
	if !extOK && !magicOK {
		return nil, nil
	}

	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil // unreadable archive = no findings
	}

	limit := d.MaxInnerBytes
	if limit <= 0 {
		limit = 10 * 1024 * 1024
	}

	var out []finding.FindingRecord
	for _, entry := range r.File {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if entry.UncompressedSize64 > uint64(limit) {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			continue
		}
		inner, err := io.ReadAll(io.LimitReader(rc, limit+1))
		rc.Close()
		if err != nil || int64(len(inner)) > limit {
			continue
		}
		innerBlob := enumerate.Blob{
			Path: fmt.Sprintf("%s!%s", b.Path, entry.Name),
			Size: int64(len(inner)),
		}
		for _, det := range d.Inner {
			fs, _ := det.Detect(ctx, innerBlob, inner)
			for i := range fs {
				if fs[i].Evidence == nil {
					fs[i].Evidence = map[string]any{}
				}
				fs[i].Evidence["archive"] = b.Path
			}
			out = append(out, fs...)
		}
	}
	return out, nil
}
