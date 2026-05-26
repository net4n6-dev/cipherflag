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
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/detect"
	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
)

func TestZIPDetector_RecursesIntoJAR(t *testing.T) {
	d := &ZIPDetector{Inner: []detect.Detector{&PEMDetector{}}}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("META-INF/cert.pem")
	_, _ = f.Write(genSelfSignedCertPEM(t))
	zw.Close()

	blob := enumerate.Blob{Path: "libs/app.jar", Size: int64(buf.Len())}
	findings, err := d.Detect(context.Background(), blob, buf.Bytes())
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected inner cert finding")
	}
	inner := findings[0]
	if inner.Evidence["archive"] != "libs/app.jar" {
		t.Errorf("expected archive evidence, got %+v", inner.Evidence)
	}
	if inner.Path != "libs/app.jar!META-INF/cert.pem" {
		t.Errorf("inner path: %q", inner.Path)
	}
}
