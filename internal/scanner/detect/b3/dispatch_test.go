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

package b3

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
)

func TestB3Dispatcher_RoutesGo(t *testing.T) {
	src := `package x
import "crypto/md5"
func y() { _ = md5.New() }`
	disp := NewDispatcher()
	findings, err := disp.Detect(context.Background(), enumerate.Blob{Path: "x.go"}, []byte(src))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected MD5 finding from Go file")
	}
}

func TestB3Dispatcher_RoutesPython(t *testing.T) {
	src := `import hashlib
hashlib.md5(b)`
	disp := NewDispatcher()
	findings, err := disp.Detect(context.Background(), enumerate.Blob{Path: "x.py"}, []byte(src))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected MD5 finding from Python file")
	}
}

func TestB3Dispatcher_NoFindingsOnUnrelatedExtension(t *testing.T) {
	disp := NewDispatcher()
	findings, _ := disp.Detect(context.Background(), enumerate.Blob{Path: "README.md"}, []byte("# hi"))
	if len(findings) != 0 {
		t.Errorf("want 0, got %d", len(findings))
	}
}
