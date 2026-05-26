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
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
)

func TestB4Dispatcher_RoutesByPath(t *testing.T) {
	disp := NewDispatcher()
	data := []byte(`ssl_protocols TLSv1 TLSv1.2;`)
	blob := enumerate.Blob{Path: "etc/nginx/nginx.conf", Size: int64(len(data))}
	findings, err := disp.Detect(context.Background(), blob, data)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected nginx finding")
	}
}

func TestB4Dispatcher_NonMatchNoFinding(t *testing.T) {
	disp := NewDispatcher()
	blob := enumerate.Blob{Path: "README.md", Size: 5}
	findings, _ := disp.Detect(context.Background(), blob, []byte("hello"))
	if len(findings) != 0 {
		t.Errorf("want 0, got %d", len(findings))
	}
}
