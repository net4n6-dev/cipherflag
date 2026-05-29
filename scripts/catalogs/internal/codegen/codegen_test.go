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

package codegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmit_WritesValidGoFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.go")
	header := Header{
		GeneratorName: "test-gen.go",
		Version:       "v1",
		Sources:       []string{"https://example.com/api"},
		PackageName:   "testpkg",
	}
	body := `var Greeting = "hello"
`
	if err := Emit(out, header, body); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	got, _ := os.ReadFile(out)
	gotStr := string(got)
	if !strings.Contains(gotStr, "package testpkg") {
		t.Errorf("missing package decl: %s", gotStr)
	}
	if !strings.Contains(gotStr, "DO NOT EDIT") {
		t.Errorf("missing DO NOT EDIT marker: %s", gotStr)
	}
	if !strings.Contains(gotStr, "Greeting = \"hello\"") {
		t.Errorf("missing body: %s", gotStr)
	}
	if !strings.Contains(gotStr, "Licensed under the Apache License") {
		t.Errorf("missing Apache license header: %s", gotStr)
	}
}

func TestEmit_RejectsUnparseable(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.go")
	header := Header{
		GeneratorName: "test-gen.go",
		Version:       "v1",
		PackageName:   "testpkg",
	}
	body := `var x = func{`
	if err := Emit(out, header, body); err == nil {
		t.Error("Emit should fail on unparseable body")
	}
}

func TestGoStringSlice(t *testing.T) {
	if got := GoStringSlice(nil); got != "nil" {
		t.Errorf("got %q", got)
	}
	if got := GoStringSlice([]string{"a", "b"}); got != `[]string{"a", "b"}` {
		t.Errorf("got %q", got)
	}
}
