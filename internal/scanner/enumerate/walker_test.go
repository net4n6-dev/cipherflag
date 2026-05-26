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

package enumerate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalker_FindsFilesAndSkipsDotGit(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, ".git", "objects"), 0755))
	must(t, os.WriteFile(filepath.Join(root, ".git", "objects", "pack"), []byte("x"), 0644))
	must(t, os.WriteFile(filepath.Join(root, "README.md"), []byte("hello"), 0644))
	must(t, os.MkdirAll(filepath.Join(root, "src"), 0755))
	must(t, os.WriteFile(filepath.Join(root, "src", "main.go"), []byte("package main\n"), 0644))

	out, err := Walk(root, Options{MaxBlobSizeBytes: 1024})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	paths := map[string]bool{}
	for _, b := range out {
		paths[b.Path] = true
	}
	if !paths["README.md"] || !paths["src/main.go"] {
		t.Errorf("missing expected files: %v", paths)
	}
	for p := range paths {
		if strings.HasPrefix(p, ".git/") {
			t.Errorf(".git/ entries must be skipped; got %s", p)
		}
	}
}

func TestWalker_HonoursMaxBlobSize(t *testing.T) {
	root := t.TempDir()
	must(t, os.WriteFile(filepath.Join(root, "small.txt"), make([]byte, 100), 0644))
	must(t, os.WriteFile(filepath.Join(root, "big.txt"), make([]byte, 2000), 0644))

	out, err := Walk(root, Options{MaxBlobSizeBytes: 1024})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	paths := map[string]int64{}
	for _, b := range out {
		paths[b.Path] = b.Size
	}
	if _, ok := paths["small.txt"]; !ok {
		t.Error("small.txt missing")
	}
	if _, ok := paths["big.txt"]; ok {
		t.Error("big.txt should have been filtered by max_blob_size_bytes")
	}
}

func TestWalker_BlobSHAIsSHA256OfContent(t *testing.T) {
	root := t.TempDir()
	must(t, os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0644))
	out, err := Walk(root, Options{MaxBlobSizeBytes: 1024})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if out[0].HexSHA() != want {
		t.Errorf("want %s, got %s", want, out[0].HexSHA())
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
