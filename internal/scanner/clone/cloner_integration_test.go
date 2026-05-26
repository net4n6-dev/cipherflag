//go:build integration

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

package clone

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Builds a bare repository at a temp path, commits a single file, then
// exercises the real ShellCloner against it. Requires system `git`.
func TestCloner_ClonesLocalFixtureRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	tmp := t.TempDir()

	work := filepath.Join(tmp, "work")
	mustRun(t, "", "git", "init", work)
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("hello\n"), 0644); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	mustRun(t, work, "git", "config", "user.email", "test@example.com")
	mustRun(t, work, "git", "config", "user.name", "Test")
	mustRun(t, work, "git", "add", "README.md")
	mustRun(t, work, "git", "commit", "-m", "init")

	bare := filepath.Join(tmp, "bare.git")
	mustRun(t, "", "git", "clone", "--bare", work, bare)

	dst := filepath.Join(tmp, "cloned")
	c := &ShellCloner{
		Runner:             &ExecRunner{},
		PartialCloneFilter: "", // partial clone not supported by local file protocol
		CheckoutMode:       "full",
	}
	result, err := c.Clone(context.Background(), CloneSpec{
		URL:       bare,
		Ref:       "",
		TargetDir: dst,
	})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if result.HeadSHA == "" {
		t.Error("expected HeadSHA populated")
	}
	if _, err := os.Stat(filepath.Join(dst, "README.md")); err != nil {
		t.Errorf("README.md missing from clone: %v", err)
	}
}

func mustRun(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, b)
	}
}
