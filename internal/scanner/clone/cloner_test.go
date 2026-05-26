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
	"strings"
	"testing"
)

type fakeRunner struct {
	calls [][]string
	err   error
}

func (f *fakeRunner) Run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return "", f.err
}

func TestCloner_InvokesGitWithPartialCloneFlags(t *testing.T) {
	fr := &fakeRunner{}
	c := &ShellCloner{
		Runner:             fr,
		PartialCloneFilter: "blob:none",
		CheckoutMode:       "sparse",
	}
	_, err := c.Clone(context.Background(), CloneSpec{
		URL:       "https://github.com/a/b",
		Ref:       "main",
		TargetDir: "/tmp/x",
	})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if len(fr.calls) == 0 {
		t.Fatal("expected at least one git invocation")
	}
	joined := strings.Join(fr.calls[0], " ")
	if !strings.Contains(joined, "--filter=blob:none") {
		t.Errorf("expected --filter=blob:none in %q", joined)
	}
	if !strings.Contains(joined, "--no-checkout") {
		t.Errorf("expected --no-checkout in %q", joined)
	}
}

func TestCloner_FullCloneWhenFilterEmpty(t *testing.T) {
	fr := &fakeRunner{}
	c := &ShellCloner{Runner: fr, PartialCloneFilter: "", CheckoutMode: "full"}
	_, err := c.Clone(context.Background(), CloneSpec{URL: "u", Ref: "main", TargetDir: "/tmp/x"})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	joined := strings.Join(fr.calls[0], " ")
	if strings.Contains(joined, "--filter") {
		t.Errorf("did not want --filter, got %q", joined)
	}
}
