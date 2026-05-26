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

// Package clone runs `git clone` against remote repos via shell-out.
// Partial clone (--filter=blob:none) is used when the caller requests it.
// The Runner interface is swapped out for unit testing.
package clone

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type CommandRunner interface {
	Run(ctx context.Context, env []string, name string, args ...string) (string, error)
}

// ExecRunner is the real-world CommandRunner using os/exec.
type ExecRunner struct{}

func (r *ExecRunner) Run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(cmd.Environ(), env...)
	}
	b, err := cmd.CombinedOutput()
	if err != nil {
		return string(b), fmt.Errorf("%s %v: %w — %s", name, args, err, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}

// CloneSpec is the high-level request the caller supplies.
type CloneSpec struct {
	URL       string   // https or ssh URL
	Ref       string   // branch or SHA; empty = default branch
	TargetDir string   // clone destination
	Env       []string // extra env vars (e.g. GIT_ASKPASS setup)
}

// CloneResult describes the state of the cloned working tree.
type CloneResult struct {
	HeadSHA string // commit the worktree is currently at
	WorkDir string // same as CloneSpec.TargetDir; returned for convenience
}

// Cloner is the interface the pipeline depends on. Swappable for tests.
type Cloner interface {
	Clone(ctx context.Context, spec CloneSpec) (*CloneResult, error)
}

// ShellCloner is the production Cloner using system `git` via CommandRunner.
type ShellCloner struct {
	Runner             CommandRunner
	PartialCloneFilter string // "blob:none" | "" for full clone
	CheckoutMode       string // "sparse" | "full"
}

func (s *ShellCloner) Clone(ctx context.Context, spec CloneSpec) (*CloneResult, error) {
	if s.Runner == nil {
		return nil, fmt.Errorf("clone: no CommandRunner configured")
	}
	args := []string{"clone"}
	if s.PartialCloneFilter != "" {
		args = append(args, "--filter="+s.PartialCloneFilter)
	}
	// --no-checkout defers populating the worktree; caller does sparse/full checkout next.
	args = append(args, "--no-checkout")
	if spec.Ref != "" {
		args = append(args, "--branch", spec.Ref)
	}
	args = append(args, spec.URL, spec.TargetDir)
	if _, err := s.Runner.Run(ctx, spec.Env, "git", args...); err != nil {
		return nil, fmt.Errorf("git clone: %w", err)
	}

	switch s.CheckoutMode {
	case "sparse":
		if _, err := s.Runner.Run(ctx, spec.Env, "git", "-C", spec.TargetDir, "sparse-checkout", "init", "--cone"); err != nil {
			if _, ferr := s.Runner.Run(ctx, spec.Env, "git", "-C", spec.TargetDir, "checkout"); ferr != nil {
				return nil, fmt.Errorf("git checkout fallback: %w", ferr)
			}
		} else {
			if _, err := s.Runner.Run(ctx, spec.Env, "git", "-C", spec.TargetDir, "checkout"); err != nil {
				return nil, fmt.Errorf("git checkout: %w", err)
			}
		}
	case "full", "":
		if _, err := s.Runner.Run(ctx, spec.Env, "git", "-C", spec.TargetDir, "checkout"); err != nil {
			return nil, fmt.Errorf("git checkout: %w", err)
		}
	default:
		return nil, fmt.Errorf("clone: unknown checkout_mode %q", s.CheckoutMode)
	}

	out, err := s.Runner.Run(ctx, spec.Env, "git", "-C", spec.TargetDir, "rev-parse", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("git rev-parse HEAD: %w", err)
	}
	return &CloneResult{
		HeadSHA: strings.TrimSpace(out),
		WorkDir: spec.TargetDir,
	}, nil
}
