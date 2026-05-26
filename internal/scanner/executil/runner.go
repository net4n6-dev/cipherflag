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

// Package executil provides a testable abstraction over os/exec for running
// system commands within scanner packages.
package executil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// CommandRunner abstracts os/exec so scanners can be unit-tested without
// running real system commands.
type CommandRunner interface {
	// Run executes name with the given args. It returns the full stdout bytes,
	// the full stderr bytes, and any error. A non-zero exit code is returned as
	// an *ExitError.
	Run(ctx context.Context, name string, args ...string) (stdout []byte, stderr []byte, err error)
}

// ExitError is returned by CommandRunner.Run when the subprocess exits with a
// non-zero status code.
type ExitError struct {
	Command  string
	ExitCode int
	Stderr   string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("command %q exited with code %d: %s", e.Command, e.ExitCode, e.Stderr)
}

// CommandResult holds the pre-configured output that TestRunner will return
// for a given command key.
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// commandKey builds a stable string representation of a command invocation,
// used as the lookup key in TestRunner and in error messages.
// Note: arguments containing spaces will produce ambiguous keys.
// Tests should avoid args with embedded spaces or use distinct fixtures.
func commandKey(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}

// OSRunner is the production implementation of CommandRunner. It delegates to
// os/exec.CommandContext.
type OSRunner struct{}

// Run implements CommandRunner using os/exec.
func (o OSRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()

	if err != nil {
		var execExitErr *exec.ExitError
		if errors.As(err, &execExitErr) {
			key := commandKey(name, args)
			return outBuf.Bytes(), errBuf.Bytes(), &ExitError{
				Command:  key,
				ExitCode: execExitErr.ExitCode(),
				Stderr:   errBuf.String(),
			}
		}
		return outBuf.Bytes(), errBuf.Bytes(), fmt.Errorf("executil: running %q: %w", name, err)
	}

	return outBuf.Bytes(), errBuf.Bytes(), nil
}

// TestRunner is a fake CommandRunner for use in unit tests. Commands are
// pre-registered by their full invocation string (name + args joined by spaces).
type TestRunner struct {
	commands map[string]CommandResult
}

// NewTestRunner creates an empty TestRunner.
func NewTestRunner() *TestRunner {
	return &TestRunner{
		commands: make(map[string]CommandResult),
	}
}

// AddCommand registers a CommandResult for the given invocation key. The key
// must match exactly what Run would compute: name and args joined with a single
// space (e.g. "ssh-keygen -l -f /path/to/key").
func (t *TestRunner) AddCommand(key string, result CommandResult) {
	t.commands[key] = result
}

// Run implements CommandRunner. It looks up the invocation key (name + args
// joined by spaces) in the configured commands map. If not found it returns an
// error. If found and ExitCode != 0 it returns an *ExitError.
func (t *TestRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	key := commandKey(name, args)

	result, ok := t.commands[key]
	if !ok {
		return nil, nil, fmt.Errorf("executil.TestRunner: no command configured for %q", key)
	}

	if result.ExitCode != 0 {
		return result.Stdout, result.Stderr, &ExitError{
			Command:  key,
			ExitCode: result.ExitCode,
			Stderr:   string(result.Stderr),
		}
	}

	return result.Stdout, result.Stderr, nil
}
