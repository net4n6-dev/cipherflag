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

package executil_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
)

func TestOSRunner_CommandNotFound(t *testing.T) {
	r := executil.OSRunner{}
	_, _, err := r.Run(context.Background(), "this-command-does-not-exist-at-all")
	if err == nil {
		t.Fatal("expected error for nonexistent command, got nil")
	}
	var exitErr *executil.ExitError
	if errors.As(err, &exitErr) {
		t.Fatalf("expected non-ExitError for missing binary, got *ExitError with code %d", exitErr.ExitCode)
	}
}

func TestOSRunner_Echo(t *testing.T) {
	r := executil.OSRunner{}
	stdout, _, err := r.Run(context.Background(), "echo", "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(stdout) != "hello\n" {
		t.Fatalf("expected %q, got %q", "hello\n", stdout)
	}
}

func TestTestRunner_ReturnsConfiguredOutput(t *testing.T) {
	tr := executil.NewTestRunner()
	tr.AddCommand("my-tool --flag value", executil.CommandResult{
		Stdout:   []byte("expected output\n"),
		Stderr:   []byte(""),
		ExitCode: 0,
	})

	stdout, _, err := tr.Run(context.Background(), "my-tool", "--flag", "value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(stdout) != "expected output\n" {
		t.Fatalf("expected %q, got %q", "expected output\n", stdout)
	}
}

func TestTestRunner_UnknownCommandReturnsError(t *testing.T) {
	tr := executil.NewTestRunner()
	_, _, err := tr.Run(context.Background(), "unknown-tool", "--arg")
	if err == nil {
		t.Fatal("expected error for unconfigured command, got nil")
	}
	if !strings.Contains(err.Error(), "unknown-tool --arg") {
		t.Fatalf("expected error to mention command key, got: %v", err)
	}
}

func TestTestRunner_NonZeroExitCode(t *testing.T) {
	tr := executil.NewTestRunner()
	tr.AddCommand("failing-tool", executil.CommandResult{
		Stdout:   []byte(""),
		Stderr:   []byte("something went wrong\n"),
		ExitCode: 255,
	})

	_, stderr, err := tr.Run(context.Background(), "failing-tool")
	if err == nil {
		t.Fatal("expected error for non-zero exit code, got nil")
	}

	exitErr, ok := err.(*executil.ExitError)
	if !ok {
		t.Fatalf("expected *executil.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode != 255 {
		t.Fatalf("expected exit code 255, got %d", exitErr.ExitCode)
	}
	if string(stderr) != "something went wrong\n" {
		t.Fatalf("expected stderr %q, got %q", "something went wrong\n", stderr)
	}
}
