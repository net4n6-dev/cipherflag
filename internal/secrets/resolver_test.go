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

package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolve_EnvScheme(t *testing.T) {
	os.Setenv("SECRETS_TEST_VAR", "s3cr3t")
	t.Cleanup(func() { os.Unsetenv("SECRETS_TEST_VAR") })

	got, err := Resolve(context.Background(), "env:SECRETS_TEST_VAR")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("want s3cr3t, got %q", got)
	}
}

func TestResolve_EnvMissing(t *testing.T) {
	os.Unsetenv("SECRETS_TEST_MISSING")
	_, err := Resolve(context.Background(), "env:SECRETS_TEST_MISSING")
	if err == nil {
		t.Fatal("want error on missing env var")
	}
	if !strings.Contains(err.Error(), "SECRETS_TEST_MISSING") {
		t.Errorf("error should mention var name; got %v", err)
	}
}

func TestResolve_FileScheme(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("token-from-file\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Resolve(context.Background(), "file:"+path)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "token-from-file" {
		t.Errorf("want trimmed, got %q", got)
	}
}

func TestResolve_UnknownScheme(t *testing.T) {
	_, err := Resolve(context.Background(), "snowflake:prod/creds")
	if err == nil {
		t.Fatal("want error on unknown scheme")
	}
	if !errors.Is(err, ErrUnknownScheme) {
		t.Errorf("want ErrUnknownScheme, got %v", err)
	}
}

func TestResolve_StubbedSchemes(t *testing.T) {
	for _, ref := range []string{
		"vault:secret/data/x#field",
		"k8s:ns/name#key",
		"aws-sm:my-secret",
		"gcp-sm:projects/p/secrets/s",
	} {
		_, err := Resolve(context.Background(), ref)
		if !errors.Is(err, ErrResolverNotImplemented) {
			t.Errorf("%q: want ErrResolverNotImplemented, got %v", ref, err)
		}
	}
}

func TestResolve_MalformedReference(t *testing.T) {
	_, err := Resolve(context.Background(), "no-scheme-at-all")
	if err == nil {
		t.Fatal("want error on malformed ref")
	}
}
