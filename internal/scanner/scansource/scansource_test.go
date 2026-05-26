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

package scansource

import (
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestFromRepository_GitKind(t *testing.T) {
	r := &model.Repository{ID: "r1", URL: "https://github.com/a/b", DefaultBranch: "main"}
	s, err := FromRepository(r, "github")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Kind() != KindGit {
		t.Errorf("kind = %q, want git", s.Kind())
	}
	if s.Reference() != "https://github.com/a/b" {
		t.Errorf("ref = %q", s.Reference())
	}
	if s.DefaultRef() != "main" {
		t.Errorf("default ref = %q", s.DefaultRef())
	}
}

func TestFromRepository_ContainerKind(t *testing.T) {
	r := &model.Repository{ID: "i1", URL: "docker.io/library/alpine:3.19", DefaultBranch: "3.19"}
	s, err := FromRepository(r, "container_registry")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Kind() != KindContainer {
		t.Errorf("kind = %q, want container", s.Kind())
	}
	if s.DefaultRef() != "3.19" {
		t.Errorf("default ref (tag) = %q", s.DefaultRef())
	}
}

func TestFromRepository_EmptyKindErrors(t *testing.T) {
	r := &model.Repository{ID: "r1"}
	s, err := FromRepository(r, "")
	if err == nil {
		t.Fatal("expected error for empty provider kind, got nil")
	}
	if s != nil {
		t.Errorf("expected nil ScanSource on error, got %+v", s)
	}
}

func TestFromRepository_UnknownKindErrors(t *testing.T) {
	r := &model.Repository{ID: "r1"}
	s, err := FromRepository(r, "some_future_kind")
	if err == nil {
		t.Fatal("expected error for unknown provider kind, got nil")
	}
	if s != nil {
		t.Errorf("expected nil ScanSource on error, got %+v", s)
	}
}
