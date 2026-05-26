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

// Package scansource provides a Go-side abstraction over Repository rows
// that may semantically represent either a git repository (Layer 6.1) or
// a container image source (Layer 6.2). The underlying DB schema is the
// same (`repositories` table); this interface keeps naming clean at the
// API/code layer without requiring a migration or a parallel table.
package scansource

import (
	"fmt"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// Kind discriminates repository-flavoured vs image-flavoured sources.
type Kind string

const (
	KindGit       Kind = "git"
	KindContainer Kind = "container"
)

// ScanSource is the unified view of a Repository row, with container-mode
// naming re-labelled. Fields map 1:1 to Repository; accessor names read
// naturally for each kind.
type ScanSource struct {
	repo *model.Repository
	kind Kind
}

// FromRepository wraps a Repository in a ScanSource. Kind is inferred from
// the provider kind; caller is responsible for joining provider first.
//
// An empty or unrecognised providerKind returns an error rather than
// silently defaulting — kind drives downstream scan behaviour (OCI pull
// vs git clone), so a fast error beats a silently wrong answer.
func FromRepository(r *model.Repository, providerKind string) (*ScanSource, error) {
	if providerKind == "" {
		return nil, fmt.Errorf("scansource: empty provider kind")
	}
	if !model.IsValidProviderKind(providerKind) {
		return nil, fmt.Errorf("scansource: unknown provider kind %q", providerKind)
	}
	k := KindGit
	if providerKind == "container_registry" {
		k = KindContainer
	}
	return &ScanSource{repo: r, kind: k}, nil
}

func (s *ScanSource) ID() string                    { return s.repo.ID }
func (s *ScanSource) ProviderID() string            { return s.repo.ProviderID }
func (s *ScanSource) Kind() Kind                    { return s.kind }
func (s *ScanSource) Underlying() *model.Repository { return s.repo }

// Reference returns the operator-meaningful reference:
//   - git: repository URL (https://github.com/org/repo)
//   - container: image reference (registry/repo:tag)
func (s *ScanSource) Reference() string { return s.repo.URL }

// DefaultRef returns the default branch (git) or default tag (container).
func (s *ScanSource) DefaultRef() string { return s.repo.DefaultBranch }

// DefaultScanMode returns the default scan mode.
func (s *ScanSource) DefaultScanMode() string { return s.repo.DefaultScanMode }

// String returns a human-readable identifier for logging.
func (s *ScanSource) String() string {
	return fmt.Sprintf("%s:%s", s.kind, s.repo.URL)
}
