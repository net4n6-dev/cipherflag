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

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The release workflow publishes images only when the pushed tag equals
// Version (scripts/check-release-tag.sh). This test catches the other half
// on every CI run, before anyone tags: a Version with no CHANGELOG section
// would ship undocumented.
func TestVersionHasChangelogSection(t *testing.T) {
	require.Regexp(t, regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`), Version,
		"Version must be semver without a leading v; the release tag is v+Version")

	changelog, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	require.NoError(t, err)
	base, _, _ := strings.Cut(Version, "-") // a prerelease documents under its release
	require.Contains(t, string(changelog), "\n## ["+base+"]",
		"CHANGELOG.md has no ## [%s] section for Version %q", base, Version)
}
