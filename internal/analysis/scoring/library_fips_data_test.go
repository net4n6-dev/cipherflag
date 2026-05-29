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

package scoring

import (
	"net/url"
	"strings"
	"testing"
)

func TestFIPSData_NoDuplicateEntries(t *testing.T) {
	seen := make(map[string]struct{})
	for _, e := range fipsStarterMap {
		key := e.LibraryName + "@" + e.VersionPrefix
		if _, dup := seen[key]; dup {
			t.Errorf("duplicate fipsStarterMap entry: %s", key)
		}
		seen[key] = struct{}{}
	}
}

func TestFIPSData_AllSourceURLsWellFormed(t *testing.T) {
	for _, e := range fipsStarterMap {
		if e.Source == "manual" {
			continue
		}
		if !strings.HasPrefix(e.Source, "https://csrc.nist.gov/") {
			t.Errorf("entry %s/%s Source not from csrc.nist.gov: %q", e.LibraryName, e.VersionPrefix, e.Source)
			continue
		}
		if _, err := url.Parse(e.Source); err != nil {
			t.Errorf("entry %s/%s unparseable Source %q: %v", e.LibraryName, e.VersionPrefix, e.Source, err)
		}
	}
}

func TestFIPSData_VersionPrefixFormat(t *testing.T) {
	for _, e := range fipsStarterMap {
		if e.VersionPrefix == "" {
			t.Errorf("entry %s has empty VersionPrefix (FIPS entries should target a specific version)", e.LibraryName)
		}
		if strings.Contains(e.VersionPrefix, " ") {
			t.Errorf("entry %s/%s VersionPrefix contains whitespace: %q", e.LibraryName, e.VersionPrefix, e.VersionPrefix)
		}
	}
}
