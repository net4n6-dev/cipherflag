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

func TestEOLData_NoDuplicateLibraryVersionPairs(t *testing.T) {
	seen := make(map[string]struct{})
	for _, e := range eolStarterMap {
		key := e.LibraryName + "@" + e.VersionPrefix
		if _, dup := seen[key]; dup {
			t.Errorf("duplicate eolStarterMap entry: %s", key)
		}
		seen[key] = struct{}{}
	}
}

func TestEOLData_AllSourceURLsWellFormed(t *testing.T) {
	for _, e := range eolStarterMap {
		if e.Source == "manual" {
			continue
		}
		if !strings.HasPrefix(e.Source, "https://") {
			t.Errorf("entry %s/%s has non-https Source: %q", e.LibraryName, e.VersionPrefix, e.Source)
			continue
		}
		if _, err := url.Parse(e.Source); err != nil {
			t.Errorf("entry %s/%s has unparseable Source %q: %v", e.LibraryName, e.VersionPrefix, e.Source, err)
		}
	}
}

func TestEOLData_SourceURLsFromAllowedDomains(t *testing.T) {
	allowed := []string{"https://endoflife.date/", "https://github.com/", "manual"}
	for _, e := range eolStarterMap {
		ok := false
		for _, prefix := range allowed {
			if e.Source == prefix || strings.HasPrefix(e.Source, prefix) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("entry %s/%s has disallowed Source domain: %q", e.LibraryName, e.VersionPrefix, e.Source)
		}
	}
}

func TestEOLData_VersionPrefixFormat(t *testing.T) {
	for _, e := range eolStarterMap {
		if e.VersionPrefix == "" {
			continue
		}
		if strings.Contains(e.VersionPrefix, " ") {
			t.Errorf("entry %s/%s VersionPrefix contains whitespace: %q", e.LibraryName, e.VersionPrefix, e.VersionPrefix)
		}
	}
}
