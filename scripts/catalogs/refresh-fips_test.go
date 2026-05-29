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
	"strings"
	"testing"
)

func TestLoadFipsWatchlist_Fixture(t *testing.T) {
	wl, err := loadFipsWatchlist("testdata/fips_sample.yaml")
	if err != nil {
		t.Fatalf("loadFipsWatchlist: %v", err)
	}
	if len(wl.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(wl.Entries))
	}
	got := wl.Entries[0]
	if got.LibraryName != "openssl" || got.Cert != 4282 || got.FIPSLevel != "fips140-3-l1" {
		t.Errorf("entry[0] = %+v", got)
	}
}

func TestRenderFipsEntries_PopulatesSourceURL(t *testing.T) {
	entries := []fipsEntry{
		{LibraryName: "openssl", VersionPrefix: "3.0.0-fips", Cert: 4282, Note: "x", FIPSLevel: "fips140-3-l1"},
		{LibraryName: "bouncy", VersionPrefix: "1.78", Cert: 0, Note: "manual entry", FIPSLevel: ""},
	}
	body, err := renderFipsEntries(entries)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(body, "csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282") {
		t.Errorf("missing CMVP URL for cert 4282:\n%s", body)
	}
	if !strings.Contains(body, `Source: "manual"`) {
		t.Errorf("cert=0 entry should render Source: \"manual\":\n%s", body)
	}
}

func TestRenderFipsEntries_WarnsOnExpired(t *testing.T) {
	entries := []fipsEntry{
		{LibraryName: "old", VersionPrefix: "1.", Cert: 1, Note: "x", Expires: "2020-01-01"},
	}
	warnings := collectFipsWarnings(entries)
	if len(warnings) == 0 {
		t.Error("expected warning for expired entry")
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "old") {
		t.Errorf("warning missing library name: %v", warnings)
	}
}
