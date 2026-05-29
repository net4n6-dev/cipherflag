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
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestTransformEndoflifeResponse_HappyPath(t *testing.T) {
	data, err := os.ReadFile("testdata/endoflife_openssl.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var cycles []endoflifeCycle
	if err := json.Unmarshal(data, &cycles); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	entries := transformEndoflifeCycles("openssl", "openssl", cycles)
	if len(entries) == 0 {
		t.Fatal("expected at least one EOL entry from openssl response")
	}
	for _, e := range entries {
		if e.LibraryName != "openssl" {
			t.Errorf("LibraryName = %q, want openssl", e.LibraryName)
		}
		// VersionPrefix must be empty, end in ".", or be a 3-part cycle name
		// (2+ dots) that uses no trailing dot because real versions use letter
		// suffixes instead of a sub-component dot (e.g. "1.0.2k").
		validPrefix := e.VersionPrefix == "" ||
			strings.HasSuffix(e.VersionPrefix, ".") ||
			strings.Count(e.VersionPrefix, ".") >= 2
		if !validPrefix {
			t.Errorf("VersionPrefix = %q, should be empty, end in '.', or be a 3-part cycle name", e.VersionPrefix)
		}
		if e.Source != "https://endoflife.date/openssl" {
			t.Errorf("Source = %q, want https://endoflife.date/openssl", e.Source)
		}
		if e.Reason == "" {
			t.Errorf("Reason empty for entry %+v", e)
		}
	}
}

func TestTransformEndoflifeResponse_FutureEOLSkipped(t *testing.T) {
	// Synthetic cycle with eol in the far future — should NOT produce an entry.
	cycles := []endoflifeCycle{
		{Cycle: "99.0", EOL: "2099-01-01"},
	}
	entries := transformEndoflifeCycles("future-lib", "future-lib", cycles)
	if len(entries) != 0 {
		t.Errorf("future-EOL cycle should be skipped, got %d entries", len(entries))
	}
}

func TestTransformEndoflifeResponse_BoolEOLTrue(t *testing.T) {
	// Cycle with `eol: true` should produce an entry regardless of date.
	cycles := []endoflifeCycle{
		{Cycle: "1.0", EOL: true},
	}
	entries := transformEndoflifeCycles("old-lib", "old-lib", cycles)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].VersionPrefix != "1.0." {
		t.Errorf("VersionPrefix = %q, want 1.0.", entries[0].VersionPrefix)
	}
}

func TestCyclePrefix(t *testing.T) {
	cases := map[string]string{
		// 2-part cycles get trailing dot so prefix matches semver 3-part versions.
		"1.0": "1.0.",
		"3.4": "3.4.",
		"0.9": "0.9.",
		// 3-part cycles (already specific) don't get trailing dot — they should
		// prefix-match letter-suffix versions like "1.0.2k", "1.1.1w".
		"1.0.2": "1.0.2",
		"1.1.1": "1.1.1",
		"0.9.8": "0.9.8",
		// Single-part cycles (legacy major-only) get trailing dot.
		"3": "3.",
		"2": "2.",
	}
	for in, want := range cases {
		if got := cyclePrefix(in); got != want {
			t.Errorf("cyclePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
