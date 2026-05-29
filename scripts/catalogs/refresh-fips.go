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

//go:build ignore

// refresh-fips regenerates internal/analysis/scoring/library_fips_data.go
// from a manually-curated watchlist at watchlists/fips.yaml. NIST CMVP
// has no clean JSON API as of 2026, so this generator is watchlist-driven.
//
// Run via `go run ./refresh-fips.go`.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/net4n6-dev/cipherflag/scripts/catalogs/internal/codegen"
)

func main() {
	if err := runFips(); err != nil {
		fmt.Fprintf(os.Stderr, "refresh-fips: %v\n", err)
		os.Exit(1)
	}
}

func runFips() error {
	wl, err := loadFipsWatchlist(fipsWatchlistPath)
	if err != nil {
		return fmt.Errorf("load watchlist: %w", err)
	}

	for _, w := range collectFipsWarnings(wl.Entries) {
		fmt.Fprintln(os.Stderr, "warn:", w)
	}

	sort.Slice(wl.Entries, func(i, j int) bool {
		if wl.Entries[i].LibraryName != wl.Entries[j].LibraryName {
			return wl.Entries[i].LibraryName < wl.Entries[j].LibraryName
		}
		return wl.Entries[i].VersionPrefix < wl.Entries[j].VersionPrefix
	})

	body, err := renderFipsEntries(wl.Entries)
	if err != nil {
		return fmt.Errorf("render: %w", err)
	}

	header := codegen.Header{
		GeneratorName: fipsGeneratorName,
		Version:       fipsGeneratorVersion,
		Sources:       []string{"NIST CMVP (manual watchlist)"},
		Watchlist:     fipsWatchlistPath,
		PackageName:   "scoring",
	}
	if err := codegen.Emit(fipsOutputPath, header, body); err != nil {
		return fmt.Errorf("emit: %w", err)
	}
	fmt.Printf("refresh-fips: wrote %d entries to %s\n", len(wl.Entries), fipsOutputPath)
	return nil
}
