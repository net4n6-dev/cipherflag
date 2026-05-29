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

// refresh-pqc regenerates internal/analysis/pqc/catalog.go and synonyms.go
// from NIST FIPS standards + IETF hybrids + the watchlist.
// liboqs registry fetch deferred to a follow-up.
//
// Run via `make refresh-pqc` or directly: `go run ./refresh-pqc.go`.
//
// This file has //go:build ignore so it doesn't collide with refresh-eol.go's
// func main(). The testable helpers live in pqc_gen.go (without build tag).
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/net4n6-dev/cipherflag/scripts/catalogs/internal/codegen"
)

const (
	pqcGeneratorName    = "refresh-pqc.go"
	pqcGeneratorVersion = "v1"
	pqcCatalogOutPath   = "../../internal/analysis/pqc/catalog.go"
	pqcSynonymsOutPath  = "../../internal/analysis/pqc/synonyms.go"
	pqcWatchlistPath    = "watchlists/pqc.yaml"
)

func main() {
	if err := runPqc(); err != nil {
		fmt.Fprintf(os.Stderr, "refresh-pqc: %v\n", err)
		os.Exit(1)
	}
}

func runPqc() error {
	wl, err := loadPqcWatchlist(pqcWatchlistPath)
	if err != nil {
		return fmt.Errorf("load watchlist: %w", err)
	}

	merged := mergeAllPqcSources(wl)

	// Stable ordering.
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	catalogBody := renderPqcCatalog(keys, merged)
	synonymsBody := renderPqcSynonyms(wl.Synonyms, merged)

	header := func(pkg string, srcs []string) codegen.Header {
		return codegen.Header{
			GeneratorName: pqcGeneratorName,
			Version:       pqcGeneratorVersion,
			Sources:       srcs,
			Watchlist:     pqcWatchlistPath,
			PackageName:   pkg,
		}
	}

	if err := codegen.Emit(pqcCatalogOutPath, header("pqc", []string{
		"NIST FIPS 203 (ML-KEM)",
		"NIST FIPS 204 (ML-DSA)",
		"NIST FIPS 205 (SLH-DSA)",
		"IETF draft-ietf-tls-hybrid-design",
		"watchlists/pqc.yaml (overrides + classical)",
	}), catalogBody); err != nil {
		return fmt.Errorf("emit catalog: %w", err)
	}
	if err := codegen.Emit(pqcSynonymsOutPath, header("pqc", []string{
		"watchlists/pqc.yaml synonyms section + auto-generated self-mappings",
	}), synonymsBody); err != nil {
		return fmt.Errorf("emit synonyms: %w", err)
	}

	fmt.Printf("refresh-pqc: wrote %d canonical entries (catalog.go) + synonyms.go\n", len(merged))
	return nil
}
