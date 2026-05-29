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

// refresh-eol regenerates internal/analysis/scoring/library_eol_data.go
// from endoflife.date + manual overlay in watchlists/eol.yaml.
//
// Run via `make refresh-eol` or directly: `go run ./refresh-eol.go`.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/scripts/catalogs/internal/codegen"
	"gopkg.in/yaml.v3"
)

const (
	generatorName     = "refresh-eol.go"
	generatorVersion  = "v1"
	outputPath        = "../../internal/analysis/scoring/library_eol_data.go"
	watchlistPath     = "watchlists/eol.yaml"
	endoflifeBase     = "https://endoflife.date/api"
	endoflifeSiteBase = "https://endoflife.date"
	politeDelay       = 1 * time.Second
	httpTimeout       = 30 * time.Second
)

// watchlist matches scripts/catalogs/watchlists/eol.yaml.
type watchlist struct {
	Products []struct {
		Slug        string `yaml:"slug"`
		LibraryName string `yaml:"library_name"`
		SubFilter   string `yaml:"sub_filter,omitempty"`
	} `yaml:"products"`
	Manual []eolEntry `yaml:"manual"`
}

// eolEntry mirrors the struct in library_eol_data.go.
type eolEntry struct {
	LibraryName   string `yaml:"library_name"`
	VersionPrefix string `yaml:"version_prefix"`
	Reason        string `yaml:"reason"`
	Source        string `yaml:"-"` // set by transformEndoflifeCycles or manual = "manual"
}

// endoflifeCycle is the JSON shape returned by endoflife.date.
// `eol` is polymorphic: bool, string-date, or omitted.
type endoflifeCycle struct {
	Cycle   string `json:"cycle"`
	EOL     any    `json:"eol"`
	Support any    `json:"support"`
	Latest  string `json:"latest,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "refresh-eol: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	wl, err := loadWatchlist(watchlistPath)
	if err != nil {
		return fmt.Errorf("load watchlist: %w", err)
	}

	var allEntries []eolEntry
	client := &http.Client{Timeout: httpTimeout}
	for i, p := range wl.Products {
		if i > 0 {
			time.Sleep(politeDelay)
		}
		cycles, err := fetchEndoflifeCycles(client, p.Slug)
		if err != nil {
			return fmt.Errorf("fetch %s: %w", p.Slug, err)
		}
		allEntries = append(allEntries, transformEndoflifeCycles(p.Slug, p.LibraryName, cycles)...)
	}

	// Manual overlay: stamp Source = "manual" and append.
	for _, m := range wl.Manual {
		m.Source = "manual"
		allEntries = append(allEntries, m)
	}

	sortEntries(allEntries)

	body, err := renderEolEntries(allEntries)
	if err != nil {
		return fmt.Errorf("render: %w", err)
	}

	srcURLs := uniqueSourceURLs(allEntries)
	header := codegen.Header{
		GeneratorName: generatorName,
		Version:       generatorVersion,
		Sources:       srcURLs,
		Watchlist:     watchlistPath,
		PackageName:   "scoring",
	}
	if err := codegen.Emit(outputPath, header, body); err != nil {
		return fmt.Errorf("emit: %w", err)
	}
	fmt.Printf("refresh-eol: wrote %d entries to %s\n", len(allEntries), outputPath)
	return nil
}

func loadWatchlist(path string) (*watchlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wl watchlist
	if err := yaml.Unmarshal(data, &wl); err != nil {
		return nil, err
	}
	return &wl, nil
}

func fetchEndoflifeCycles(c *http.Client, slug string) ([]endoflifeCycle, error) {
	url := fmt.Sprintf("%s/%s.json", endoflifeBase, slug)
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var cycles []endoflifeCycle
	if err := json.Unmarshal(body, &cycles); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return cycles, nil
}

// transformEndoflifeCycles maps a single product's cycles to library_eol_data
// entries. Cycles that are not EOL yet are skipped.
func transformEndoflifeCycles(slug, libraryName string, cycles []endoflifeCycle) []eolEntry {
	var entries []eolEntry
	src := fmt.Sprintf("%s/%s", endoflifeSiteBase, slug)
	now := time.Now()
	for _, c := range cycles {
		eol, isEOL := cycleIsEOL(c.EOL, now)
		if !isEOL {
			continue
		}
		reason := fmt.Sprintf("%s %s EOL %s", titleCase(libraryName), c.Cycle, eol)
		entries = append(entries, eolEntry{
			LibraryName:   strings.ToLower(libraryName),
			VersionPrefix: cyclePrefix(c.Cycle),
			Reason:        reason,
			Source:        src,
		})
	}
	return entries
}

// cycleIsEOL inspects the polymorphic `eol` field. Returns the rendered
// "EOL marker" string + true when the cycle is EOL as of `now`.
func cycleIsEOL(raw any, now time.Time) (string, bool) {
	switch v := raw.(type) {
	case bool:
		if v {
			return "yes", true
		}
		return "", false
	case string:
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return v, true // unparseable but present — treat as EOL with raw string
		}
		if t.Before(now) {
			return v, true
		}
		return v, false
	default:
		return "", false
	}
}

// cyclePrefix converts an endoflife.date cycle string to a version prefix
// suitable for strings.HasPrefix matching.
//
//   - 2-part cycles ("3.1", "1.0") → append "." → "3.1.", "1.0."
//     Real version strings for these cycles always have a third component
//     (e.g. "3.1.4", "1.0.2").
//   - 3-part cycles ("1.0.2", "0.9.8") → no trailing dot → "1.0.2", "0.9.8"
//     Real version strings use letter suffixes without a dot (e.g. "1.0.2k"),
//     so appending "." would prevent any match.
func cyclePrefix(cycle string) string {
	if strings.Count(cycle, ".") >= 2 {
		return cycle // already specific enough; no trailing dot
	}
	return cycle + "."
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func sortEntries(entries []eolEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].LibraryName != entries[j].LibraryName {
			return entries[i].LibraryName < entries[j].LibraryName
		}
		return entries[i].VersionPrefix < entries[j].VersionPrefix
	})
}

func uniqueSourceURLs(entries []eolEntry) []string {
	seen := make(map[string]bool)
	var out []string
	for _, e := range entries {
		if e.Source == "" || e.Source == "manual" {
			continue
		}
		if !seen[e.Source] {
			seen[e.Source] = true
			out = append(out, e.Source)
		}
	}
	sort.Strings(out)
	return out
}

// renderEolEntries returns the Go source body (var declaration + entries).
func renderEolEntries(entries []eolEntry) (string, error) {
	var sb strings.Builder
	sb.WriteString("// eolStarterMap lists library name+version prefixes known to be EOL.\n")
	sb.WriteString("// Match is by (lowercased library_name, version prefix via strings.HasPrefix).\n")
	sb.WriteString("// Generated from endoflife.date — see scripts/catalogs/refresh-eol.go.\n")
	sb.WriteString("var eolStarterMap = []struct {\n")
	sb.WriteString("\tLibraryName   string\n")
	sb.WriteString("\tVersionPrefix string\n")
	sb.WriteString("\tReason        string\n")
	sb.WriteString("\tSource        string\n")
	sb.WriteString("}{\n")
	for _, e := range entries {
		fmt.Fprintf(&sb, "\t{LibraryName: %q, VersionPrefix: %q, Reason: %q, Source: %q},\n",
			e.LibraryName, e.VersionPrefix, e.Reason, e.Source)
	}
	sb.WriteString("}\n")
	return sb.String(), nil
}
