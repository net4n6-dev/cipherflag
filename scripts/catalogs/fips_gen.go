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

// fips_gen.go contains the shared types and logic for refresh-fips.go.
// The entry-point (func main) lives in refresh-fips.go which carries
// //go:build ignore so `go build ./...` skips it while `go test ./...`
// still compiles and exercises these helpers.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	fipsGeneratorName    = "refresh-fips.go"
	fipsGeneratorVersion = "v1"
	fipsOutputPath       = "../../internal/analysis/scoring/library_fips_data.go"
	fipsWatchlistPath    = "watchlists/fips.yaml"
	cmvpCertURLTemplate  = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/%d"
)

type fipsWatchlist struct {
	Entries []fipsEntry `yaml:"entries"`
}

type fipsEntry struct {
	LibraryName   string `yaml:"library_name"`
	VersionPrefix string `yaml:"version_prefix"`
	Cert          int    `yaml:"cert"`
	Expires       string `yaml:"expires"`
	Note          string `yaml:"note"`
	FIPSLevel     string `yaml:"fips_level"`
}

func loadFipsWatchlist(path string) (*fipsWatchlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wl fipsWatchlist
	if err := yaml.Unmarshal(data, &wl); err != nil {
		return nil, err
	}
	return &wl, nil
}

func collectFipsWarnings(entries []fipsEntry) []string {
	now := time.Now()
	var warnings []string
	for _, e := range entries {
		if e.Expires == "" {
			continue
		}
		t, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("entry %s/%s: unparseable expires %q",
				e.LibraryName, e.VersionPrefix, e.Expires))
			continue
		}
		if t.Before(now) {
			warnings = append(warnings, fmt.Sprintf("entry %s/%s expired on %s — consider removing",
				e.LibraryName, e.VersionPrefix, e.Expires))
		}
	}
	return warnings
}

func renderFipsEntries(entries []fipsEntry) (string, error) {
	var sb strings.Builder
	sb.WriteString("import \"strings\"\n\n")
	sb.WriteString("// fipsStarterMap lists library name+version prefixes known to have\n")
	sb.WriteString("// FIPS 140-2/140-3 validated builds. Match is by (lowercased library_name,\n")
	sb.WriteString("// version prefix via strings.HasPrefix). Generated from watchlists/fips.yaml.\n")
	sb.WriteString("var fipsStarterMap = []struct {\n")
	sb.WriteString("\tLibraryName   string\n")
	sb.WriteString("\tVersionPrefix string\n")
	sb.WriteString("\tNote          string\n")
	sb.WriteString("\tFIPSLevel     string\n")
	sb.WriteString("\tSource        string\n")
	sb.WriteString("}{\n")
	for _, e := range entries {
		source := "manual"
		if e.Cert > 0 {
			source = fmt.Sprintf(cmvpCertURLTemplate, e.Cert)
		}
		fmt.Fprintf(&sb, "\t{LibraryName: %q, VersionPrefix: %q, Note: %q, FIPSLevel: %q, Source: %q},\n",
			e.LibraryName, e.VersionPrefix, e.Note, e.FIPSLevel, source)
	}
	sb.WriteString("}\n\n")
	// Preserve a strings reference so the import isn't unused if no other code uses it.
	sb.WriteString("// Quiet unused-import warnings if no other code in this file uses strings.\n")
	sb.WriteString("var _ = strings.HasPrefix\n")
	return sb.String(), nil
}
