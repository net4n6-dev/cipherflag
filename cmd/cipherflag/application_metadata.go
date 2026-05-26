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

// application_metadata.go — CLI for the v1.7.0 HNDL TTL registry.
//
// Usage:
//
//	cipherflag application-metadata presets
//	cipherflag application-metadata declare --tag <t> --preset <p> [--owner <team>] [--note <text>]
//	cipherflag application-metadata declare --tag <t> --ttl-years <n>   [--owner <team>] [--note <text>]
//	cipherflag application-metadata import --file <path>
//
// Presets ship as a baked-in (compliance-profile → default-TTL-years)
// table. Operators pick the matching profile per application tag;
// operators who need exact TTLs supply --ttl-years directly or use the
// import file path for batch declarations with explicit values.
//
// Spec: research/hndl-plan-v1.7.0.md §3 P4.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// appMetaPreset is one compliance-profile → default TTL entry.
// Descriptions cite the specific regulatory basis so operators can
// verify fit with their own compliance posture before committing.
type appMetaPreset struct {
	Name      string
	TTLYears  int
	Context   string
	Citation  string
}

// appMetaPresets is the baked-in table. User decision #5 on the plan
// explicitly asked for US-fed-relevant entries alongside common
// commercial compliance contexts.
//
// TTL values are conservative defaults — operators should verify
// against their own retention schedule. For v1.7.0 we ship these 8;
// the Mozilla-trust-store-equivalent expansion to finer-grained sub-
// variants lands as v1.7.1+ work (tracked in docs/roadmap.md).
var appMetaPresets = []appMetaPreset{
	// Commercial / cross-jurisdiction
	{
		Name: "pci-dss", TTLYears: 7,
		Context:  "PCI-DSS card-data retention + fraud investigation window.",
		Citation: "PCI-DSS 4.0 requirement 3.3.1 / 3.2 + industry fraud-window practice.",
	},
	{
		Name: "hipaa", TTLYears: 25,
		Context:  "HIPAA protected health information + state-law extensions.",
		Citation: "HIPAA 45 CFR 164.530(j); state pediatric extensions push past age of majority.",
	},
	{
		Name: "sox", TTLYears: 7,
		Context:  "Sarbanes-Oxley financial audit records.",
		Citation: "SOX §103 + SEC 17 CFR 210.2-06(a).",
	},
	{
		Name: "gdpr", TTLYears: 3,
		Context:  "GDPR default retention (operators should narrow per article-specific grounds).",
		Citation: "GDPR Art. 5(1)(e) storage-limitation; typical default before explicit basis.",
	},
	// US federal
	{
		Name: "fisma-moderate", TTLYears: 7,
		Context:  "FISMA Moderate-impact systems — NIST SP 800-53 baseline retention.",
		Citation: "NIST SP 800-53 Rev. 5 AU-11 / SI-12; OMB Circular A-130.",
	},
	{
		Name: "fisma-high", TTLYears: 20,
		Context:  "FISMA High-impact + High-Value Assets. Aligns with OMB M-23-02 mission-sensitive-in-2035 scope.",
		Citation: "OMB M-23-02 §II.A; NIST SP 800-53 Rev. 5 High baseline.",
	},
	{
		Name: "nss-cnsa2", TTLYears: 25,
		Context:  "National Security Systems — CNSA 2.0 mandate. HNDL-primary-target traffic.",
		Citation: "NSM-10 §3; CNSS Policy 15; NSA CNSA 2.0 migration timeline (2030 transition, 2035 completion).",
	},
	{
		Name: "nara-permanent", TTLYears: 100,
		Context:  "NARA permanent federal records. Effectively indefinite protection.",
		Citation: "44 USC Ch. 33; NARA General Records Schedules designated 'permanent'.",
	},
}

// presetByName returns the preset for the given name; nil if unknown.
func presetByName(name string) *appMetaPreset {
	for i := range appMetaPresets {
		if appMetaPresets[i].Name == name {
			return &appMetaPresets[i]
		}
	}
	return nil
}

// appMetaImportEntry is one row in the batch JSON file. Either Preset
// or (TTLYears / SensitiveUntil) must be set; Preset wins if both
// are present.
type appMetaImportEntry struct {
	Tag                string  `json:"tag"`
	Preset             string  `json:"preset,omitempty"`
	DataTTLYears       *int    `json:"data_ttl_years,omitempty"`
	DataSensitiveUntil *string `json:"data_sensitive_until,omitempty"` // RFC3339
	OwnerTeam          string  `json:"owner_team,omitempty"`
	Note               string  `json:"note,omitempty"`
}

// runApplicationMetadata dispatches the `application-metadata`
// subcommand. Three verbs: presets / declare / import.
func runApplicationMetadata(ctx context.Context, cfg *config.Config) {
	if len(os.Args) < 3 {
		printAppMetaUsage()
		os.Exit(1)
	}
	switch os.Args[2] {
	case "presets":
		printPresets()
	case "declare":
		runAppMetaDeclare(ctx, cfg, os.Args[3:])
	case "import":
		runAppMetaImport(ctx, cfg, os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[2])
		printAppMetaUsage()
		os.Exit(1)
	}
}

func printAppMetaUsage() {
	fmt.Println("Usage: cipherflag application-metadata <subcommand> [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  presets                                          Print the baked-in compliance-preset table")
	fmt.Println("  declare --tag <t> --preset <p>                   Declare a single application's TTL via preset")
	fmt.Println("  declare --tag <t> --ttl-years <n>                Declare a single application's TTL explicitly")
	fmt.Println("  import  --file <path>                            Batch declare from a JSON array")
	fmt.Println()
	fmt.Println("Common flags on declare:  --owner <team>  --note <text>")
	fmt.Println()
	fmt.Println("See research/hndl-plan-v1.7.0.md for preset sourcing + US-fed context.")
}

func printPresets() {
	// Sort alphabetically by name for readable tabular output.
	sorted := make([]appMetaPreset, len(appMetaPresets))
	copy(sorted, appMetaPresets)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	// Column widths.
	var nameW, ttlW int
	for _, p := range sorted {
		if len(p.Name) > nameW {
			nameW = len(p.Name)
		}
		ttlStr := fmt.Sprintf("%dy", p.TTLYears)
		if len(ttlStr) > ttlW {
			ttlW = len(ttlStr)
		}
	}
	if nameW < 14 {
		nameW = 14
	}
	if ttlW < 4 {
		ttlW = 4
	}

	fmt.Printf("%-*s  %-*s  %s\n", nameW, "PRESET", ttlW, "TTL", "CONTEXT")
	fmt.Printf("%-*s  %-*s  %s\n", nameW, strings.Repeat("-", nameW), ttlW, strings.Repeat("-", ttlW), strings.Repeat("-", 60))
	for _, p := range sorted {
		fmt.Printf("%-*s  %-*s  %s\n", nameW, p.Name, ttlW, fmt.Sprintf("%dy", p.TTLYears), p.Context)
		if p.Citation != "" {
			fmt.Printf("%-*s  %-*s    %s\n", nameW, "", ttlW, "", "citation: "+p.Citation)
		}
	}
	fmt.Println()
	fmt.Println("Override any preset's TTL by passing --ttl-years explicitly; use --file for batch.")
}

func runAppMetaDeclare(ctx context.Context, cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("application-metadata declare", flag.ExitOnError)
	tag := fs.String("tag", "", "application tag (required)")
	preset := fs.String("preset", "", "compliance preset name (run `presets` to list)")
	ttlYears := fs.Int("ttl-years", -1, "explicit TTL override in years (0..100)")
	owner := fs.String("owner", "", "owner team (optional metadata)")
	note := fs.String("note", "", "free-form note (optional metadata)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if strings.TrimSpace(*tag) == "" {
		fmt.Fprintln(os.Stderr, "--tag is required")
		os.Exit(1)
	}
	if *preset == "" && *ttlYears < 0 {
		fmt.Fprintln(os.Stderr, "--preset or --ttl-years is required")
		os.Exit(1)
	}
	if *preset != "" && *ttlYears >= 0 {
		fmt.Fprintln(os.Stderr, "--preset and --ttl-years are mutually exclusive")
		os.Exit(1)
	}

	var resolvedTTL int
	var resolvedNote string = *note
	if *preset != "" {
		p := presetByName(*preset)
		if p == nil {
			fmt.Fprintf(os.Stderr, "unknown preset: %s (run `cipherflag application-metadata presets` to list)\n", *preset)
			os.Exit(1)
		}
		resolvedTTL = p.TTLYears
		if resolvedNote == "" {
			resolvedNote = "preset=" + p.Name + " — " + p.Context
		}
	} else {
		if *ttlYears < 0 || *ttlYears > 100 {
			fmt.Fprintf(os.Stderr, "--ttl-years must be 0..100, got %d\n", *ttlYears)
			os.Exit(1)
		}
		resolvedTTL = *ttlYears
	}

	st, err := store.NewPostgresStore(ctx, cfg.Storage.PostgresURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect postgres")
	}
	defer st.Close()

	ttl := resolvedTTL
	req := &store.DeclareApplicationMetadataRequest{
		Tag:          strings.TrimSpace(*tag),
		DataTTLYears: &ttl,
		OwnerTeam:    strings.TrimSpace(*owner),
		Note:         resolvedNote,
	}
	if err := st.UpsertApplicationMetadata(ctx, req); err != nil {
		log.Fatal().Err(err).Str("tag", req.Tag).Msg("declare failed")
	}
	fmt.Printf("application-metadata declare: %s → ttl_years=%d (preset=%s)\n",
		req.Tag, resolvedTTL, nonEmpty(*preset, "explicit"))
}

func runAppMetaImport(ctx context.Context, cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("application-metadata import", flag.ExitOnError)
	filePath := fs.String("file", "", "JSON file containing an array of entries (required)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if strings.TrimSpace(*filePath) == "" {
		fmt.Fprintln(os.Stderr, "--file is required")
		os.Exit(1)
	}

	entries, err := loadAppMetaEntries(*filePath)
	if err != nil {
		log.Fatal().Err(err).Str("path", *filePath).Msg("load entries failed")
	}
	if len(entries) == 0 {
		fmt.Println("No entries to apply.")
		return
	}

	st, err := store.NewPostgresStore(ctx, cfg.Storage.PostgresURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect postgres")
	}
	defer st.Close()

	// Build the set of known application tags so we can skip-and-warn
	// on declarations whose tag doesn't appear in any asset. Matches
	// the v1.6.0 shadow-CA CLI's "not yet observed" semantics.
	knownTags := map[string]bool{}
	if apps, err := st.ListApplications(ctx, nil); err == nil {
		for _, a := range apps {
			knownTags[a.Tag] = true
		}
	}

	var applied, skipped, failed int
	for _, e := range entries {
		tag := strings.TrimSpace(e.Tag)
		if tag == "" {
			log.Warn().Msg("entry missing tag, skipping")
			failed++
			continue
		}

		// Validate preset OR explicit TTL.
		var ttl int
		var useTTL bool
		if e.Preset != "" {
			p := presetByName(e.Preset)
			if p == nil {
				log.Warn().Str("tag", tag).Str("preset", e.Preset).Msg("unknown preset, skipping")
				failed++
				continue
			}
			ttl = p.TTLYears
			useTTL = true
			if e.Note == "" {
				e.Note = "preset=" + p.Name + " — " + p.Context
			}
		} else if e.DataTTLYears != nil {
			ttl = *e.DataTTLYears
			useTTL = true
		} else if e.DataSensitiveUntil == nil {
			log.Warn().Str("tag", tag).Msg("entry missing preset / ttl_years / sensitive_until, skipping")
			failed++
			continue
		}

		if len(knownTags) > 0 && !knownTags[tag] {
			log.Info().Str("tag", tag).Msg("tag not found in inventory — skipping (re-run after tagging assets)")
			skipped++
			continue
		}

		req := &store.DeclareApplicationMetadataRequest{
			Tag:       tag,
			OwnerTeam: strings.TrimSpace(e.OwnerTeam),
			Note:      e.Note,
		}
		if useTTL {
			req.DataTTLYears = &ttl
		}
		// Explicit absolute-date handling (if the import entry supplied
		// one rather than a preset). Not common but covered for
		// operators who ship regulatory-sunset dates.
		if e.DataSensitiveUntil != nil {
			parsed, perr := parseRFC3339OrDate(*e.DataSensitiveUntil)
			if perr != nil {
				log.Warn().Err(perr).Str("tag", tag).Msg("invalid data_sensitive_until, skipping")
				failed++
				continue
			}
			req.DataSensitiveUntil = &parsed
		}

		if err := st.UpsertApplicationMetadata(ctx, req); err != nil {
			log.Warn().Err(err).Str("tag", tag).Msg("declare failed")
			failed++
			continue
		}
		log.Info().Str("tag", tag).Int("ttl_years", ttl).Msg("declared")
		applied++
	}
	fmt.Printf("application-metadata import: %d applied, %d skipped (tag not found in inventory), %d failed\n",
		applied, skipped, failed)
}

func loadAppMetaEntries(path string) ([]appMetaImportEntry, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []appMetaImportEntry
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w (expected JSON array of {tag, preset|data_ttl_years, owner_team?, note?})", path, err)
	}
	return out, nil
}

// nonEmpty returns a if non-empty, else b. Tiny helper for the CLI
// summary printout.
func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parseRFC3339OrDate accepts both full RFC3339 timestamps and
// YYYY-MM-DD bare dates (interpreted as UTC midnight). Operators
// hand-rolling files find YYYY-MM-DD natural; RFC3339 is there for
// scripted tooling that already emits timestamps.
func parseRFC3339OrDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty time string")
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if v, err := time.Parse(layout, s); err == nil {
			return v, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised time format: %s (expected RFC3339 or YYYY-MM-DD)", s)
}
