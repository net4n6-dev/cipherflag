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

// declared_cas.go — CLI subcommand for the v1.6.0 shadow-CA registry.
//
// Usage:
//
//	cipherflag declared-cas import --starter
//	cipherflag declared-cas import --file path/to/starter.json
//
// The --starter flag applies a small baked-in list of widely-trusted
// public CA root fingerprints (see publicStarterCAs below). Fingerprints
// not present in the certificates table are skipped — a fresh
// deployment with no observations yet won't find most of them, and
// that's correct behaviour; re-run the command after ingest catches
// up.
//
// The --file flag is designed for operator-curated lists. The file is
// a JSON array of DeclareCARequest shapes (fingerprint_sha256 required,
// owner_team + note optional). Lets an operator ship their own full
// trust-store declaration instead of (or in addition to) the baked
// starter.
//
// Spec: research/shadow-ca-plan-v1.6.0.md §2 decision + §11 deferred
// (full trust-store curation as v1.6.1+).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// publicStarterCAs is a small curated list of widely-trusted public
// root CAs. Used by `cipherflag declared-cas import --starter`.
//
// Each entry records the lowercase-hex SHA-256 fingerprint of the root
// certificate as published in its vendor documentation. Operators
// should verify against their own trust store before relying on this
// list — vendor key-rotations produce new fingerprints that this list
// won't reflect until the next CipherFlag release.
//
// Intentionally short (5 entries) in v1.6.0. Expanding to the full
// Mozilla CA Certificate Program tier is tracked as v1.6.1 work — see
// `docs/roadmap.md` shadow-CA entries. The `--file` flag below is the
// operator-curation escape hatch until then.
var publicStarterCAs = []starterEntry{
	{
		Fingerprint: "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
		Name:        "ISRG Root X1",
		OwnerTeam:   "public-ca",
		Note:        "Let's Encrypt root. Widely deployed; operator-verify against own trust store.",
	},
	{
		Fingerprint: "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161",
		Name:        "DigiCert Global Root CA",
		OwnerTeam:   "public-ca",
		Note:        "DigiCert root. Widely deployed; operator-verify against own trust store.",
	},
	{
		Fingerprint: "8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e",
		Name:        "Amazon Root CA 1",
		OwnerTeam:   "public-ca",
		Note:        "Amazon root. Widely deployed; operator-verify against own trust store.",
	},
	{
		Fingerprint: "ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99",
		Name:        "GlobalSign Root CA",
		OwnerTeam:   "public-ca",
		Note:        "GlobalSign root. Widely deployed; operator-verify against own trust store.",
	},
	{
		Fingerprint: "45140b3247eb9cc8c5b4f0d7b53091f7329208906e5a63e2749dd3aca9198eda",
		Name:        "GoDaddy Root CA G2",
		OwnerTeam:   "public-ca",
		Note:        "GoDaddy root. Widely deployed; operator-verify against own trust store.",
	},
}

type starterEntry struct {
	Fingerprint  string `json:"fingerprint_sha256"`
	Name         string `json:"name,omitempty"`          // human label; not stored in DB, just for log output
	OwnerTeam    string `json:"owner_team,omitempty"`
	Note         string `json:"note,omitempty"`
	HolderHostID string `json:"holder_host_id,omitempty"` // optional host UUID (migration 045)
}

// runDeclaredCAs dispatches the `declared-cas` subcommand. Supports
// `import --starter` and `import --file <path>`. All other args are
// usage errors.
func runDeclaredCAs(ctx context.Context, cfg *config.Config) {
	if len(os.Args) < 3 {
		printDeclaredCAsUsage()
		os.Exit(1)
	}
	switch os.Args[2] {
	case "import":
		runDeclaredCAsImport(ctx, cfg, os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[2])
		printDeclaredCAsUsage()
		os.Exit(1)
	}
}

func printDeclaredCAsUsage() {
	fmt.Println("Usage: cipherflag declared-cas <subcommand> [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  import --starter             Apply the baked-in public-CA starter list")
	fmt.Println("  import --file <path>         Apply an operator-curated JSON file")
	fmt.Println()
	fmt.Println("JSON file format (--file): array of objects with the following fields:")
	fmt.Println("  fingerprint_sha256  (required) lowercase hex SHA-256 of the CA cert")
	fmt.Println("  owner_team          (optional) team that owns this CA")
	fmt.Println("  note                (optional) free-text annotation")
	fmt.Println("  holder_host_id      (optional) UUID of the host holding the CA private key")
	fmt.Println("                      Use when the private key is HSM-resident or otherwise")
	fmt.Println("                      not auto-detected by the certificate scanner.")
	fmt.Println("  name                (optional) human-readable label; logged but not stored")
	fmt.Println()
	fmt.Println("See research/shadow-ca-plan-v1.6.0.md for starter list sourcing.")
}

func runDeclaredCAsImport(ctx context.Context, cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("declared-cas import", flag.ExitOnError)
	useStarter := fs.Bool("starter", false, "apply the baked-in public-CA starter list")
	filePath := fs.String("file", "", "apply entries from a JSON file (array of {fingerprint_sha256, owner_team, note})")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if !*useStarter && *filePath == "" {
		fmt.Fprintln(os.Stderr, "--starter or --file is required")
		printDeclaredCAsUsage()
		os.Exit(1)
	}
	if *useStarter && *filePath != "" {
		fmt.Fprintln(os.Stderr, "--starter and --file are mutually exclusive")
		os.Exit(1)
	}

	entries, err := loadStarterEntries(*useStarter, *filePath)
	if err != nil {
		log.Fatal().Err(err).Msg("load starter entries failed")
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

	var applied, skipped, failed int
	for _, e := range entries {
		fp := strings.ToLower(strings.TrimSpace(e.Fingerprint))
		if fp == "" {
			log.Warn().Str("name", e.Name).Msg("entry missing fingerprint, skipping")
			failed++
			continue
		}
		err := st.DeclareCA(ctx, &store.DeclareCARequest{
			FingerprintSHA256: fp,
			OwnerTeam:         e.OwnerTeam,
			Note:              e.Note,
			HolderHostID:      e.HolderHostID,
		})
		if err != nil {
			// Store distinguishes "not in certificates" (expected — cert
			// hasn't been observed yet) from "is a leaf" (operator error).
			msg := err.Error()
			if strings.Contains(msg, "not in certificates") {
				log.Info().Str("fingerprint", fp).Str("name", e.Name).Msg("not yet observed — skipping (re-run after ingest catches up)")
				skipped++
				continue
			}
			log.Warn().Err(err).Str("fingerprint", fp).Str("name", e.Name).Msg("declare failed")
			failed++
			continue
		}
		log.Info().Str("fingerprint", fp).Str("name", e.Name).Msg("declared")
		applied++
	}
	fmt.Printf("declared-cas import: %d applied, %d skipped (not yet observed), %d failed\n", applied, skipped, failed)
}

func loadStarterEntries(useStarter bool, filePath string) ([]starterEntry, error) {
	if useStarter {
		// Return a copy so callers can't mutate the package-level list.
		out := make([]starterEntry, len(publicStarterCAs))
		copy(out, publicStarterCAs)
		return out, nil
	}
	if filePath == "" {
		return nil, errors.New("no input specified")
	}
	body, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filePath, err)
	}
	var entries []starterEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w (expected JSON array of {fingerprint_sha256, owner_team, note})", filePath, err)
	}
	return entries, nil
}
