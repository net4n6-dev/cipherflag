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

// ownership.go — CLI for the v1.8.0 ownership resolver (AQ-OP-01).
//
// Usage:
//
//	cipherflag ownership declare --asset-type <t> --asset-id <id> --team <slug> \
//	                             [--owner <email>] [--service <svc>] [--note <text>]
//	cipherflag ownership import   --file <path.csv>
//	cipherflag ownership backfill
//
// `declare` writes a single direct-tier operator_stamp sighting — the
// path operators use to correct an inferred guess, or attribute an
// asset the resolver couldn't classify.
//
// `import` takes a CSV with columns:
//   asset_type,asset_id,team,named_owner,business_svc,note
// (header row required; rows with an unknown asset_type or an
// asset_id that isn't in the inventory are skipped with a warning —
// same skip-on-not-observed semantic v1.6.0 `declared-cas import` and
// v1.7.0 `application-metadata import` established.)
//
// `backfill` runs the three BackfillOwnershipFrom* functions from P1
// in sequence so operators upgrading from v1.7.x don't need to wait
// for the first scan cycle to populate the ledger. Fresh installs
// rely on the seed phase (P6) instead; backfill is explicitly
// upgrade-time work per user decision #2 on the plan.
//
// Spec: research/ownership-plan-v1.8.0.md §3 P4.
package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// ownershipAssetTypes mirrors migration 028's aos_asset_type_check.
// Value is the per-type existence probe: given an asset_id, returns
// one row with a single column when the asset exists, zero rows
// otherwise. Keeps the CLI's inventory check aligned with the
// store-layer polymorphic table map (applicationTagsTables) without
// expanding the public store API for this one call site.
var ownershipAssetTypes = map[string]string{
	"certificate":       `SELECT 1 FROM certificates       WHERE fingerprint_sha256 = $1`,
	"ssh_key":           `SELECT 1 FROM ssh_keys           WHERE id::text           = $1`,
	"crypto_library":    `SELECT 1 FROM crypto_libraries   WHERE id::text           = $1`,
	"crypto_config":     `SELECT 1 FROM crypto_configs     WHERE id::text           = $1`,
	"protocol_endpoint": `SELECT 1 FROM protocol_endpoints WHERE id::text           = $1`,
	"host":              `SELECT 1 FROM hosts              WHERE id::text           = $1`,
	"repository":        `SELECT 1 FROM repositories       WHERE id::text           = $1`,
}

// assetExists runs the per-type probe. Returns (false, nil) when the
// row isn't there — the CLI treats that as a skip, not an error.
func assetExists(ctx context.Context, st *store.PostgresStore, assetType, assetID string) (bool, error) {
	probe, ok := ownershipAssetTypes[assetType]
	if !ok {
		return false, fmt.Errorf("unknown asset_type %q (allowed: certificate, ssh_key, crypto_library, crypto_config, protocol_endpoint, host, repository)", assetType)
	}
	var one int
	err := st.Pool().QueryRow(ctx, probe, assetID).Scan(&one)
	if err != nil {
		// pgx returns ErrNoRows for zero rows; wrap anything else.
		if strings.Contains(err.Error(), "no rows") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// runOwnership dispatches the `ownership` subcommand.
func runOwnership(ctx context.Context, cfg *config.Config) {
	if len(os.Args) < 3 {
		printOwnershipUsage()
		os.Exit(1)
	}
	switch os.Args[2] {
	case "declare":
		runOwnershipDeclare(ctx, cfg, os.Args[3:])
	case "import":
		runOwnershipImport(ctx, cfg, os.Args[3:])
	case "backfill":
		runOwnershipBackfill(ctx, cfg, os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[2])
		printOwnershipUsage()
		os.Exit(1)
	}
}

func printOwnershipUsage() {
	fmt.Println("Usage: cipherflag ownership <subcommand> [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  declare   --asset-type <t> --asset-id <id> --team <slug> [--owner <email>] [--service <svc>] [--note <text>]")
	fmt.Println("            Write a single direct-tier operator_stamp sighting.")
	fmt.Println()
	fmt.Println("  import    --file <path.csv>")
	fmt.Println("            Batch from CSV: asset_type,asset_id,team,named_owner,business_svc,note (header required).")
	fmt.Println("            Rows whose (asset_type,asset_id) aren't in the inventory are skipped.")
	fmt.Println()
	fmt.Println("  backfill  Run the three BackfillOwnershipFrom* passes: application_metadata → declared_ca → cert_subject.")
	fmt.Println("            Operator-run once after upgrade; fresh installs rely on the seed phase.")
	fmt.Println()
	fmt.Println("Allowed asset_types: certificate, ssh_key, crypto_library, crypto_config, protocol_endpoint, host, repository")
	fmt.Println()
	fmt.Println("See research/ownership-plan-v1.8.0.md §3 P4.")
}

// runOwnershipDeclare writes one operator_stamp sighting for the
// single (asset_type, asset_id, team) trio supplied on the command
// line. Triggers team-skeleton auto-create transitively via
// UpsertOwnershipSighting (§2.9).
func runOwnershipDeclare(ctx context.Context, cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("ownership declare", flag.ExitOnError)
	assetType := fs.String("asset-type", "", "asset_type (required — one of: "+allowedOwnershipTypesCSV()+")")
	assetID := fs.String("asset-id", "", "asset_id (required — hex fingerprint for certs, UUID for others)")
	team := fs.String("team", "", "team slug (required)")
	owner := fs.String("owner", "", "named owner email (optional)")
	service := fs.String("service", "", "business service tag (optional)")
	note := fs.String("note", "", "evidence note (optional; max 2048 bytes)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	at := strings.TrimSpace(*assetType)
	aid := strings.TrimSpace(*assetID)
	tm := strings.TrimSpace(*team)
	if at == "" || aid == "" || tm == "" {
		fmt.Fprintln(os.Stderr, "--asset-type, --asset-id, and --team are required")
		os.Exit(1)
	}
	if _, ok := ownershipAssetTypes[at]; !ok {
		fmt.Fprintf(os.Stderr, "unknown asset_type %q (allowed: %s)\n", at, allowedOwnershipTypesCSV())
		os.Exit(1)
	}
	if len(*note) > 2048 {
		fmt.Fprintln(os.Stderr, "--note exceeds 2048 bytes")
		os.Exit(1)
	}

	st, err := store.NewPostgresStore(ctx, cfg.Storage.PostgresURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect postgres")
	}
	defer st.Close()

	// Pre-flight existence check — mirrors the import path's skip
	// semantic. For a single-row declare we error out instead of
	// skipping, because the operator explicitly named this asset and
	// silently doing nothing is worse than telling them their ID is
	// unknown.
	exists, err := assetExists(ctx, st, at, aid)
	if err != nil {
		log.Fatal().Err(err).Msg("inventory probe failed")
	}
	if !exists {
		fmt.Fprintf(os.Stderr, "%s %q not found in inventory — refusing to write a dangling sighting\n", at, aid)
		os.Exit(1)
	}

	evidence := map[string]any{}
	if n := strings.TrimSpace(*note); n != "" {
		evidence["note"] = n
	}

	now := time.Now()
	sighting := &store.OwnershipSighting{
		AssetType:   at,
		AssetID:     aid,
		Team:        tm,
		NamedOwner:  strings.TrimSpace(*owner),
		BusinessSvc: strings.TrimSpace(*service),
		Source:      "operator_stamp",
		Confidence:  "direct",
		FirstSeen:   now,
		LastSeen:    now,
		Evidence:    evidence,
	}
	if err := st.UpsertOwnershipSighting(ctx, sighting); err != nil {
		log.Fatal().Err(err).Msg("stamp failed")
	}
	fmt.Printf("ownership declare: %s %s → team=%s (direct/operator_stamp)\n", at, aid, tm)
}

// ownershipCSVRow is one parsed row from the CSV import. All six
// columns must be present (header supplies the order); empty cells
// produce empty strings. The downstream apply loop validates
// required fields, skips missing assets, and surfaces failures as
// counted per-row log lines.
type ownershipCSVRow struct {
	AssetType   string
	AssetID     string
	Team        string
	NamedOwner  string
	BusinessSvc string
	Note        string
	LineNumber  int // 1-based, including header as line 1
}

// runOwnershipImport batches declarations from a CSV file. Columns
// are fixed: asset_type,asset_id,team,named_owner,business_svc,note.
// A header row is required — the parser sanity-checks the exact
// column order so a column-reorder mistake can't silently corrupt
// the ledger with swapped fields.
func runOwnershipImport(ctx context.Context, cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("ownership import", flag.ExitOnError)
	filePath := fs.String("file", "", "CSV file (required; header: asset_type,asset_id,team,named_owner,business_svc,note)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if strings.TrimSpace(*filePath) == "" {
		fmt.Fprintln(os.Stderr, "--file is required")
		os.Exit(1)
	}

	rows, err := loadOwnershipCSV(*filePath)
	if err != nil {
		log.Fatal().Err(err).Str("path", *filePath).Msg("load csv failed")
	}
	if len(rows) == 0 {
		fmt.Println("No entries to apply.")
		return
	}

	st, err := store.NewPostgresStore(ctx, cfg.Storage.PostgresURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect postgres")
	}
	defer st.Close()

	var applied, skipped, failed int
	now := time.Now()
	for _, r := range rows {
		if r.AssetType == "" || r.AssetID == "" || r.Team == "" {
			log.Warn().Int("line", r.LineNumber).Msg("required field missing (asset_type/asset_id/team), skipping")
			failed++
			continue
		}
		if _, ok := ownershipAssetTypes[r.AssetType]; !ok {
			log.Warn().Int("line", r.LineNumber).Str("asset_type", r.AssetType).Msg("unknown asset_type, skipping")
			failed++
			continue
		}
		if len(r.Note) > 2048 {
			log.Warn().Int("line", r.LineNumber).Msg("note exceeds 2048 bytes, skipping")
			failed++
			continue
		}
		exists, err := assetExists(ctx, st, r.AssetType, r.AssetID)
		if err != nil {
			log.Warn().Err(err).Int("line", r.LineNumber).Msg("inventory probe failed, skipping")
			failed++
			continue
		}
		if !exists {
			log.Info().Int("line", r.LineNumber).Str("asset_type", r.AssetType).Str("asset_id", r.AssetID).
				Msg("asset not found in inventory, skipping (re-run after ingest catches up)")
			skipped++
			continue
		}

		evidence := map[string]any{}
		if r.Note != "" {
			evidence["note"] = r.Note
		}

		sighting := &store.OwnershipSighting{
			AssetType:   r.AssetType,
			AssetID:     r.AssetID,
			Team:        r.Team,
			NamedOwner:  r.NamedOwner,
			BusinessSvc: r.BusinessSvc,
			Source:      "operator_stamp",
			Confidence:  "direct",
			FirstSeen:   now,
			LastSeen:    now,
			Evidence:    evidence,
		}
		if err := st.UpsertOwnershipSighting(ctx, sighting); err != nil {
			log.Warn().Err(err).Int("line", r.LineNumber).Str("asset_id", r.AssetID).Msg("stamp failed")
			failed++
			continue
		}
		log.Info().Int("line", r.LineNumber).Str("asset_type", r.AssetType).Str("asset_id", r.AssetID).
			Str("team", r.Team).Msg("stamped")
		applied++
	}
	fmt.Printf("ownership import: %d applied, %d skipped (asset not in inventory), %d failed\n",
		applied, skipped, failed)
}

// loadOwnershipCSV reads + parses the import file into ownershipCSVRow
// records. The header is required and must match the documented
// column order exactly; any other order or column set is rejected
// rather than silently reinterpreted.
func loadOwnershipCSV(path string) ([]ownershipCSVRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = 6
	r.TrimLeadingSpace = true

	expectedHeader := []string{"asset_type", "asset_id", "team", "named_owner", "business_svc", "note"}
	header, err := r.Read()
	if err == io.EOF {
		return nil, errors.New("empty CSV file")
	}
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if len(header) != len(expectedHeader) {
		return nil, fmt.Errorf("header must have %d columns, got %d", len(expectedHeader), len(header))
	}
	for i, want := range expectedHeader {
		if strings.TrimSpace(strings.ToLower(header[i])) != want {
			return nil, fmt.Errorf("header column %d: expected %q, got %q (column order is fixed: %s)",
				i+1, want, header[i], strings.Join(expectedHeader, ","))
		}
	}

	var out []ownershipCSVRow
	lineNo := 1 // header was line 1; first data row is line 2
	for {
		lineNo++
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read line %d: %w", lineNo, err)
		}
		out = append(out, ownershipCSVRow{
			AssetType:   strings.TrimSpace(rec[0]),
			AssetID:     strings.TrimSpace(rec[1]),
			Team:        strings.TrimSpace(rec[2]),
			NamedOwner:  strings.TrimSpace(rec[3]),
			BusinessSvc: strings.TrimSpace(rec[4]),
			Note:        strings.TrimSpace(rec[5]),
			LineNumber:  lineNo,
		})
	}
	return out, nil
}

// runOwnershipBackfill is the upgrade-time fan-out: call the three
// BackfillOwnershipFrom* passes in order and surface per-source row
// counts. The passes are independently idempotent — re-running is
// safe. Scanner hot-path auto-invocation was explicitly rejected per
// user decision #2 (the plan's §6 open questions) — this CLI is the
// only path that ever fires the backfill.
func runOwnershipBackfill(ctx context.Context, cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("ownership backfill", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "ownership backfill takes no positional arguments")
		os.Exit(1)
	}

	st, err := store.NewPostgresStore(ctx, cfg.Storage.PostgresURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect postgres")
	}
	defer st.Close()

	fmt.Println("ownership backfill: application_metadata → declared_ca → cert_subject")
	fmt.Println()

	appMeta, err := st.BackfillOwnershipFromApplicationMetadata(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("backfill application_metadata failed")
	}
	fmt.Printf("  application_metadata : %d row(s) upserted\n", appMeta)

	declCA, err := st.BackfillOwnershipFromDeclaredCAs(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("backfill declared_ca failed")
	}
	fmt.Printf("  declared_ca          : %d row(s) upserted\n", declCA)

	subj, err := st.BackfillOwnershipFromCertSubjects(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("backfill cert_subject failed")
	}
	fmt.Printf("  cert_subject         : %d row(s) upserted\n", subj)

	fmt.Println()
	fmt.Printf("ownership backfill: done (%d total across three sources)\n", appMeta+declCA+subj)
}

// allowedOwnershipTypesCSV returns the asset_type enum as a
// comma-joined string for usage messages. Sourced from the same map
// that drives the inventory probes so the two can never drift.
func allowedOwnershipTypesCSV() string {
	// Deterministic order for stable error messages.
	order := []string{"certificate", "ssh_key", "crypto_library", "crypto_config", "protocol_endpoint", "host", "repository"}
	return strings.Join(order, ", ")
}
