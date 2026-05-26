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

// scan_truststore.go — one-shot CLI for scanning the local host's trust stores
// and JKS private-key entries.
//
// Usage: cipherflag scan-truststore --host-id <uuid>
//
// The operator must supply a --host-id that matches an existing row in the
// hosts table; observations are FK-attributed to that host_id.
//
// Spec: docs/superpowers/specs/2026-05-18-l4-f-sp1.6-pki-trusted-by-design.md
// Task: 20 (L4-F SP-1.6)

import (
	"context"
	"flag"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/scanner/configs"
	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
	"github.com/net4n6-dev/cipherflag/internal/scanner/truststore"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// runScanTruststore is the entry point for `cipherflag scan-truststore`.
// It performs a one-shot scan of the local host's trust stores and JKS
// private-key entries, then persists the results via the store upserts.
func runScanTruststore(ctx context.Context, cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("scan-truststore", flag.ExitOnError)
	hostID := fs.String("host-id", "", "UUID of the host this scan is attributed to (must exist in hosts table)")
	if err := fs.Parse(args); err != nil {
		log.Fatal().Err(err).Msg("scan-truststore: flag parse error")
	}

	if *hostID == "" {
		log.Fatal().Msg("scan-truststore: --host-id <uuid> is required")
	}

	st, err := store.NewPostgresStore(ctx, cfg.Storage.PostgresURL)
	if err != nil {
		log.Fatal().Err(err).Msg("scan-truststore: open store")
	}
	defer st.Close()

	// OSRunner is the production CommandRunner; no NewLocal() constructor exists.
	runner := executil.OSRunner{}
	scanner := truststore.New(runner, st, cfg.Scanners.JVMKeystorePasswords)

	log.Info().Str("host_id", *hostID).Msg("scan-truststore: starting")

	result, err := scanner.Scan(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("scan-truststore: scan failed")
	}

	// Collect trust-bundle refs declared in application configs (nginx,
	// Apache, PostgreSQL) and ingest the referenced PEM bundles as
	// app_config-sourced observations.
	cfgScanner := configs.New(runner)
	appRefs := cfgScanner.ScanTrustBundles(ctx, truststore.TrustBundlePaths)
	if len(appRefs) > 0 {
		appObs, err := truststore.IngestAppConfigBundles(appRefs)
		if err != nil {
			// IngestAppConfigBundles always returns nil error (log-and-continue
			// semantics), but handle defensively.
			log.Warn().Err(err).Msg("scan-truststore: app_config bundle ingest partial error")
		}
		result.TrustStore = append(result.TrustStore, appObs...)
		log.Info().
			Int("refs", len(appRefs)).
			Int("observations", len(appObs)).
			Msg("scan-truststore: app_config trust bundles ingested")
	}

	// Stamp host_id on every observation before persisting.
	for i := range result.TrustStore {
		result.TrustStore[i].HostID = *hostID
	}
	for i := range result.PrivateKey {
		result.PrivateKey[i].HostID = *hostID
	}

	if err := st.UpsertTrustStoreObservations(ctx, result.TrustStore); err != nil {
		log.Fatal().Err(err).Msg("scan-truststore: write trust store observations")
	}
	if err := st.UpsertPrivateKeyHoldings(ctx, result.PrivateKey); err != nil {
		log.Fatal().Err(err).Msg("scan-truststore: write private-key holdings")
	}

	// Warn for any discoverer that reported a non-empty error string so
	// the operator can spot silent failures without losing the overall
	// scan result (resilience semantics are preserved).
	for name, oc := range result.DiscovererResults {
		if oc.Err != "" {
			log.Warn().
				Str("discoverer", name).
				Str("error", oc.Err).
				Msg("scan-truststore: discoverer reported an error")
		}
	}

	log.Info().
		Str("host_id", *hostID).
		Int("bundles_scanned", result.BundlesScanned).
		Int("trust_store_observations", len(result.TrustStore)).
		Int("private_key_observations", len(result.PrivateKey)).
		Msg("scan-truststore: complete")
}
