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
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/analysis/scoring"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/scanner/configs"
	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
	"github.com/net4n6-dev/cipherflag/internal/scanner/truststore"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// runScanTruststore is the entry point for `cipherflag scan-truststore`.
// It performs a one-shot scan of the local host's trust stores and JKS
// private-key entries, then persists the results via the store upserts.
func runScanTruststore(ctx context.Context, cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("scan-truststore", flag.ContinueOnError)
	hostID := fs.String("host-id", "", "UUID of the host this scan is attributed to (must exist in hosts table)")
	parseSubcommandFlags(fs, args)

	if *hostID == "" {
		usageError(fs, "--host-id <uuid> is required")
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

	var scorer scoring.Scorer = scoring.NewNoopScorer()
	if cfg.Analysis.ScorerEnabled {
		scorer = scoring.NewDispatcher(st)
	}
	ing := ingest.NewUnifiedIngester(st, ingest.WithScorer(scorer))
	covered, privateKeys := result.CoveredSources()
	scope := reconcileScope{
		// The app_config pass above always runs (its per-file problems are
		// logged, not returned), so its source is always covered.
		TrustSources: append(covered, "app_config"),
		PrivateKeys:  privateKeys,
	}
	if err := persistTrustStoreScan(ctx, st, ing, *hostID, result, scope); err != nil {
		log.Fatal().Err(err).Msg("scan-truststore: persist scan")
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

// reconcileScope is what a scan fully covered, so what it may prune: the
// trust-store sources whose discoverers all succeeded (plus app_config,
// which scan-truststore collects itself) and whether private keys were
// covered. The zero value prunes nothing.
type reconcileScope struct {
	TrustSources []string
	PrivateKeys  bool
}

// certIngester is the part of ingest.UnifiedIngester persistTrustStoreScan uses.
type certIngester interface {
	Ingest(ctx context.Context, result *ingest.DiscoveryResult) (*ingest.IngestionSummary, error)
}

// persistTrustStoreScan writes one scan's results for hostID. host_trust_store
// and cert_private_key_holding reference certificates by fingerprint, so the
// scanned certificates are stored first, through the normal ingest path
// (metadata filled from the PEM, provenance on the scanned host, scoring).
// Without that, every row for a certificate CipherFlag had not already seen
// failed its foreign key and was dropped: on a fresh install, all of them.
//
// Then the scan is reconciled: for each source in scope, rows this scan did
// not refresh (a CA or key that is no longer there) are removed. A source
// with a row that could not be written is left alone, since it was not
// fully recorded. The cutoff is the database clock read before any write,
// the clock that stamps last_seen, so a host clock running ahead of the
// database cannot remove rows the scan has just written.
func persistTrustStoreScan(ctx context.Context, st *store.PostgresStore, ing certIngester, hostID string, result truststore.ScanResult, scope reconcileScope) error {
	watermark, err := st.DatabaseNow(ctx)
	if err != nil {
		return err
	}
	if certs := scannedCertificates(result); len(certs) > 0 {
		if _, err := ing.Ingest(ctx, &ingest.DiscoveryResult{
			Source:             "truststore",
			SourceHostID:       hostID,
			SkipHostResolution: true,
			Timestamp:          time.Now().UTC(),
			Certificates:       certs,
		}); err != nil {
			return fmt.Errorf("store scanned certificates: %w", err)
		}
	}
	trustFailed, err := st.UpsertTrustStoreObservations(ctx, result.TrustStore)
	if err != nil {
		return fmt.Errorf("write trust store observations: %w", err)
	}
	keysFailed, err := st.UpsertPrivateKeyHoldings(ctx, result.PrivateKey)
	if err != nil {
		return fmt.Errorf("write private-key holdings: %w", err)
	}

	for _, source := range scope.TrustSources {
		if n := trustFailed[source]; n > 0 {
			log.Warn().Str("source", source).Int("failed_rows", n).
				Msg("scan-truststore: not removing stale rows for a source with rows that could not be written")
			continue
		}
		pruned, err := st.PruneStaleTrustStoreRows(ctx, hostID, source, watermark)
		if err != nil {
			return fmt.Errorf("remove stale %s trust-store rows: %w", source, err)
		}
		if pruned > 0 {
			log.Info().Str("source", source).Int64("removed", pruned).
				Msg("scan-truststore: removed trust-store entries no longer present")
		}
	}
	if scope.PrivateKeys {
		// Every private-key observation from this scanner has source
		// "truststore" (JKS and PKCS#12 entries).
		const keySource = "truststore"
		if n := keysFailed[keySource]; n > 0 {
			log.Warn().Int("failed_rows", n).
				Msg("scan-truststore: not removing stale private-key rows: some could not be written")
		} else {
			pruned, err := st.PruneStalePrivateKeyHoldings(ctx, hostID, keySource, watermark)
			if err != nil {
				return fmt.Errorf("remove stale private-key rows: %w", err)
			}
			if pruned > 0 {
				log.Info().Int64("removed", pruned).
					Msg("scan-truststore: removed private-key holdings no longer present")
			}
		}
	}
	return nil
}

// scannedCertificates is one discovery per certificate and place it was found
// (a CA in two trust stores is one certificate with two provenance rows).
// Observations without a PEM are skipped; their rows then land only if the
// certificate is already known.
func scannedCertificates(result truststore.ScanResult) []dedup.CertDiscovery {
	type place struct{ fingerprint, storeType, path string }
	seen := map[place]bool{}
	var out []dedup.CertDiscovery
	add := func(fingerprint, pemText, storeType, path string) {
		p := place{fingerprint, storeType, path}
		if pemText == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, dedup.CertDiscovery{
			FingerprintSHA256: fingerprint,
			RawPEM:            pemText,
			Source:            "truststore",
			StoreType:         storeType,
			FilePath:          path,
		})
	}
	for _, o := range result.TrustStore {
		add(o.CAFingerprint, o.CAPEM, o.Source, o.SourceDetail)
	}
	for _, o := range result.PrivateKey {
		add(o.CertFingerprint, o.CertPEM, o.Source, o.SourceDetail)
	}
	return out
}
