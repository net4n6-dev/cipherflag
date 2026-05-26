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

// Package truststore discovers and ingests system trust stores from a
// host. Emits TrustStoreObservation (universal trust declarations) and
// PrivateKeyObservation (when JKS bundles contain PrivateKeyEntry).
// Spec: docs/superpowers/specs/2026-05-18-l4-f-sp1.6-pki-trusted-by-design.md
package truststore

import (
	"context"
	"sync"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/scanner/executil"
)

// Scanner orchestrates per-platform discovery and bundle parsing.
type Scanner struct {
	runner       executil.CommandRunner
	jvmPasswords []string
	spkiLookup   SPKILookup
	discoverers  []discoverer
}

// SPKILookup mirrors certfiles.SPKILookup; satisfied by *store.PostgresStore.
type SPKILookup interface {
	CertFingerprintBySPKI(ctx context.Context, spkiFingerprint string) (string, bool)
}

// discoverer pairs a stable name with a Run func so Scan can attribute
// per-discoverer outcomes. The err return is for fatal-but-non-blocking
// issues a discoverer may surface; today all four implementations return
// nil and log-and-continue internally.
type discoverer struct {
	// Name identifies the discoverer in DiscovererOutcome keys.
	// Stable values: "linux_os_bundles", "macos_keychains",
	// "jvm_keystores", "runtime_bundles".
	Name string
	// Run executes the discovery. It must never panic; per-path errors
	// are logged internally. A non-nil err signals a discoverer-level
	// failure (e.g. the entire subsystem is unavailable).
	Run func(ctx context.Context, s *Scanner) ([]bundleObservation, error)
}

// bundleObservation is the internal record a discoverer produces before
// the mapper turns it into typed observations.
type bundleObservation struct {
	Path         string
	Source       string // os_bundle | app_config | jvm_cacerts | lang_runtime
	SourceDetail string
	Format       string // pem | der | jks | pkcs12
	Data         []byte
}

// DiscovererOutcome summarises a single discoverer's contribution.
type DiscovererOutcome struct {
	// BundleCount is the number of raw bundle files returned.
	BundleCount int
	// Err is the serialised discoverer-level error string, or "" on success.
	Err string
}

// ScanResult collects everything produced by a single Scan invocation.
type ScanResult struct {
	TrustStore        []model.TrustStoreObservation
	PrivateKey        []model.PrivateKeyObservation
	BundlesScanned    int                          // total across all discoverers
	DiscovererResults map[string]DiscovererOutcome // keyed by discoverer Name
}

// New constructs a Scanner. jvmPasswords defaults to ["changeit"] when nil.
func New(runner executil.CommandRunner, spkiLookup SPKILookup, jvmPasswords []string) *Scanner {
	if len(jvmPasswords) == 0 {
		jvmPasswords = []string{"changeit"}
	}
	s := &Scanner{
		runner:       runner,
		spkiLookup:   spkiLookup,
		jvmPasswords: jvmPasswords,
	}
	s.discoverers = []discoverer{
		{Name: "linux_os_bundles", Run: discoverLinuxOSBundles},
		{Name: "macos_keychains", Run: discoverMacOSKeychains},
		{Name: "jvm_keystores", Run: discoverJVMKeystores},
		{Name: "runtime_bundles", Run: discoverRuntimeBundles},
	}
	return s
}

// Scan runs all discoverers in parallel, maps each bundle, returns the
// combined observation set plus per-discoverer outcome stats.
// HostID is stamped onto observations by the caller (pipeline-level concern).
// Per-discoverer failures are logged and skipped; the top-level error is
// always nil — resilience semantics are preserved at the discoverer level.
func (s *Scanner) Scan(ctx context.Context) (ScanResult, error) {
	type collected struct {
		bundles []bundleObservation
		outcome DiscovererOutcome
		name    string
	}

	results := make([]collected, len(s.discoverers))
	var wg sync.WaitGroup
	for i, d := range s.discoverers {
		wg.Add(1)
		go func(idx int, d discoverer) {
			defer wg.Done()
			bundles, err := d.Run(ctx, s)
			oc := DiscovererOutcome{BundleCount: len(bundles)}
			if err != nil {
				oc.Err = err.Error()
			}
			results[idx] = collected{
				name:    d.Name,
				bundles: bundles,
				outcome: oc,
			}
		}(i, d)
	}
	wg.Wait()

	var out ScanResult
	if len(s.discoverers) > 0 {
		out.DiscovererResults = make(map[string]DiscovererOutcome, len(s.discoverers))
	}

	var allBundles []bundleObservation
	for _, r := range results {
		if r.name == "" {
			continue
		}
		out.DiscovererResults[r.name] = r.outcome
		out.BundlesScanned += r.outcome.BundleCount
		allBundles = append(allBundles, r.bundles...)
	}

	for _, b := range allBundles {
		trust, key := s.mapBundle(b)
		out.TrustStore = append(out.TrustStore, trust...)
		out.PrivateKey = append(out.PrivateKey, key...)
	}
	return out, nil
}
