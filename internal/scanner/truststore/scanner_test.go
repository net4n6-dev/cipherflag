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

package truststore

import (
	"context"
	"errors"
	"testing"
)

func TestNew_DefaultsJVMPasswordsToChangeit(t *testing.T) {
	s := New(nil, nil, nil)
	if len(s.jvmPasswords) != 1 || s.jvmPasswords[0] != "changeit" {
		t.Errorf("jvmPasswords = %v, want [changeit]", s.jvmPasswords)
	}
}

func TestScan_EmptyHost_ReturnsEmpty(t *testing.T) {
	s := &Scanner{discoverers: nil}
	res, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TrustStore) != 0 || len(res.PrivateKey) != 0 {
		t.Errorf("expected empty result, got %+v", res)
	}
	if res.BundlesScanned != 0 {
		t.Errorf("BundlesScanned = %d, want 0", res.BundlesScanned)
	}
	// With no discoverers the map should be nil (never initialised).
	if len(res.DiscovererResults) != 0 {
		t.Errorf("DiscovererResults = %v, want empty/nil", res.DiscovererResults)
	}
}

// TestScan_PerDiscovererOutcomes stubs two discoverers — one healthy (3 bundles,
// nil error) and one failed (0 bundles, sentinel error) — and asserts that Scan
// reports correct per-discoverer stats without surfacing a top-level error.
func TestScan_PerDiscovererOutcomes(t *testing.T) {
	sentinelErr := errors.New("probe subsystem unavailable")

	s := &Scanner{
		discoverers: []discoverer{
			{
				Name: "healthy",
				Run: func(_ context.Context, _ *Scanner) ([]bundleObservation, error) {
					return []bundleObservation{
						{Path: "/a", Source: "os_bundle", SourceDetail: "/a", Format: "pem"},
						{Path: "/b", Source: "os_bundle", SourceDetail: "/b", Format: "pem"},
						{Path: "/c", Source: "os_bundle", SourceDetail: "/c", Format: "pem"},
					}, nil
				},
			},
			{
				Name: "failing",
				Run: func(_ context.Context, _ *Scanner) ([]bundleObservation, error) {
					return nil, sentinelErr
				},
			},
		},
	}

	res, err := s.Scan(context.Background())

	// Top-level error must always be nil.
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}

	// Total bundles counted across all discoverers.
	if res.BundlesScanned != 3 {
		t.Errorf("BundlesScanned = %d, want 3", res.BundlesScanned)
	}

	// Both discoverers must appear in the outcomes map.
	if len(res.DiscovererResults) != 2 {
		t.Fatalf("len(DiscovererResults) = %d, want 2; map = %v", len(res.DiscovererResults), res.DiscovererResults)
	}

	healthy, ok := res.DiscovererResults["healthy"]
	if !ok {
		t.Fatal("DiscovererResults missing key 'healthy'")
	}
	if healthy.BundleCount != 3 {
		t.Errorf("healthy.BundleCount = %d, want 3", healthy.BundleCount)
	}
	if healthy.Err != "" {
		t.Errorf("healthy.Err = %q, want empty", healthy.Err)
	}

	failing, ok := res.DiscovererResults["failing"]
	if !ok {
		t.Fatal("DiscovererResults missing key 'failing'")
	}
	if failing.BundleCount != 0 {
		t.Errorf("failing.BundleCount = %d, want 0", failing.BundleCount)
	}
	if failing.Err != sentinelErr.Error() {
		t.Errorf("failing.Err = %q, want %q", failing.Err, sentinelErr.Error())
	}
}
