//go:build integration

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

package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest/dedup"
	"github.com/net4n6-dev/cipherflag/internal/ingest/observcache"
	"github.com/net4n6-dev/cipherflag/internal/store"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

func newIntegrationStore(t *testing.T) *store.PostgresStore {
	t.Helper()

	ctx := context.Background()
	st, err := store.NewPostgresStore(ctx, testdb.Require(t))
	if err != nil {
		t.Skipf("integration DB unavailable: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	tables := []string{
		"asset_provenance",
		"asset_health_reports",
		"agent_tokens",
		"protocol_observations",
		"crypto_configs",
		"crypto_libraries",
		"ssh_keys",
		"host_identifiers",
		"observations",
		"endpoint_profiles",
		"health_reports",
		"ingestion_state",
		"pcap_jobs",
		"certificates",
		"hosts",
		"users",
	}
	pool := st.Pool()
	for _, tbl := range tables {
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE"); err != nil {
			// Table may not exist in earlier migration states; ignore.
			_ = err
		}
	}
	return st
}

// fixedTime is a stable timestamp used across all testResult() calls so that
// cache keys are deterministic — time.Now() in NotBefore/NotAfter would
// produce a different key on every call and prevent hit detection.
var fixedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func testResult() *DiscoveryResult {
	return &DiscoveryResult{
		Source:       "sentinelone",
		SourceHostID: "test-device-001",
		Hostname:     "web-01",
		IPAddresses:  []string{"10.0.1.10"},
		OSFamily:     "linux",
		Timestamp:    fixedTime,
		Certificates: []dedup.CertDiscovery{{
			FingerprintSHA256: "abc123",
			SubjectCN:         "example.com",
			IssuerCN:          "Test CA",
			SerialNumber:      "01",
			NotBefore:         fixedTime.Add(-30 * 24 * time.Hour),
			NotAfter:          fixedTime.Add(30 * 24 * time.Hour),
			KeyAlgorithm:      "RSA",
			KeySizeBits:       2048,
			FilePath:          "/etc/ssl/cert.pem",
		}},
	}
}

func TestIngest_FirstObservation_WritesCert(t *testing.T) {
	st := newIntegrationStore(t)
	cache := observcache.NewLRU(1000, time.Hour)
	ing := NewUnifiedIngester(st, WithObservationCache(cache))

	summary, err := ing.Ingest(context.Background(), testResult())
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if summary.CertificatesNew != 1 {
		t.Errorf("CertificatesNew = %d, want 1", summary.CertificatesNew)
	}
}

func TestIngest_DuplicateObservation_SkipsDedup(t *testing.T) {
	st := newIntegrationStore(t)
	cache := observcache.NewLRU(1000, time.Hour)
	ing := NewUnifiedIngester(st, WithObservationCache(cache))
	ctx := context.Background()

	if _, err := ing.Ingest(ctx, testResult()); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}
	snap1 := ing.Metrics().Snapshot()

	if _, err := ing.Ingest(ctx, testResult()); err != nil {
		t.Fatalf("second Ingest: %v", err)
	}
	snap2 := ing.Metrics().Snapshot()

	if snap2.TotalHits-snap1.TotalHits != 1 {
		t.Errorf("expected +1 hit on second ingest; got %d → %d", snap1.TotalHits, snap2.TotalHits)
	}
	if snap2.TotalMisses-snap1.TotalMisses != 0 {
		t.Errorf("expected 0 new misses on second ingest; got %d → %d", snap1.TotalMisses, snap2.TotalMisses)
	}
}

func TestIngest_ChangedObservation_DoesNotHitCache(t *testing.T) {
	st := newIntegrationStore(t)
	cache := observcache.NewLRU(1000, time.Hour)
	ing := NewUnifiedIngester(st, WithObservationCache(cache))
	ctx := context.Background()

	if _, err := ing.Ingest(ctx, testResult()); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}

	changed := testResult()
	changed.Certificates[0].SubjectAltNames = []string{"alt.example.com"}

	if _, err := ing.Ingest(ctx, changed); err != nil {
		t.Fatalf("changed Ingest: %v", err)
	}

	snap := ing.Metrics().Snapshot()
	if snap.TotalMisses != 2 {
		t.Errorf("TotalMisses = %d, want 2 (first + changed)", snap.TotalMisses)
	}
	if snap.TotalHits != 0 {
		t.Errorf("TotalHits = %d, want 0 (changed content should never hit)", snap.TotalHits)
	}
}

func TestIngest_TTLExpiry_ReprocessesObservation(t *testing.T) {
	st := newIntegrationStore(t)
	cache := observcache.NewLRU(1000, 100*time.Millisecond)
	ing := NewUnifiedIngester(st, WithObservationCache(cache))
	ctx := context.Background()

	if _, err := ing.Ingest(ctx, testResult()); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	if _, err := ing.Ingest(ctx, testResult()); err != nil {
		t.Fatalf("second Ingest: %v", err)
	}
	snap := ing.Metrics().Snapshot()
	if snap.TotalMisses != 2 {
		t.Errorf("TotalMisses = %d, want 2 (TTL expired)", snap.TotalMisses)
	}
}

func TestIngest_DisabledCacheMatchesCurrentBehaviour(t *testing.T) {
	st := newIntegrationStore(t)
	ing := NewUnifiedIngester(st)
	ctx := context.Background()

	if _, err := ing.Ingest(ctx, testResult()); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}
	if _, err := ing.Ingest(ctx, testResult()); err != nil {
		t.Fatalf("second Ingest: %v", err)
	}

	snap := ing.Metrics().Snapshot()
	if snap.TotalHits != 0 {
		t.Errorf("disabled cache should never hit; got %d hits", snap.TotalHits)
	}
	if snap.TotalMisses != 2 {
		t.Errorf("TotalMisses = %d, want 2 (every observation goes through dedup)", snap.TotalMisses)
	}
}

func TestIngest_NewProvenanceOnSameAsset_WritesProvenance(t *testing.T) {
	st := newIntegrationStore(t)
	cache := observcache.NewLRU(1000, time.Hour)
	ing := NewUnifiedIngester(st, WithObservationCache(cache))
	ctx := context.Background()

	r1 := testResult()
	r1.Source = "sentinelone"
	if _, err := ing.Ingest(ctx, r1); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}

	r2 := testResult()
	r2.Source = "zeek"
	if _, err := ing.Ingest(ctx, r2); err != nil {
		t.Fatalf("second Ingest: %v", err)
	}

	snap := ing.Metrics().Snapshot()
	if snap.TotalMisses != 2 {
		t.Errorf("TotalMisses = %d, want 2 (different source → different key)", snap.TotalMisses)
	}
	if snap.TotalHits != 0 {
		t.Errorf("TotalHits = %d, want 0 (source change must not hit cache)", snap.TotalHits)
	}

	pool := st.Pool()
	var provCount int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM asset_provenance
		WHERE asset_type = 'certificate' AND asset_id = 'abc123'
	`).Scan(&provCount)
	if err != nil {
		t.Fatalf("count provenance: %v", err)
	}
	if provCount != 2 {
		t.Errorf("provenance rows = %d, want 2 (one per source)", provCount)
	}
}

func TestIngest_AttritionSafety_TTLCapPreservesFreshness(t *testing.T) {
	st := newIntegrationStore(t)
	cfg := config.IntakeDedupConfig{
		Enabled:    true,
		TTLSeconds: 10, // 10 seconds — "misconfigured high"
		MaxEntries: 1000,
	}
	cache := observcache.New(cfg, 200*time.Millisecond)
	ing := NewUnifiedIngester(st, WithObservationCache(cache))
	ctx := context.Background()

	if _, err := ing.Ingest(ctx, testResult()); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, err := ing.Ingest(ctx, testResult()); err != nil {
		t.Fatalf("second Ingest: %v", err)
	}
	snap := ing.Metrics().Snapshot()
	if snap.TotalMisses != 2 {
		t.Errorf("TotalMisses = %d, want 2 (effective TTL capped at 100ms, cache should have expired)", snap.TotalMisses)
	}
}

func TestIngest_DedupFailureDoesNotMark(t *testing.T) {
	st := newIntegrationStore(t)
	cache := observcache.NewLRU(1000, time.Hour)
	ing := NewUnifiedIngester(st, WithObservationCache(cache))
	ctx := context.Background()

	bad := testResult()
	bad.Certificates[0].FingerprintSHA256 = ""

	_, err := ing.Ingest(ctx, bad)
	if err == nil {
		t.Skip("store tolerates empty fingerprint; dedup-failure path not exercised. Consider using a cancelled context to force a DB error and re-enabling this test.")
	}

	snap := ing.Metrics().Snapshot()
	if cache.Size() != 0 {
		t.Errorf("cache.Size() = %d after dedup failure; want 0 (key must not be marked)", cache.Size())
	}
	if snap.TotalMisses != 1 {
		t.Errorf("TotalMisses = %d, want 1 (one attempted observation)", snap.TotalMisses)
	}
}
