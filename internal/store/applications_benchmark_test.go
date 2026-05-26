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

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/testdb"
)

// BenchmarkGetApplication_ByScope measures end-to-end wall-clock of
// PostgresStore.GetApplication at increasing scope sizes. The call
// path issues three sequential queries:
//
//	1. UNION-ALL across 7 tag-carrying tables joined to asset_health_reports
//	2. ListApplicationSnapshots (for the 7-day score-delta reference)
//	3. ListApplicationScopeAssets (for top-contributing-rules aggregation)
//
// Benchmark informs the v1.3.8 decision on whether to consolidate.
// Per the Dev Philosophy: profile-first. If total wall-clock is
// acceptable at the biggest realistic scope, no optimization needed.
func BenchmarkGetApplication_ByScope(b *testing.B) {
	scopes := []int{10, 50, 200}
	for _, n := range scopes {
		b.Run(fmt.Sprintf("assets=%d", n), func(b *testing.B) {
			st := testStoreForBench(b)
			tag := fmt.Sprintf("bench-getapp-%d", n)
			cleanup := seedAppBench(b, st, tag, n)
			defer cleanup()

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				detail, err := st.GetApplication(context.Background(), tag)
				if err != nil {
					b.Fatalf("GetApplication: %v", err)
				}
				// seedAppBench tags the host + n configs → n+1 total.
				// Accept any scope ≥ n+1 so the benchmark stays loose.
				if detail == nil || detail.TotalAssets < n {
					b.Fatalf("expected ≥%d assets, got %v", n, detail)
				}
			}
		})
	}
}

// BenchmarkGenerateAgency_ByAppCount measures the agency-wide OMB
// rollup path. Current shape: ListApplications once, then for each
// app GetApplication (3 queries) + ListApplicationScopeAssets (1
// query = redundant, GetApplication already called it internally).
// Cost should scale ~4N round-trips where N is app count.
func BenchmarkGenerateAgency_ByAppCount(b *testing.B) {
	appCounts := []int{5, 25, 100}
	for _, n := range appCounts {
		b.Run(fmt.Sprintf("apps=%d", n), func(b *testing.B) {
			st := testStoreForBench(b)
			tags := make([]string, n)
			cleanups := make([]func(), n)
			for i := 0; i < n; i++ {
				tags[i] = fmt.Sprintf("bench-agency-%d-%d", n, i)
				cleanups[i] = seedAppBench(b, st, tags[i], 10) // 10 assets each
			}
			defer func() {
				for _, c := range cleanups {
					c()
				}
			}()

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				apps, err := st.ListApplications(context.Background(), nil)
				if err != nil {
					b.Fatalf("list apps: %v", err)
				}
				for _, app := range apps {
					// Mirror GenerateAgency's call shape — GetApplication
					// + ListApplicationScopeAssets per app.
					_, _ = st.GetApplication(context.Background(), app.Tag)
					_, _ = st.ListApplicationScopeAssets(context.Background(), app.Tag)
				}
			}
		})
	}
}

// testStoreForBench mirrors testStore (from testhelper_test.go) but
// targets benchmarks (B is not T). Skips if the test DB isn't wired;
// truncates nothing — benchmark data is cleaned up per-test.
func testStoreForBench(b *testing.B) *PostgresStore {
	b.Helper()
	dsn := testdb.Require(b)
	ctx := context.Background()
	st, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		b.Fatalf("connect: %v", err)
	}
	b.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		b.Fatalf("migrate: %v", err)
	}
	return st
}

// seedAppBench creates a host + `n` crypto_configs tagged with the
// given application_tag. Each config also gets a native-shape health
// report. Returns a cleanup func that removes everything. Deliberately
// avoids certificates / ssh_keys / crypto_libraries to sidestep the
// migration-019 trigger bug (fixed in migration 023 but this keeps the
// benchmarks portable to DBs without that migration applied).
func seedAppBench(b *testing.B, st *PostgresStore, tag string, n int) func() {
	b.Helper()
	ctx := context.Background()

	var hostID string
	if err := st.pool.QueryRow(ctx, `
		INSERT INTO hosts (canonical_hostname, os_family, host_type, application_tags)
		VALUES ($1, 'linux', 'server', ARRAY[$2])
		RETURNING id::text
	`, "bench-"+tag, tag).Scan(&hostID); err != nil {
		b.Fatalf("seed host: %v", err)
	}

	configIDs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var cid string
		if err := st.pool.QueryRow(ctx, `
			INSERT INTO crypto_configs (host_id, file_path, config_type, source, application_tags)
			VALUES ($1::uuid, $2, 'nginx', 'bench', ARRAY[$3])
			RETURNING id::text
		`, hostID, fmt.Sprintf("/etc/%s/cfg%d.conf", tag, i), tag).Scan(&cid); err != nil {
			b.Fatalf("seed config %d: %v", i, err)
		}
		configIDs = append(configIDs, cid)
		report := &model.AssetHealthReport{
			AssetType: "crypto_config", AssetID: cid,
			Grade: "B", Score: 78, PQCStatus: "vulnerable",
			Compliance: map[string]string{"cnsa_2": "fail"},
			ScoredAt:   time.Now(), RiskScore: 45,
			RiskFactors: map[string]int{"algo_weakness": 40},
			Findings: []model.HealthFinding{
				{RuleID: "CFG-001", Title: "Weak TLS", Severity: model.SeverityHigh,
					Category: model.CategoryProtocol, Detail: "TLSv1.0", Deduction: 30},
			},
		}
		if err := st.SaveAssetHealthReport(ctx, report); err != nil {
			b.Fatalf("save report %d: %v", i, err)
		}
	}

	return func() {
		ctx := context.Background()
		for _, cid := range configIDs {
			_, _ = st.pool.Exec(ctx, `DELETE FROM asset_health_reports WHERE asset_id = $1`, cid)
			_, _ = st.pool.Exec(ctx, `DELETE FROM crypto_configs WHERE id::text = $1`, cid)
		}
		_, _ = st.pool.Exec(ctx, `DELETE FROM hosts WHERE id::text = $1`, hostID)
	}
}

